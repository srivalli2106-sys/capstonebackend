# Application Flow

## 1. Registration

```
User          Frontend                      Backend                 Storage
 |  enter user_id + passphrase                |                       |
 |------------>  validate (3..64, >=8 chars)  |                       |
 |                generate Ed25519 seed       |                       |
 |                generate X25519 device keys |                       |
 |                derive AES key (PBKDF2)     |                       |
 |                encrypt seed + device keys  |                       |
 |                write IndexedDB record      |----------- IndexedDB   |
 |                ik_public = pub(seed)       |                       |
 |                --------- POST /auth/register {user_id, ik_public}
 |                                            |------> user exists?    |
 |                                            | 409 if already exists  |
 |                                            |        insert user ----| MongoDB
 |                POST /auth/challenge {user_id}                       |
 |                                            |<------ {nonce}         |
 |                sign nonce (Ed25519)        |                       |
 |                POST /auth/verify {user_id, nonce, signature}       |
 |                                            | consume challenge (atomic)
 |                                            | verify sig vs ik_public
 |                                            | issue JWT {sub,iss,iat,exp,jti}
 |<----------------------------------------------- {token, user_id}  |
 |                store JWT in sessionStorage |                       |
```

On any backend failure after local record creation, the local record is
deleted (rollback) before the error propagates.

## 2. Login / unlock

```
User         Frontend                      Backend
 |  user_id + passphrase                     |
 |--------------> unlockIdentity:            |
 |                 read IndexedDB record     |
 |                 PBKDF2 + AES-GCM decrypt  |
 |                 (wrong passphrase fails locally, never reaches backend)
 |                 POST /auth/challenge {user_id}
 |                 sign raw nonce locally    |
 |                 POST /auth/verify {..., signature}
 |<---------------- {token, user_id}
 |                 save JWT (sessionStorage)
 |                 hold unlocked identity in memory (deviceKeys ready)
 |                 KeyController.refresh() -> best-effort bundle upload
```

The identity is never restored automatically on reload; the user must
re-enter the passphrase (JWT may still be valid and is restored).

## 3. Key bundle upload (after unlock)

```
Frontend                          Backend                       MongoDB
KeyController.refresh()
  build public bundle (ik_public, xdh_public,
    spk_public, spk_signature, opk_public)
  POST /keys/upload {xdh_public, spk_public,
                     spk_sig, opk_public}         upsert key_bundles
        (Bearer JWT, require_auth)  <----------------------------- user document
        validates hex + sizes (400) and user existence (404)
```

Failures are best-effort: logged to console, never block auth or chat.

## 4. Open a conversation (initiator side)

```
ChatController.openConversation(peer)
  GET /keys/bundle/{peer}   (Bearer JWT)
      backend: fetch bundle, consume OPK atomically (single-use), serve it
  parseRemoteKeyBundle(ik_public, xdh_public, spk_public, spk_sig, opk_public?)
  E2EESession.initiate(ikxPrivate, remoteBundle)
      verify spk signature (Ed25519 over SPK_SIGN_CONTEXT || spk_public)
      run X3DH, derive SK + AD, create root key + sending ratchet
  send session_init envelope { type:'session_init', data: base64url(initPayload) }
```

If the bundle lacks `xdh_public`, initiation fails with a controlled
`backend_blocker` diagnostic; the client never fabricates substitutes.

## 5. Receive a session_init (responder side)

```
WebSocket -> InboundEnvelope(type=session_init)
ChatController.handleSessionInit
  E2EESession.accept(spkPrivate, ikxPrivate, ikxPublic, [opkPrivate], initPayload)
  build responder session, record session state 'ready'
  send session_accept envelope { data: '' }   (UI confirmation)
```

## 6. Send a message

```
sendText(peer, plaintext)
  session.encryptMessage(UTF-8 bytes, extraAd=[0]) -> wire bytes
  data = base64url(wire)
  WebSocketController.sendEnvelope({ type:'text', recipient: peer, data })
  -> {id, type, recipient, data}  (client-side envelope)
  Backend: normalize_envelope (stamps sender/timestamp/version),
  dedup by id, presence check:
    online  -> forward to peer socket (server-authoritative envelope)
    offline -> enqueue Redis pending:{peer}
Outbound status: sending -> sent.
```

## 7. Receive a message

```
WebSocket -> InboundEnvelope(type=text, sender, timestamp, data)
  session.decryptMessage(base64url(data), extraAd=[0])
  -> plaintext rendered with server timestamp
  Dedup set per session guards against reprocessing duplicate ids.
```

## 8. Offline delivery

```
Peer connects to /ws -> first-frame auth ->
   presence connect, conn registration (takeover of old conn, close 4000)
   flush_pending(peer): dequeue_all pending:{peer}, send each; on send
   failure re-queue the remaining and stop.
```

## 9. Logout / identity lock

```
logout()            -> POST /auth/logout (revokes jti), clearSession()
identity lock       -> drops unlocked seed + device keys from memory
WebSocketController -> disconnect ('logout'/'lock'), no reconnect
ChatController      -> clearAllSessions() (session.wipe(), conversations cleared)
```

## Sequence for one full conversation lifecycle

```
A unlock -> upload bundle    B unlock -> upload bundle
A opens chat w/ B: bundle fetch -> X3DH initiate -> session_init (->B)
B accepts -> session_accept (->A)
A -> text ciphertext -> B decrypts
B -> text ciphertext -> A decrypts
either logs out / locks -> sessions wiped, transport disconnected
```