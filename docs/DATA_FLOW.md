# Data Flow

End-to-end walkthrough of the four core flows, from user gesture to the wire.

## Registration flow

```
User:  type user_id + passphrase in register form
Client (AppShell -> authController.registerUser)
       1. user_id/normalization validations (3..64 chars)
       2. passphrase -> PBKDF2 -> identity key
       3. -> IdentityController.registerNew: derive Ed25519 + X25519 identity
          -> encrypt seed/device keys under passphrase-derived key
          -> persist wrapped records in IndexedDB (secure-messaging db)
       4. POST /auth/register { user_id, ik_public }
Server:  validate -> store identity { user_id, ik_public }
       201 { "status": "registered", "user_id" }   |  409 conflict
Client:  authed; KeyController provisions X25519 bundle -> POST /keys/upload
        navigate to /chat
```

## Login (proof-of-possession) flow

```
Client:  passphrase -> PBKDF2 -> identityKey
        -> IdentityController.unlock  (decrypt + verify seed, load device keys)
POST /auth/challenge { user_id }
Server:  generates 32 random bytes, stores with TTL (default 120 s) -> { nonce }
Client:  sig = Ed25519.sign(nonce_raw_bytes, auth_seed)     // raw nonce, not hex
POST /auth/verify { user_id, nonce, signature }
Server:  atomic challenge consume -> verify sig over nonce against ik_public
        -> issue JWT (claims sub/iss/iat/exp/jti + user_id) -> { token, user_id }
Client:  token -> sessionStorage; unlockKeyBundle -> PUT key bundle
         KeyController status -> ready
        open WS, first frame auth
```

## Messaging flow (encrypted)

```
Alice types, hits send
ChatController:
   session for bob in memory?
     no  -> GET /keys/bundle/bob -> X3DH initiate -> session_init envelope to bob
     yes -> ratchet.encrypt(plaintext)
   envelope { id=ULID, type=text|file, recipient=bob, data=b64(ciphertext) }
   -> WebSocket -> server
Server:
   validate id/type/recipient/size  |  rate_limit ws_message
   dedup by (sender, id) within DEDUP_TTL
   presence: bob online? -> relay stamped envelope to bob's socket
              else        -> enqueue pending:bob (opaque ciphertext)
Bob's client (any order of delivery -> skipped-key buffering):
   session for alice? no -> accept via session_accept
   ratchet.decrypt -> plaintext -> render; sender's delivery_receipt/read_receipt back
```

## Session handshake flow (on the wire)

```
Alice                          Server                  Bob
  session_init (X3DH frame) -->
                                    (relay)  ----------> session stored (pending)
                                                  <---  session_accept (ratchet pub)
  (relay) <------------------- (relay)
  session ready                                     session ready
  text ~ ciphertext ---------> (relay) -----------> decrypt
```

Server treats both frames like any envelope; it never inspects `data`.

## Local history flow (encrypted at rest)

```
Alice unlocks with her passphrase
  -> identity/device keys restored (IndexedDB secure-messaging)
  -> ChatController.maybeHydrate -> chatStore.unlock(ikxPrivate)
     key = HKDF-SHA256(ikxPrivate, info="secure-messaging-chat-history-v1" + self)
     -> loads per-peer AES-256-GCM ciphertext rows (secure-messaging-chat)
Conversation gains a message / receipt / read state
  -> markDirty(peer) -> debounced 400 ms -> chatStore.save (ciphertext only)
Delete conversation / message-for-me  -> local row/message removed
Logout / lock                    -> flush pending saves -> chatStore.lock (key dropped)
Reload                          -> history restores; session re-established via session_init
```

Only ciphertext and envelope metadata (ids, timestamps) touch IndexedDB
`secure-messaging-chat`; plaintext exists only in JS memory.

## Where data lives per stage

| Stage | Storage |
| --- | --- |
| Browser, at rest — identity | IndexedDB `secure-messaging` (wrapped identity + device keys only) |
| Browser, at rest — history | IndexedDB `secure-messaging-chat` (AES-256-GCM ciphertext only, bound to the device identity key) |
| Browser, session | `sessionStorage` JWT + user_id |
| Browser, memory | identities (keys), sessions, chat view |
| Wire | opaque ciphertext in server-authoritative envelopes |
| Server | user records (MongoDB), challenge/JWT/rate-limit state (Redis), offline ciphertext queue (Redis) |