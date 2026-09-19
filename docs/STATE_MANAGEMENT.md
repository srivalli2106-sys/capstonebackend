# State Management

React 18 + react-router 6, deliberately **no external state library**: state
is owned by thin singleton controllers wired into one `App`, with pages
reading from them via context/props.

## Ownership

| Piece | Owner | Persistence |
| --- | --- | --- |
| JWT + user_id | `AuthController` | `sessionStorage` (`secure-messaging:jwt`, `secure-messaging:user_id`) |
| identity (seed, device keys) | `IdentityController` | IndexedDB `secure-messaging`, wrapped |
| key bundle (SPK/OPK) | `KeyController` (`LocalKeyInfo`) | IndexedDB, wrapped |
| sessions + ratchet states | `ChatController` | memory only |
| transports | `WebSocketController`, `WebSocketClient` | n/a |

## Ready gate

`App.tsx`:

```
App
 +--- await authController.ready()          (restores JWT from sessionStorage)
 +--- await KeyController boot               (loads bundle if present)
 +--- create WebSocketController(auth)       (WS after auth)
 +--- setRealtimeTransport(ChatController)   (auto-connect)
 +--- <BrowserRouter>  [render gate: ready state reached]
       ├── /           Home
       ├── /chat       Chat      (protected)
       └── /settings   Settings  (protected)
```

The router only mounts once auth bootstrap settles, so unauthenticated users
can't race a protected route.

## Auth state machine

```
missing     -> register or login
unlocked    -> keyController.provision() -> ready
locked      -> prompt passphrase
ready       -> chat available; WS connected; upload bundle on first unlock
```

`AuthController` is the single source of truth for "who am I"; every other
controller reads it (e.g. WS re-auth on reconnect).

## KeyController status

| status | meaning |
| --- | --- |
| `not_provisioned` | no local identity/bundle; register first |
| `ready` | bundle uploaded; chats encrypted |

On every unlock it re-uploads/writes the wrapped bundle so the server is
up-to-date after device changes.

## Chat session store (`ChatController`)

- `Map<conversationKey, E2EESession>`; in-memory.
- Envelope dispatch: `session_init`/`session_accept`/`text`/`file`/
  `delivery_receipt`/`read_receipt`/`typing`.
- Receipts are applied to in-memory message status; no receipt data is
  persisted. Message status and read/unread state ARE folded into the
  encrypted local history store so a reload restores the thread's ticks.
- Lock/logout/dispose clears the whole map (sessions are ephemeral by design).

## State reset paths

| Event | Clears |
| --- | --- |
| `lock()` | identity keys, sessions, JWT (then `disposeRealtimeTransport`) |
| `logout()` | same + server-side JWT revocation |
| `disposeRealtimeTransport()` | transports, singletons reset |
| app reload | memory state; IndexedDB identity survives; encrypted history (`secure-messaging-chat`) survives; JWT in sessionStorage survives per tab |

## Data-down, actions-up

- HTTP flows (`api/*`) return typed results to controllers; controllers
  mutate their own state; pages re-render from bound selectors.
- Standalone features (contacts, conversation list metadata beyond the stored
  thread, pagination) are intentionally out of scope; conversation history is
  handled by `src/persistence/chatStore.ts` (see `MESSAGING.md`).