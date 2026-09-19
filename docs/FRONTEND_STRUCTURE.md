# Frontend Structure

## Directory layout

```
capstonefrontend/
├── index.html                  Vite entry, app shell HTML
├── package.json                scripts and dependencies
├── tsconfig.json               TypeScript config (strict)
├── vite.config.ts              Vite config
├── vitest.config.ts            Vitest config (node env, test env vars)
├── vercel.json                 SPA rewrite for Vercel
├── .env.example                VITE_* variables (public only)
├── public/                     static assets
├── src/
│   ├── main.tsx                React bootstrap
│   ├── App.tsx                 wires realtime transport, router, controllers
│   ├── config/env.ts           reads VITE_* env, derives WS base URL
│   ├── routes/router.tsx       route table
│   ├── components/             AppShell, RequireAuth, AuthLayout, Logo, ...
│   ├── pages/                  Home, Login, Register, Chat, Settings, legal
│   ├── hooks/                  useAuth, useChat, useKeyStatus, useHealthCheck
│   ├── auth/                   AuthController + sessionStorage
│   ├── keys/                   KeyController (bundle upload)
│   ├── realtime/               WebSocketController, WebSocketClient,
│   │                           ChatController, messageId, types, setup
│   ├── api/                    http wrapper + typed endpoint modules
│   ├── crypto/                 all client cryptography
│   ├── types/                  shared TypeScript types
│   └── styles/global.css       design tokens and component styles
└── test/                       Vitest test files + setup
```

## Controllers (singletons)

| Controller | File | Responsibility |
| --- | --- | --- |
| `AuthController` | `src/auth/AuthController.ts` | Single source of truth for auth + identity state. Holds the JWT, restores it from sessionStorage, unlocks identity, runs challenge/verify, handles logout and 401s. |
| `KeyController` | `src/keys/KeyController.ts` | Derives and publishes the current identity's public key bundle. Best-effort upload when identity is unlocked and a JWT is held. |
| `WebSocketController` | `src/realtime/WebSocketController.ts` | Transport lifecycle: connect/disconnect, backoff reconnect, dispatch of envelopes, close-code classification. Never sees plaintext (only opaque base64url data). |
| `ChatController` | `src/realtime/ChatController.ts` | In-memory E2EE session store plus WebSocket bridge. Establishes X3DH sessions, encrypts/decrypts, routes inbound envelopes. |

All controllers expose subscribe/getSnapshot patterns that React hooks wrap.

## Crypto layer (`src/crypto/`)

| Module | Provides |
| --- | --- |
| `ed25519.ts` | Generate/sign/verify Ed25519 (noble/curves), hex helpers, short ids |
| `x25519.ts` | X25519 keypair generation, public derivation, raw DH (noble/curves) |
| `x3dh.ts` | X3DH initiator/responder SK derivation, init-frame encode/decode |
| `keyBundle.ts` | Remote bundle validation and parsing into typed structures |
| `doubleRatchet.ts` | Symmetric-turn Double Ratchet (send/recv chains, skipped keys) |
| `ratchetKdf.ts` | Root/chain/message key derivation via HKDF-SHA256 |
| `e2eeSession.ts` | High-level `E2EESession` (initiate/accept/encrypt/decrypt/export) |
| `session.ts` | Legacy `X3DHSession` (X3DH only, superseded by e2eeSession) |
| `deviceKeys.ts` | Device key generation, SPK signing, encrypted persistence envelope |
| `identity.ts` | Identity lifecycle: registerNew, unlock, lock, delete |
| `identityStore.ts` | IndexedDB schema and record access (`secure-messaging` / `identities`) |
| `kdf.ts` | PBKDF2-SHA256 passphrase key derivation (600k iterations) |
| `hkdf.ts` | HKDF-SHA256 via Web Crypto |
| `aead.ts` | AES-256-GCM encrypt/decrypt (12-byte IV) with raw-key helpers |
| `hex.ts`, `base64url.ts` | Encoding utilities |

## API layer (`src/api/`)

| Module | Wraps |
| --- | --- |
| `http.ts` | Fetch wrapper: timeout (AbortController), JSON, Bearer token, `X-Request-ID`, `ApiError`, single 401 hook |
| `auth.ts` | `/auth/register`, `/auth/challenge`, `/auth/verify`, `/auth/logout` |
| `keys.ts` | `/keys/upload`, `/keys/bundle/{id}`, `/keys/prekeys/{id}` |
| `health.ts` | `/health`, `/health/ready` |

## Routing

Defined in `src/routes/router.tsx`:

| Path | Element | Guard |
| --- | --- | --- |
| `/` | HomePage | - |
| `/login` | LoginPage | - |
| `/register` | RegisterPage | - |
| `/privacy`, `/terms`, `/contact` | Legal pages | - |
| `/chat` | ChatPage | RequireAuth |
| `/settings` | SettingsPage | RequireAuth |
| `/404` | NotFoundPage | - |
| `*` | redirect to `/404` | - |

## Dependencies

Runtime: `@noble/curves` (Ed25519/X25519), `idb` (IndexedDB), `react`,
`react-dom`, `react-router-dom`. Dev: Vite, TypeScript, Vitest,
`@vitejs/plugin-react`, `fake-indexeddb`, type packages. No TLS/WebSocket
crypto libraries are used; all symmetric/derived-key work uses Web Crypto.

## Realtime wiring

`App.tsx` constructs a single `WebSocketController`, then calls
`setRealtimeTransport` (from `realtime/setup.ts`) which creates the
`ChatController` singleton and connects. Logout/lock disconnects the
transport and wipes in-memory sessions (see `SESSION_MANAGEMENT.md`).