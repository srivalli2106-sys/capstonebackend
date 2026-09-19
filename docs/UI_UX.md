# UI / UX

## Routes and layout

- `AppShell` is the app frame: top navigation (Home, Chat, Settings), an
  identity badge (unlocked user / locked / no identity), and a lock button.
- `routes/router.tsx`:
  - `/` Home — auth entry (register/login) or a ready snapshot.
  - `/chat` — protected; the messaging screen.
  - `/settings` — protected; profile, device/key status, logout.
- `/chat` and `/settings` render full-viewport; `/` flows through the shell.
  Protected routes redirect to `/` when not authed.

## Design language

- Plain React + inline component styles; no heavy CSS framework.
- Light/dark aware palette, monospace hex fingerprints for keys/ids to make
  copy-paste and verification obvious.
- Status surfaced visually: connection state, session state (initiating /
  active / locked), message status (sent/delivered/read indicators).

## Key flows

### Onboarding
1. Register: pick a user_id (3..64, allowed charset) and a passphrase; the
   identity is created locally then registered against the API.
2. Login: passphrase -> proves the device key; the badge flips to
   "ready".

### Chat
- Conversation pane: pending states for session handshake (X3DH frame), then
  the ratchet stream.
- Sending: ciphertext is produced synchronously client-side; failures
  surface inline (offline, rate-limited, peer missing).
- Typing and receipts: typing indicators drawn from `typing` envelopes;
  delivery/read states from `delivery_receipt`/`read_receipt`.

### Settings
- Shows identity fingerprint, key status (SPK/OPK counts), and the lock/logout
  actions.

## Notifications and error copy

- Error copy maps typed errors to short user-directed sentences (see
  `ERROR_HANDLING.md`): never raw codes except in the copyable fingerprint
  fields.
- Offline / reconnecting states are explicit; reconnect backoff is invisible
  to the user except a subtle status hint.

## Accessibility and responsiveness

- Keyboard operable: forms reachable and submittable; focus management on
  route change.
- Responsive layout verified for small screens (see `FRONTEND_STRUCTURE.md`
  for the size budget after CSS/JS trimming).

## Out of scope (documented)

- Contact management, conversation list persistence, attachments beyond a
  `file` envelope stub, dark image/voice messages, localization.
- See `LIMITATIONS.md` for the full list.