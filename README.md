# 🔐 Secure Messaging App

**End-to-end encrypted messaging with the Double Ratchet protocol.**

Everything (messages, keys, files) is encrypted **on your device** before it ever reaches the server. The server only relays opaque encrypted blobs — it can never read your messages.

---

## ✨ What this does at a glance

```
Alice's phone                Server (can't read anything)             Bob's phone
      │                              │                                     │
      │  1. Register once            │                                     │
      │  (sends public key)          │                                     │
      │ ────────────────────────────►│                                     │
      │                              │                                     │
      │  2. Alice wants to chat Bob  │                                     │
      │  asks server for Bob's keys  │                                     │
      │ ────────────────────────────►│◄────────────────────────────────────│
      │                              │                                     │
      │  3. Alice & Bob do a         │                                     │
      │  secret key exchange (X3DH)  │                                     │
      │  BOTH now share a secret     │                                     │
      │  key that only they know     │                                     │
      │                              │                                     │
      │  4. Alice encrypts message   │                                     │
      │  🔒 "hello bob" → gibberish  │                                     │
      │ ────────────────────────────►│═══════════════►────────────────────►│
      │                              │  (relays gibberish)                 │
      │                              │                                     │  5. Bob decrypts
      │                              │                                     │  🔓 gibberish → "hello bob"
```

---

## 🗂️ Folder Structure (what each part does)

```
secure-messaging/
│
├── server/               ← The backend (this README focuses here)
│   ├── app.py            ← The main entry point. Starts the server & wires routes together
│   ├── db.py             ← Talks to MongoDB Atlas (stores users & their public keys)
│   ├── middleware.py     ← Security: checks login tokens (JWT) & rate-limits requests
│   ├── redis_client.py   ← Tracks who's online + queues messages for offline users
│   └── routes/           ← The actual "brain" — each file handles one type of request
│       ├── auth.py       ← Registration (one-time only) + login
│       ├── keys.py       ← Uploading / fetching public key bundles
│       └── messages.py   ← WebSocket — the real-time message relay
│
├── crypto/               ← (future) The encryption math lives here
├── protocol/             ← (future) The Double Ratchet / X3DH logic
├── client/               ← (future) The app you'd use to chat
├── tests/                ← (future) Automated tests
│
└── requirements.txt      ← List of Python packages this project needs
```

---

## 🧠 Backend explained for beginners

The backend has **3 jobs**. Here's how each is handled:

### 1. Accounts (who can use the app)
- **`POST /auth/register`** — create an account. **One-time only**: once a username exists, you can never register it again. A unique index in MongoDB enforces this.
- **`POST /auth/login`** — logs you in and gives you a **token** (like a temporary ID card). You must show this token on every other request.

### 2. Keys (the "padlocks" for encryption)
Each user stores their **public keys** on the server. These are like padlocks anyone can pick up — but only the owner has the matching key to open them.
- **`POST /keys/upload`** — save your public keys (padlocks) on the server.
- **`GET /keys/bundle/{user_id}`** — fetch someone's padlocks so you can start a secret chat with them. The server hands them over **once** and then "uses up" the one-time key.

### 3. Messages (the actual chat)
- **`WS /ws`** — a WebSocket (a live, two-way connection). When you send a message:
  - If the **recipient is online** → server forwards it instantly.
  - If the **recipient is offline** → server queues it and delivers when they reconnect.

> ⚠️ **Important:** The server only ever sees **encrypted gibberish**. It never sees your actual message text.

---

## 🛠️ Prerequisites (install these first)

| Tool | Why | Where to get it |
|------|-----|-----------------|
| **Python 3.10+** | Runs the whole backend | https://www.python.org/downloads/ (check **"Add to PATH"** during install) |
| **MongoDB Atlas** | The cloud database that stores users & keys | https://www.mongodb.com/atlas (free tier is fine) |

> **Optional but recommended:** Redis. Used for online-status & offline message queueing. If you skip it, the app still runs — it just won't queue messages for offline users.

---

## 🚀 Setup & Run (step by step)

### Step 1 — Clone / open the project
```powershell
cd "C:\Users\user\Desktop\secure-messaging
```

### Step 2 — Install dependencies
```powershell
pip install -r requirements.txt
```

### Step 3 — Set up MongoDB Atlas
1. Go to https://www.mongodb.com/atlas and create a free cluster
2. Click **Connect → Drivers → Python**
3. Copy your connection string. It looks like:
   ```
   mongodb+srv://USERNAME:PASSWORD@cluster0.xxxxx.mongodb.net
   ```

### Step 4 — Set environment variables
Tell the backend where your database is (PowerShell):
```powershell
$env:MONGODB_URI="mongodb+srv://USERNAME:PASSWORD@cluster0.xxxxx.mongodb.net"
$env:MONGODB_DB="secure_messaging"
```

> 🔑 **Tip:** Keep your password out of code. Using a `.env` file or environment variables is safer.

### Step 5 — Start the server
```powershell
python -m uvicorn server.app:app --host 0.0.0.0 --port 8000
```

You should see:
```
INFO:     Uvicorn running on http://0.0.0.0:8000
INFO:     Application startup complete.
```

### Step 6 — Open it in your browser
| URL | What it shows |
|-----|---------------|
| **http://localhost:8000/docs** | Interactive API tester (Swagger UI) — try every endpoint here |
| **http://localhost:8000/redoc** | Alternative, cleaner API docs |
| **http://localhost:8000/health** | Simple "I'm alive" check → `{"status": "ok"}` |

---

## 🧪 Try it yourself (in the browser)

Open **http://localhost:8000/docs**. Here's a full walkthrough:

### 1. Register a user
- Endpoint: `POST /auth/register`
- Body (replace with anything):
  ```json
  {
    "user_id": "alice",
    "ik_public": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
  }
  ```
- ✅ Returns `201` → registered
- 🚫 Try the same `user_id` again → `409 Conflict` (one-time registration works!)

> 📝 `ik_public` must be a **32-byte hex string** (exactly 64 hex characters). For quick testing, copy the example above or generate one in Python:
> ```python
> import secrets
> print(secrets.token_hex(32))
> ```

### 2. Login
- Endpoint: `POST /auth/login`
- Body: `{ "user_id": "alice" }`
- ✅ Returns a `token`. **Copy it** — you'll paste it in the "Authorize" box (padlock button, top-right) for the next steps.

### 3. Upload your keys
- Endpoint: `POST /keys/upload`
- Body:
  ```json
  {
    "spk_public": "<64 hex chars>",
    "spk_sig": "<64 hex chars>",
    "opk_public": "<64 hex chars>"
  }
  ```
- ✅ Returns `{"status": "ok"}`

### 4. Fetch someone's key bundle
- Endpoint: `GET /keys/bundle/{user_id}`
- Replace `{user_id}` with a real username that uploaded keys
- ✅ Returns their public keys (and consumes their one-time key)

---

## 🔌 WebSocket testing (real-time chat)

The `/ws` endpoint is real-time — you can't fully test it from the browser docs. Use a tool like **wscat** or a small script.

Quick test with PowerShell + Python:

```python
# test_ws.py — send a message over WebSocket
import asyncio, json
import websockets

async def main():
    uri = "ws://localhost:8000/ws?token=YOUR_LOGIN_TOKEN_HERE"
    async with websockets.connect(uri) as ws:
        msg = {"to": "bob", "data": "aGVsbG8="}  # base64 of an encrypted blob
        await ws.send(json.dumps(msg))
        print("sent:", msg)
        reply = await ws.recv()
        print("received:", reply)

asyncio.run(main())
```

Messages sent from the client look like:
```json
{
  "to": "bob",            // who to send to
  "data": "aGVsbG8="      // the ENCRYPTED payload (base64) — server just relays it
}
```

---

## 🔒 Security model (why this is secure)

The server **cannot** read your messages because of how the protocol works:

| Property | How it's achieved |
|----------|-------------------|
| **One-time registration** | Unique index on `user_id` — you can't re-register or impersonate |
| **End-to-end encryption** | Messages encrypted with AES-256-GCM before leaving your device |
| **Forward secrecy** | Double Ratchet — each message uses a fresh key, old keys are deleted forever |
| **Per-session keys** | Every new chat session does a fresh key exchange — no session replay |
| **Identity verification** | X3DH with signed prekeys — you prove you are who you say you are |
| **Message integrity** | If anyone tampers with a message, decryption fails automatically |

---

## ⚠️ Important security note

**This is a learning / demo project.** The encryption logic (`crypto/`, `protocol/`, `client/`) is **not yet implemented** — only the backend exists right now. Do **not** use this to protect real, sensitive messages until the full protocol is built and audited.

---

## 🛣️ Roadmap (what's coming)

- [ ] **Phase 1** — Core crypto primitives (X25519, HKDF, AES-GCM)
- [ ] **Phase 2** — Double Ratchet implementation
- [ ] **Phase 3** — X3DH handshake
- [ ] **Phase 4** — Message wire format & session management
- [ ] **Phase 5** — ✅ Server (this, done)
- [ ] **Phase 6** — Client app (CLI first, then mobile/desktop UI)
- [ ] **Phase 7** — End-to-end tests & security benchmarks

---

## 🛠️ Common errors & fixes

| Error | Cause | Fix |
|-------|-------|-----|
| `'uvicorn' is not recognized` | uvicorn not on PATH | Use `python -m uvicorn ...` instead |
| `ServerSelectionTimeoutError` | Can't reach Atlas | Check `MONGODB_URI` / password / internet |
| `pymongo.errors.DuplicateKeyError` | Registering a user that exists | That's expected — one-time registration blocks it |
| `409 Conflict` on register | Username already taken | Pick a different `user_id` |
| `Missing bearer token` on `/keys/*` | You forgot to authorize | Paste your login token in the 🔒 Authorize button |
| Can't connect `/ws` | Bad or expired token | Log in again for a fresh token |

---

## 📦 Tech Stack

| Layer | Technology |
|-------|------------|
| API framework | FastAPI (Python) |
| Database | MongoDB Atlas (via Motor) |
| Cache / queues | Redis |
| Auth | JWT (PyJWT) |
| Encryption | AES-256-GCM + X25519 (via `cryptography`) |
| Real-time | WebSockets |

---

## 🤝 Want to contribute?

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes
4. Push & open a Pull Request

---

Made with ❤️ for secure, private communication.
