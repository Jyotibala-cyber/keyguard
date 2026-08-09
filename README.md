# KeyGuard — Cryptographic Key Management & Security Tool

**KeyGuard** is a fully functional cybersecurity application that brings a complete
cryptographic toolkit behind a professional, SOC-inspired dashboard. It performs **real**
encryption, decryption, hashing, key management, password security and reporting — no
placeholder buttons, no dummy features.

![Tech](https://img.shields.io/badge/Flask-3-blueviolet) ![Crypto](https://img.shields.io/badge/PyCryptodome-3.19-informational) ![RSA](https://img.shields.io/badge/cryptography-48-orange) ![Status](https://img.shields.io/badge/status-production-ready-success)

---

## Features

| Module | Capabilities |
|---|---|
| **Dashboard** | Live counters, security score, activity mix, operation success rate, real-time recent activity |
| **AES Encryption** | AES-128/192/256 **GCM** authenticated encryption for text **and** files; key generation; encrypted `.enc` file output & decrypt back to original |
| **RSA Encryption** | 1024/2048/4096-bit key pair generation, RSA-**OAEP (SHA-256)** encrypt with public key, decrypt with private key, secure key vault storage |
| **Hash Analyzer** | SHA-256, SHA-512, SHA-1, MD5 for text and files (chunked, memory-safe); one-pass multi-digest; integrity comparison to **detect file modification** |
| **Key Management** | Generate/store/delete AES & RSA keys, key vault (`key_store.json`), strength analysis, generation history |
| **Password Security** | PBKDF2-HMAC-SHA256 password hashing (150k iterations), random salt generation, constant-time verification, live strength gauge with crack-time estimation |
| **Reports** | JSON + Markdown audit reports, per-category and per-day breakdowns, full operation log viewer |
| **Settings** | Persisted preferences, security level, max upload size, activity-log maintenance |
| **Privacy / Multi-user isolation** | Signed **session token** per browser — every user's keys, activity log, uploads, settings and reports live in a private per-session workspace and are never visible to other sessions. One-click **"Start New Session"** wipes all personal data |
| **Volatile mode** | Run with `KEYGUARD_VOLATILE=1` for a **zero-storage** mode — all data lives only in memory and OS temp files; nothing is written to the project and a restart wipes everything |

All operations are written to a structured, JSON-lines **activity log** that drives every
counter and report on the platform — scoped to the active session.

## Tech Stack

- **Backend:** Python 3.13 · Flask 3
- **Crypto:** PyCryptodome (AES-GCM) · `cryptography` (RSA-OAEP, PEM)
- **Hashing/KDF:** `hashlib` (SHA-2/MD5) · PBKDF2-HMAC-SHA256
- **Frontend:** HTML · CSS (glassmorphism dark theme) · Vanilla JS (fetch API)

## Project Structure

```
KeyGuard/
├── app.py                    # Flask application, routes, logging, reports, session isolation
├── .secret_key               # Auto-generated session signing secret (first run)
├── encryption/
│   ├── __init__.py
│   ├── aes.py                # AES-GCM text & file encryption
│   └── rsa.py                # RSA key pairs, OAEP encrypt/decrypt
├── security/
│   ├── __init__.py
│   ├── hashing.py            # SHA-256/512, SHA-1, MD5 digest generation
│   └── password.py           # PBKDF2 hashing, salt, strength analysis
├── data/                     # Per-session privacy workspaces (auto-created)
│   └── <session_id>/         # One private folder per browser session:
│       ├── activity.log      #   session-scoped operation log
│       ├── key_store.json    #   session-scoped key vault index
│       ├── settings.json     #   session-scoped preferences
│       ├── keys/aes/         #   generated AES key material
│       ├── keys/rsa/         #   RSA PEM keypairs (<key_id>/private.pem, public.pem)
│       ├── uploads/          #   uploaded + processed files (downloadable)
│       └── reports/          #   exported audit reports
├── templates/                # SOC-style dashboard pages (Jinja2)
├── static/
│   ├── css/style.css         # Dark cybersecurity theme
│   └── js/app.js             # UI helpers, API client, toasts
├── requirements.txt
└── README.md
```

## Getting Started

```bash
# 1. Create & activate a virtual environment (recommended)
python -m venv venv
venv\Scripts\activate          # Windows
source venv/bin/activate       # macOS / Linux

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the application
python app.py                       # persistent per-session workspaces (data/<session_id>/)
KEYGUARD_VOLATILE=1 python app.py   # volatile mode — zero data stored, wiped on restart

# 4. Open your browser
#    http://127.0.0.1:5000
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `KEYGUARD_SECRET` | auto-generated `.secret_key` | Secret used to sign session cookies. Set a fixed value so sessions survive across restarts/deployments. |
| `KEYGUARD_VOLATILE` | off | Set to `1`/`true` to run in **zero-storage** mode — all data lives in memory & OS temp files, wiped on restart. |
| `KEYGUARD_COOKIE_SECURE` | off | Set to `1`/`true` to send session cookies with the `Secure` flag (required behind HTTPS). |
| `PORT` | `5000` | Port the web server binds to (Railway sets this automatically). |

## Deploying to Railway

1. **Push this repo to GitHub** — make sure `.secret_key`, `data/`, `keys/`, `uploads/`
   and `reports/` stay out of git (already handled by `.gitignore`).
2. On **Railway** → **New Project** → **Deploy from GitHub repo** and select this repo.
3. Railway auto-detects Python, installs `requirements.txt` and starts the app with the
   provided `Procfile` (`gunicorn app:app`).
4. In **Variables**, add:
   - `KEYGUARD_SECRET` → a long random string (e.g. `python -c "import secrets; print(secrets.token_hex(32))"`)
   - `KEYGUARD_COOKIE_SECURE` → `1`
   - `KEYGUARD_VOLATILE` → `1` *(recommended: Railway storage is ephemeral — zero-storage
     mode guarantees nothing sensitive persists and a redeploy starts clean)*
5. Open the generated `*.up.railway.app` URL. Railway terminates TLS automatically.

> No secrets are ever committed: the auto-generated `.secret_key` is git-ignored, and all
> per-session keys/logs/uploads/reports live only under `data/<session_id>/` which is also
> git-ignored.

## Security Notes

- **Session-based privacy isolation.** The moment a browser first opens KeyGuard it
  receives a signed **session token** (a signed `HttpOnly` cookie, `SameSite=Lax`).
  All keys, activity logs, uploads, reports and settings are stored under
  `data/<session_id>/`, so one user can never see another user's data — even on the
  same machine. Settings → **Privacy & Session** shows your token and offers
  **Start New Session**, which wipes your entire workspace and mints a fresh session.
  Signing secret is auto-generated into `.secret_key` (or set `KEYGUARD_SECRET`) and
  persists across restarts so sessions remain valid.
- **Volatile / zero-storage mode.** Start with `KEYGUARD_VOLATILE=1` and KeyGuard never
  writes keys, logs, settings or reports to the project (`data/` stays empty). Structured
  data stays in process memory and file artifacts use throwaway OS temp directories that
  are removed automatically on shutdown — nothing survives a restart.
- **`data/` is auto-created** and grows one private folder per browser session. It is
  safe to delete or back up as a whole; in volatile mode it is never written to.
- **AES** uses **GCM** mode: confidentiality *and* authenticated integrity. Tampered
  ciphertext is rejected on decryption.
- **RSA** uses **OAEP** padding with SHA-256 (IND-CCA2 secure).
- Passwords are stored via PBKDF2-HMAC-SHA256 with per-password random salts and verified
  with **constant-time** comparison (`hmac.compare_digest`).
- **Privacy-first file handling:** source uploads are wiped from disk immediately after
  processing (configurable in Settings → *Delete source uploads after processing*), so
  plaintext never lingers in `uploads/`.
- Generated key material is stored locally under each session's `data/<session_id>/keys/`.
  For production use, integrate a hardware-backed vault (HSM / OS keychain) and enable
  `SESSION_COOKIE_SECURE` behind HTTPS — KeyGuard is a reference implementation for
  education and portfolios.

## Disclaimer

KeyGuard is a security **educational tool**. Cryptographic material should be protected
with the appropriate operational controls before use in any real production environment.

## License

MIT
