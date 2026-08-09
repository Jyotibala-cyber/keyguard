"""KeyGuard — Cryptographic Key Management & Security Tool.

A fully working cybersecurity toolkit exposing real AES/RSA encryption,
hashing, key management, password security and reporting behind a
professional SOC-style dashboard.
"""

import json
import os
import re
import shutil
import tempfile
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_from_directory, session

from encryption import aes as aes
from encryption import rsa as rsa
from security.hashing import ALLOWED_ALGOS, hashes_for_file, hashes_for_text
from security.password import generate_salt, hash_password, password_strength, verify_password

BASE_DIR = Path(__file__).resolve().parent

DATA_ROOT = BASE_DIR / "data"

DATA_ROOT.mkdir(parents=True, exist_ok=True)

VOLATILE = os.environ.get("KEYGUARD_VOLATILE", "").strip().lower() in ("1", "true", "yes", "on")

# Hard cap on upload size, enforced at the Flask level. Configurable via
# KEYGUARD_MAX_UPLOAD_MB (default 16 MB) to prevent OOM/DoS via huge files.
MAX_UPLOAD_MB = int(os.environ.get("KEYGUARD_MAX_UPLOAD_MB", "16"))

# Abandoned per-session workspaces older than this TTL are garbage-collected
# automatically (hours). Defaults to 24h.
SESSION_TTL_HOURS = int(os.environ.get("KEYGUARD_SESSION_TTL_HOURS", "24"))
SESSION_CLEANUP_INTERVAL = int(os.environ.get("KEYGUARD_CLEANUP_INTERVAL", "3600"))

_MEM = {}
_TEMP_DIRS = {}

DEFAULT_SETTINGS = {
    "auto_save_aes_keys": True,
    "auto_delete_uploads": True,
    "max_file_size_mb": MAX_UPLOAD_MB,
    "report_include_logs": True,
    "security_level": "High",
}


def _load_or_create_secret():
    """Persist a random signing secret so session cookies survive restarts."""
    secret_file = BASE_DIR / ".secret_key"
    if secret_file.exists():
        try:
            return secret_file.read_text(encoding="utf-8").strip()
        except OSError:
            pass
    secret = uuid.uuid4().hex + uuid.uuid4().hex
    try:
        secret_file.write_text(secret, encoding="utf-8")
    except OSError:
        pass
    return secret


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("KEYGUARD_SECRET") or _load_or_create_secret()
# Hard cap enforced at the Flask level (see MAX_UPLOAD_MB above).
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
app.config["JSON_SORT_KEYS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Enable Secure cookies when running behind HTTPS (Railway provides HTTPS by default)
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("KEYGUARD_COOKIE_SECURE", "").strip().lower() in ("1", "true", "yes", "on")


# --------------------------------------------------------------------------- #
#  Session privacy layer
# --------------------------------------------------------------------------- #

def get_session_id():
    """Return (creating on first visit) the private token for this browser session."""
    if "sid" not in session:
        session["sid"] = uuid.uuid4().hex
    return session["sid"]


def workspace():
    """Per-session data workspace. Every user's keys, logs, uploads, settings
    and reports live in their own directory and are never visible to others.

    In VOLATILE mode nothing persists: files live in an ephemeral OS temp dir
    and structured data lives in memory — a restart wipes everything."""
    sid = get_session_id()
    if VOLATILE:
        tmp = _TEMP_DIRS.get(sid)
        if tmp is None:
            tmp = tempfile.TemporaryDirectory(prefix="keyguard_")
            _TEMP_DIRS[sid] = tmp
        root = Path(tmp.name)
    else:
        root = DATA_ROOT / sid
        _touch_session(sid)
    uploads = root / "uploads"
    keys = root / "keys"
    aes = keys / "aes"
    rsa = keys / "rsa"
    reports = root / "reports"
    for _d in (uploads, aes, rsa, reports):
        _d.mkdir(parents=True, exist_ok=True)
    return {
        "root": root,
        "uploads": uploads,
        "keys": keys,
        "aes": aes,
        "rsa": rsa,
        "reports": reports,
        "activity_log": root / "activity.log",
        "key_store": root / "key_store.json",
        "settings_file": root / "settings.json",
    }


def _mem():
    return _MEM.setdefault(get_session_id(), {"logs": [], "keys": {"keys": []}, "settings": None})


def _touch_session(sid):
    """Update the folder mtime so an active session is never garbage-collected."""
    if VOLATILE:
        return
    try:
        os.utime(DATA_ROOT / sid, None)
    except OSError:
        pass


def cleanup_stale_sessions():
    """Delete per-session workspaces idle for more than SESSION_TTL_HOURS.

    Prevents abandoned sessions from filling up disk in persistent mode.
    Skips the current session and everything in VOLATILE mode."""
    if VOLATILE:
        return
    cutoff = time.time() - SESSION_TTL_HOURS * 3600
    current = get_session_id()
    try:
        for folder in DATA_ROOT.iterdir():
            if not folder.is_dir():
                continue
            if folder.name == current:
                continue
            try:
                if folder.stat().st_mtime < cutoff:
                    shutil.rmtree(folder, ignore_errors=True)
            except OSError:
                continue
    except OSError:
        pass


def _session_cleanup_loop():
    """Background thread that periodically sweeps stale sessions."""
    while True:
        time.sleep(SESSION_CLEANUP_INTERVAL)
        try:
            cleanup_stale_sessions()
        except Exception:
            pass


def start_session_cleanup():
    """Run an initial sweep and launch the background collector (no-op in VOLATILE)."""
    if VOLATILE:
        return
    cleanup_stale_sessions()
    t = threading.Thread(target=_session_cleanup_loop, daemon=True)
    t.start()


# --------------------------------------------------------------------------- #
#  Data layer helpers
# --------------------------------------------------------------------------- #

def now_iso():
    return datetime.now().isoformat(timespec="seconds")


def log_activity(category, action, status, detail=""):
    """Append a structured, JSON-lines operation log entry for this session."""
    entry = {
        "timestamp": now_iso(),
        "session": get_session_id()[:8] + "...",
        "category": category,
        "action": action,
        "status": status,
        "detail": detail,
    }
    if VOLATILE:
        _mem()["logs"].append(entry)
        return entry
    ws = workspace()
    try:
        with open(ws["activity_log"], "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except OSError:
        pass
    return entry


def read_logs(limit=None):
    if VOLATILE:
        entries = list(_mem()["logs"])
        return entries[-limit:] if limit else entries
    entries = []
    ws = workspace()
    log_path = ws["activity_log"]
    if log_path.exists():
        with open(log_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except (json.JSONDecodeError, ValueError):
                    continue
    if limit:
        entries = entries[-limit:]
    return entries


def load_key_store():
    if VOLATILE:
        return _mem()["keys"]
    ws = workspace()
    store_path = ws["key_store"]
    if store_path.exists():
        try:
            with open(store_path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            pass
    return {"keys": []}


def save_key_store(data):
    if VOLATILE:
        _mem()["keys"] = data
        return
    ws = workspace()
    with open(ws["key_store"], "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def add_key(entry):
    data = load_key_store()
    data["keys"].append(entry)
    save_key_store(data)
    return entry


def delete_key(key_id):
    data = load_key_store()
    data["keys"] = [k for k in data["keys"] if k.get("id") != key_id]
    save_key_store(data)


def load_settings():
    merged = dict(DEFAULT_SETTINGS)
    if VOLATILE:
        bucket = _mem()
        if bucket["settings"] is None:
            bucket["settings"] = dict(DEFAULT_SETTINGS)
        merged.update(bucket["settings"])
        return merged
    ws = workspace()
    settings_path = ws["settings_file"]
    if settings_path.exists():
        try:
            with open(settings_path, "r", encoding="utf-8") as fh:
                merged.update(json.load(fh))
        except (json.JSONDecodeError, OSError):
            pass
    return merged


def save_settings(settings):
    if VOLATILE:
        _mem()["settings"] = dict(settings)
        return
    ws = workspace()
    with open(ws["settings_file"], "w", encoding="utf-8") as fh:
        json.dump(settings, fh, indent=2)


def compute_stats():
    logs = read_logs()

    def count(pred):
        return sum(1 for l in logs if pred(l))

    stats = {
        "total_operations": len(logs),
        "encrypted_files": count(lambda l: l.get("category") == "AES" and l.get("action") == "Encrypt file" and l.get("status") == "success"),
        "decrypted_files": count(lambda l: l.get("category") == "AES" and l.get("action") == "Decrypt file" and l.get("status") == "success"),
        "text_operations": count(lambda l: l.get("category") == "AES" and "text" in l.get("action", "").lower()),
        "keys_generated": count(lambda l: l.get("action") == "Generate" and l.get("status") == "success"),
        "hash_operations": count(lambda l: l.get("category") == "Hashing" and l.get("status") == "success"),
        "password_operations": count(lambda l: l.get("category") == "Password"),
        "rsa_operations": count(lambda l: l.get("category") == "RSA"),
        "success": count(lambda l: l.get("status") == "success"),
        "failed": count(lambda l: l.get("status") == "failed"),
    }
    store = load_key_store()
    keys = store.get("keys", [])
    stats["aes_keys"] = sum(1 for k in keys if k.get("type") == "aes")
    stats["rsa_keys"] = sum(1 for k in keys if k.get("type") == "rsa")
    stats["total_keys"] = stats["aes_keys"] + stats["rsa_keys"]

    score = 100
    if stats["total_operations"]:
        score -= min(40, stats["failed"] * 5)
    stats["security_score"] = max(10, min(100, score))
    return stats


def save_upload(file_storage):
    """Persist an uploaded file with a random name into this session's dir.

    Enforces the per-session max upload size (settings) on top of Flask's
    MAX_CONTENT_LENGTH hard cap, so a huge file can't be written to disk."""
    limit_mb = load_settings().get("max_file_size_mb", MAX_UPLOAD_MB)
    limit_bytes = limit_mb * 1024 * 1024
    if request.content_length and request.content_length > limit_bytes:
        raise ValueError("File exceeds the {} MB upload limit".format(limit_mb))
    ws = workspace()
    ext = Path(file_storage.filename or "file").suffix or ".bin"
    name = "up_{}{}".format(uuid.uuid4().hex, ext)
    path = ws["uploads"] / name
    file_storage.save(path)
    if path.stat().st_size > limit_bytes:
        path.unlink(missing_ok=True)
        raise ValueError("File exceeds the {} MB upload limit".format(limit_mb))
    return path


def err(message, code=400):
    return jsonify({"success": False, "error": str(message)}), code


def body():
    return request.get_json(silent=True) or {}


@app.context_processor
def inject_session_info():
    return {
        "session_token": get_session_id()[:8] + "...",
        "session_id": get_session_id(),
        "volatile": VOLATILE,
    }


# --------------------------------------------------------------------------- #
#  Pages
# --------------------------------------------------------------------------- #

@app.route("/")
def dashboard():
    return render_template("dashboard.html", active="dashboard", stats=compute_stats())


@app.route("/aes")
def aes_page():
    return render_template("aes.html", active="aes")


@app.route("/rsa")
def rsa_page():
    return render_template("rsa.html", active="rsa")


@app.route("/hashing")
def hashing_page():
    return render_template("hashing.html", active="hashing", algos=sorted(ALLOWED_ALGOS))


@app.route("/keys")
def keys_page():
    return render_template("keys.html", active="keys", stats=compute_stats())


@app.route("/password")
def password_page():
    return render_template("password.html", active="password")


@app.route("/reports")
def reports_page():
    return render_template("reports.html", active="reports", stats=compute_stats())


@app.route("/settings")
def settings_page():
    return render_template("settings.html", active="settings", settings=load_settings())


# --------------------------------------------------------------------------- #
#  Dashboard API
# --------------------------------------------------------------------------- #

@app.route("/api/stats")
def api_stats():
    return jsonify({"success": True, "stats": compute_stats(), "recent": read_logs(10)})


# --------------------------------------------------------------------------- #
#  AES API
# --------------------------------------------------------------------------- #

@app.route("/api/aes/generate-key", methods=["POST"])
def api_aes_generate_key():
    try:
        data = body()
        bits = int(data.get("bits", 256))
        key = aes.generate_key(bits)
        settings = load_settings()
        saved = False
        if settings.get("auto_save_aes_keys", True):
            entry = {
                "id": "aes_" + uuid.uuid4().hex[:10],
                "type": "aes",
                "algorithm": "AES-{}".format(bits),
                "key_size": bits,
                "created": now_iso(),
                "key": key,
                "strength": "256-bit" if bits == 256 else "{} bit".format(bits),
            }
            add_key(entry)
            saved = True
        log_activity("Key Management", "Generate", "success",
                     "AES-{} key{}".format(bits, " (saved to vault)" if saved else ""))
        return jsonify({"success": True, "key": key, "saved": saved})
    except ValueError as exc:
        log_activity("Key Management", "Generate", "failed", str(exc))
        return err(exc)


@app.route("/api/aes/encrypt-text", methods=["POST"])
def api_aes_encrypt_text():
    data = body()
    key = (data.get("key") or "").strip()
    plaintext = data.get("text") or ""
    if not key:
        return err("AES key is required")
    if not plaintext:
        return err("Plaintext is required")
    try:
        result = aes.encrypt_text(key, plaintext)
        log_activity("AES", "Encrypt text", "success", "{} chars -> {} bytes".format(len(plaintext), len(result)))
        return jsonify({"success": True, "result": result})
    except ValueError as exc:
        log_activity("AES", "Encrypt text", "failed", str(exc))
        return err(exc)


@app.route("/api/aes/decrypt-text", methods=["POST"])
def api_aes_decrypt_text():
    data = body()
    key = (data.get("key") or "").strip()
    ciphertext = (data.get("text") or "").strip()
    if not key:
        return err("AES key is required")
    if not ciphertext:
        return err("Ciphertext is required")
    try:
        result = aes.decrypt_text(key, ciphertext)
        log_activity("AES", "Decrypt text", "success", "{} bytes decrypted".format(len(ciphertext)))
        return jsonify({"success": True, "result": result})
    except ValueError as exc:
        log_activity("AES", "Decrypt text", "failed", str(exc))
        return err(exc)


def _aes_file_op(request, op_name):
    key = (request.form.get("key") or "").strip()
    fh = request.files.get("file")
    if not key:
        return err("AES key is required")
    if not fh or not fh.filename:
        return err("No file uploaded")
    label = "Encrypt file" if op_name == "encrypt" else "Decrypt file"
    try:
        src = save_upload(fh)
        ws = workspace()
        dst = ws["uploads"] / ("enc_{}.enc" if op_name == "encrypt" else "dec_{}").format(uuid.uuid4().hex)
        try:
            with open(src, "rb") as fin, open(dst, "wb") as fout:
                if op_name == "encrypt":
                    aes.encrypt_file(key, fin, fout)
                else:
                    aes.decrypt_file(key, fin, fout)
        except Exception:
            dst.unlink(missing_ok=True)
            raise
        finally:
            if load_settings().get("auto_delete_uploads", True):
                src.unlink(missing_ok=True)
        size = dst.stat().st_size
        log_activity("AES", label, "success", "{} -> {} ({} bytes)".format(fh.filename, dst.name, size))
        return jsonify({
            "success": True,
            "filename": dst.name,
            "size": size,
            "download_url": "/download/{}".format(dst.name),
            "source_deleted": load_settings().get("auto_delete_uploads", True),
        })
    except ValueError as exc:
        log_activity("AES", label, "failed", str(exc))
        return err(exc)
    except OSError as exc:
        return err("File processing error: {}".format(exc))


@app.route("/api/aes/encrypt-file", methods=["POST"])
def api_aes_encrypt_file():
    return _aes_file_op(request, "encrypt")


@app.route("/api/aes/decrypt-file", methods=["POST"])
def api_aes_decrypt_file():
    return _aes_file_op(request, "decrypt")


# --------------------------------------------------------------------------- #
#  RSA API
# --------------------------------------------------------------------------- #

@app.route("/api/rsa/generate", methods=["POST"])
def api_rsa_generate():
    try:
        data = body()
        bits = int(data.get("bits", 2048))
        if bits < 2048:
            log_activity("Key Management", "Generate", "failed",
                         "RSA-{} rejected: <2048 bits is cryptographically weak".format(bits))
            return err("RSA-{} is no longer secure. Minimum is 2048 bits (4096 recommended).".format(bits), 400)
        priv_pem, pub_pem = rsa.generate_keypair(bits)
        key_id = "rsa_" + uuid.uuid4().hex[:10]
        key_dir = workspace()["rsa"] / key_id
        key_dir.mkdir(parents=True, exist_ok=True)
        (key_dir / "private.pem").write_text(priv_pem, encoding="utf-8")
        (key_dir / "public.pem").write_text(pub_pem, encoding="utf-8")

        entry = {
            "id": key_id,
            "type": "rsa",
            "algorithm": "RSA-{}".format(bits),
            "key_size": bits,
            "created": now_iso(),
            "strength": "Strong" if bits >= 2048 else "Legacy",
            "private_path": str(key_dir / "private.pem"),
            "public_path": str(key_dir / "public.pem"),
        }
        add_key(entry)
        log_activity("Key Management", "Generate", "success", "RSA-{} keypair".format(bits))
        return jsonify({"success": True, "key_id": key_id, "private_pem": priv_pem, "public_pem": pub_pem})
    except ValueError as exc:
        log_activity("Key Management", "Generate", "failed", str(exc))
        return err(exc)


@app.route("/api/rsa/keys", methods=["GET"])
def api_rsa_keys():
    store = load_key_store()
    keys = [k for k in store.get("keys", []) if k.get("type") == "rsa"]
    return jsonify({"success": True, "keys": keys})


@app.route("/api/rsa/encrypt", methods=["POST"])
def api_rsa_encrypt():
    data = body()
    pub_pem = (data.get("public_key") or "").strip()
    plaintext = data.get("text") or ""
    if not pub_pem:
        return err("Public key is required")
    if not plaintext:
        return err("Plaintext is required")
    try:
        ct = rsa.encrypt_data(pub_pem, plaintext)
        log_activity("RSA", "Encrypt", "success", "{} chars encrypted".format(len(plaintext)))
        return jsonify({"success": True, "result": ct})
    except ValueError as exc:
        log_activity("RSA", "Encrypt", "failed", str(exc))
        return err(exc)


@app.route("/api/rsa/decrypt", methods=["POST"])
def api_rsa_decrypt():
    data = body()
    priv_pem = (data.get("private_key") or "").strip()
    ciphertext = (data.get("text") or "").strip()
    if not priv_pem:
        return err("Private key is required")
    if not ciphertext:
        return err("Ciphertext is required")
    try:
        pt = rsa.decrypt_data(priv_pem, ciphertext)
        log_activity("RSA", "Decrypt", "success", "{} bytes decrypted".format(len(ciphertext)))
        return jsonify({"success": True, "result": pt})
    except ValueError as exc:
        log_activity("RSA", "Decrypt", "failed", str(exc))
        return err(exc)


@app.route("/api/rsa/keys/<key_id>", methods=["GET", "DELETE"])
def api_rsa_key(key_id):
    if request.method == "GET":
        store = load_key_store()
        key = next((k for k in store.get("keys", []) if k.get("id") == key_id and k.get("type") == "rsa"), None)
        if not key:
            return err("Key not found", 404)
        pub_pem = Path(key["public_path"]).read_text(encoding="utf-8")
        return jsonify({"success": True, "key": key, "public_pem": pub_pem})
    # DELETE
    delete_key(key_id)
    rsa_dir = workspace()["rsa"] / key_id
    if rsa_dir.is_dir():
        shutil.rmtree(rsa_dir, ignore_errors=True)
    log_activity("Key Management", "Delete key", "success", key_id)
    return jsonify({"success": True})


# --------------------------------------------------------------------------- #
#  Hash API
# --------------------------------------------------------------------------- #

@app.route("/api/hash/text", methods=["POST"])
def api_hash_text():
    data = body()
    text = data.get("text") or ""
    if not text:
        return err("Text is required")
    try:
        result = hashes_for_text(text)
        log_activity("Hashing", "Hash text", "success", "{} chars".format(len(text)))
        return jsonify({"success": True, "hashes": result})
    except ValueError as exc:
        log_activity("Hashing", "Hash text", "failed", str(exc))
        return err(exc)


@app.route("/api/hash/file", methods=["POST"])
def api_hash_file():
    fh = request.files.get("file")
    if not fh or not fh.filename:
        return err("No file uploaded")
    try:
        src = save_upload(fh)
        try:
            with open(src, "rb") as fin:
                result = hashes_for_file(fin)
            size = src.stat().st_size
        finally:
            if load_settings().get("auto_delete_uploads", True):
                src.unlink(missing_ok=True)
        log_activity("Hashing", "Hash file", "success", "{} ({})".format(fh.filename, size))
        return jsonify({"success": True, "filename": fh.filename, "hashes": result})
    except ValueError as exc:
        return err(exc)
    except OSError as exc:
        return err("File processing error: {}".format(exc))


@app.route("/api/hash/compare", methods=["POST"])
def api_hash_compare():
    data = body()
    first = (data.get("first") or "").strip().lower()
    second = (data.get("second") or "").strip().lower()
    if not first or not second:
        return err("Both hash values are required")
    if not re.match(r"^[0-9a-f]{32,128}$", first) or not re.match(r"^[0-9a-f]{32,128}$", second):
        return err("Invalid hex digest format")
    match = first == second
    log_activity("Hashing", "Integrity check", "success" if match else "failed",
                 "match={}".format(match))
    return jsonify({"success": True, "match": match})


# --------------------------------------------------------------------------- #
#  Key Management API
# --------------------------------------------------------------------------- #

@app.route("/api/keys", methods=["GET"])
def api_keys():
    store = load_key_store()
    keys = store.get("keys", [])
    for k in keys:
        k.pop("key", None)
    return jsonify({"success": True, "keys": keys})


@app.route("/api/keys/<key_id>", methods=["GET", "DELETE"])
def api_key(key_id):
    store = load_key_store()
    key = next((k for k in store.get("keys", []) if k.get("id") == key_id), None)
    if not key:
        return err("Key not found", 404)
    if request.method == "GET":
        if key.get("type") == "aes":
            return jsonify({"success": True, "key": key})
        pub = Path(key["public_path"]).read_text(encoding="utf-8")
        return jsonify({"success": True, "key": key, "public_pem": pub})
    # DELETE
    delete_key(key_id)
    if key.get("type") == "rsa":
        rsa_dir = workspace()["rsa"] / key_id
        if rsa_dir.is_dir():
            shutil.rmtree(rsa_dir, ignore_errors=True)
    log_activity("Key Management", "Delete key", "success", key_id)
    return jsonify({"success": True})


# --------------------------------------------------------------------------- #
#  Password Security API
# --------------------------------------------------------------------------- #

@app.route("/api/password/hash", methods=["POST"])
def api_password_hash():
    data = body()
    password = data.get("password") or ""
    if not password:
        return err("Password is required")
    if len(password) > 1024:
        return err("Password is too long")
    try:
        salt = generate_salt()
        stored = hash_password(password)
        log_activity("Password", "Hash password", "success", "salt={}".format(salt[:8] + "..."))
        return jsonify({"success": True, "salt": salt, "hash": stored, "format": "PBKDF2-HMAC-SHA256"})
    except Exception as exc:
        log_activity("Password", "Hash password", "failed", str(exc))
        return err("Hashing failed: {}".format(exc))


@app.route("/api/password/verify", methods=["POST"])
def api_password_verify():
    data = body()
    password = data.get("password") or ""
    stored = (data.get("hash") or "").strip()
    if not password or not stored:
        return err("Password and stored hash are required")
    ok = verify_password(password, stored)
    log_activity("Password", "Verify password", "success" if ok else "failed",
                 "result={}".format(ok))
    return jsonify({"success": True, "match": ok})


@app.route("/api/password/strength", methods=["POST"])
def api_password_strength():
    data = body()
    password = data.get("password") or ""
    result = password_strength(password)
    return jsonify({"success": True, "strength": result})


# --------------------------------------------------------------------------- #
#  Reports API
# --------------------------------------------------------------------------- #

def build_report():
    settings = load_settings()
    logs = read_logs()
    stats = compute_stats()

    by_category = {}
    for l in logs:
        cat = l.get("category", "Other")
        bucket = by_category.setdefault(cat, {"success": 0, "failed": 0})
        status = l.get("status", "success")
        bucket[status] = bucket.get(status, 0) + 1

    by_day = {}
    for l in logs:
        day = l.get("timestamp", "")[:10]
        if day:
            by_day[day] = by_day.get(day, 0) + 1

    store = load_key_store()
    key_meta = [
        {"id": k.get("id"), "type": k.get("type"), "algorithm": k.get("algorithm"),
         "key_size": k.get("key_size"), "created": k.get("created")}
        for k in store.get("keys", [])
    ]

    return {
        "title": "KeyGuard Security Operations Report",
        "generated_at": now_iso(),
        "keyguard_version": "1.0.0",
        "summary": stats,
        "breakdown_by_category": by_category,
        "operations_by_day": by_day,
        "managed_keys": key_meta,
        "settings": settings,
        "activity_log": logs if settings.get("report_include_logs", True) else None,
    }


def _md_report(report):
    lines = [
        "# {}".format(report["title"]),
        "",
        "**Generated:** {}  ".format(report["generated_at"]),
        "**KeyGuard version:** {}".format(report["keyguard_version"]),
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|---|---|",
        "| Total operations | {} |".format(report["summary"]["total_operations"]),
        "| Successful | {} |".format(report["summary"]["success"]),
        "| Failed | {} |".format(report["summary"]["failed"]),
        "| Encrypted files | {} |".format(report["summary"]["encrypted_files"]),
        "| Decrypted files | {} |".format(report["summary"]["decrypted_files"]),
        "| Keys generated | {} |".format(report["summary"]["keys_generated"]),
        "| Hash operations | {} |".format(report["summary"]["hash_operations"]),
        "| Password operations | {} |".format(report["summary"]["password_operations"]),
        "| RSA operations | {} |".format(report["summary"]["rsa_operations"]),
        "| Managed keys | {} |".format(report["summary"]["total_keys"]),
        "| Security score | {} / 100 |".format(report["summary"]["security_score"]),
        "",
        "## Breakdown by category",
        "",
    ]
    for cat, counts in sorted(report["breakdown_by_category"].items()):
        lines.append("- **{}**: {} success / {} failed".format(cat, counts.get("success", 0), counts.get("failed", 0)))
    lines += ["", "## Operations by day", ""]
    for day, n in sorted(report["operations_by_day"].items()):
        lines.append("- {}: {}".format(day, n))
    lines += ["", "## Managed keys", ""]
    for k in report["managed_keys"]:
        lines.append("- `{}` — {} ({}), created {}".format(k["id"], k["algorithm"], k.get("key_size"), k["created"]))
    lines += ["", "_This report was generated by KeyGuard v1.0.0._", ""]
    return "\n".join(lines)


@app.route("/api/reports/generate", methods=["POST"])
def api_reports_generate():
    try:
        report = build_report()
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_name = "keyguard_report_{}.json".format(stamp)
        md_name = "keyguard_report_{}.md".format(stamp)
        ws = workspace()
        (ws["reports"] / json_name).write_text(json.dumps(report, indent=2), encoding="utf-8")
        (ws["reports"] / md_name).write_text(_md_report(report), encoding="utf-8")
        log_activity("Reports", "Generate report", "success", json_name)
        return jsonify({
            "success": True,
            "json_file": json_name,
            "md_file": md_name,
            "json_url": "/reports/download/{}".format(json_name),
            "md_url": "/reports/download/{}".format(md_name),
        })
    except OSError as exc:
        log_activity("Reports", "Generate report", "failed", str(exc))
        return err("Could not write report: {}".format(exc))


@app.route("/api/reports/list")
def api_reports_list():
    files = sorted(
        ({"name": p.name, "size": p.stat().st_size, "modified": datetime.fromtimestamp(p.stat().st_mtime).isoformat(timespec="seconds")}
         for p in workspace()["reports"].glob("*") if p.is_file()),
        key=lambda f: f["modified"], reverse=True,
    )
    return jsonify({"success": True, "files": files})


@app.route("/reports/download/<name>")
def reports_download(name):
    reports_dir = workspace()["reports"]
    if not (reports_dir / name).is_file():
        return err("Report not found", 404)
    return send_from_directory(reports_dir, name, as_attachment=True)


@app.route("/api/reports/logs")
def api_reports_logs():
    limit = request.args.get("limit", type=int)
    return jsonify({"success": True, "logs": read_logs(limit)})


# --------------------------------------------------------------------------- #
#  Settings API
# --------------------------------------------------------------------------- #

@app.route("/api/settings", methods=["GET", "POST"])
def api_settings():
    if request.method == "GET":
        return jsonify({"success": True, "settings": load_settings()})
    data = body()
    settings = load_settings()
    for k in ("auto_save_aes_keys", "auto_delete_uploads", "report_include_logs"):
        if k in data:
            settings[k] = bool(data[k])
    if "max_file_size_mb" in data:
        try:
            settings["max_file_size_mb"] = int(data["max_file_size_mb"])
        except (ValueError, TypeError):
            pass
    if "security_level" in data and data["security_level"] in ("High", "Medium", "Low"):
        settings["security_level"] = data["security_level"]
    save_settings(settings)
    log_activity("Settings", "Update settings", "success")
    return jsonify({"success": True, "settings": settings})


@app.route("/api/settings/clear-log", methods=["POST"])
def api_clear_log():
    workspace()["activity_log"].unlink(missing_ok=True)
    return jsonify({"success": True})


# --------------------------------------------------------------------------- #
#  Session / privacy API
# --------------------------------------------------------------------------- #

@app.route("/api/session")
def api_session():
    return jsonify({
        "success": True,
        "session_id": get_session_id(),
        "token": get_session_id()[:8] + "...",
        "volatile": VOLATILE,
    })


@app.route("/api/session/reset", methods=["POST"])
def api_session_reset():
    """Wipe all of this session's data and mint a fresh, clean session."""
    sid = get_session_id()
    if VOLATILE:
        _MEM.pop(sid, None)
        tmp = _TEMP_DIRS.pop(sid, None)
        if tmp is not None:
            try:
                tmp.cleanup()
            except OSError:
                pass
    else:
        shutil.rmtree(DATA_ROOT / sid, ignore_errors=True)
    session.pop("sid", None)
    new_sid = get_session_id()
    log_activity("Settings", "Reset session", "success", "started fresh session")
    return jsonify({"success": True, "session_id": new_sid, "volatile": VOLATILE})


# --------------------------------------------------------------------------- #
#  File downloads
# --------------------------------------------------------------------------- #

@app.route("/download/<name>")
def download(name):
    uploads_dir = workspace()["uploads"]
    if not (uploads_dir / name).is_file():
        return err("File not found", 404)
    return send_from_directory(uploads_dir, name, as_attachment=True)


# --------------------------------------------------------------------------- #
#  Misc
# --------------------------------------------------------------------------- #

@app.errorhandler(413)
def too_large(_e):
    return err("Uploaded file exceeds the size limit")


@app.errorhandler(404)
def not_found(_e):
    return err("Page not found", 404)


@app.errorhandler(500)
def server_error(_e):
    return err("Internal server error", 500)


if __name__ == "__main__":
    # Railway (and most PaaS) provide the port via the PORT environment variable.
    # Bind 0.0.0.0 so the app is reachable outside the container.
    start_session_cleanup()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
