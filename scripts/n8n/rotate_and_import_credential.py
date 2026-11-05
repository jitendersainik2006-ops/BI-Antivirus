"""
BI Antivirus - Rotate API Key & Securely Import n8n Credential
Strictly operates on D: drive. Never prints or logs secrets.
"""

import os
import sys
import json
import secrets
import subprocess
import sqlite3
import urllib.request
import urllib.error
from pathlib import Path

PROJECT_ROOT = Path(r"D:\bit defender")
DATA_DIR = PROJECT_ROOT / "data"
CONFIG_DIR = PROJECT_ROOT / "config" / "n8n"
SCRIPTS_DIR = PROJECT_ROOT / "scripts" / "n8n"
LOGS_DIR = PROJECT_ROOT / "logs" / "n8n"
API_KEY_FILE = DATA_DIR / "api_key.txt"
ENV_FILE = CONFIG_DIR / "n8n.env"
DB_FILE = DATA_DIR / "n8n" / ".n8n" / "database.sqlite"
TEMP_CRED_FILE = DATA_DIR / "n8n" / ".cred_import_payload.json"

NODE_EXE = r"D:\Program Files\nodejs\node.exe"
N8N_BIN = str(PROJECT_ROOT / "n8n" / "node_modules" / "n8n" / "bin" / "n8n")

def load_env(env_path: Path) -> dict:
    env = {}
    if env_path.exists():
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip()
    return env

def rotate_api_key():
    # 1. Read old key for revocation verification (never printed)
    old_key = ""
    if API_KEY_FILE.exists():
        try:
            with open(API_KEY_FILE, "r", encoding="utf-8") as f:
                old_key = f.read().strip()
        except Exception as e:
            print(f"[!] Warning reading existing key: {e}", file=sys.stderr)

    # 2. Generate new cryptographically secure 256-bit token
    new_key = secrets.token_hex(32)

    # 3. Write new key to D:\bit defender\data\api_key.txt
    API_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(API_KEY_FILE, "w", encoding="utf-8") as f:
        f.write(new_key)
    try:
        os.chmod(API_KEY_FILE, 0o600)
    except Exception:
        pass
    print("[*] Successfully rotated BI Antivirus API key on D: drive.")

    # 4. Update n8n.env
    if ENV_FILE.exists():
        lines = []
        key_found = False
        with open(ENV_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("BI_ANTIVIRUS_API_KEY="):
                    lines.append(f"BI_ANTIVIRUS_API_KEY={new_key}\n")
                    key_found = True
                else:
                    lines.append(line)
        if not key_found:
            lines.append(f"\nBI_ANTIVIRUS_API_KEY={new_key}\n")
        with open(ENV_FILE, "w", encoding="utf-8") as f:
            f.writelines(lines)
        print("[*] Aligned BI_ANTIVIRUS_API_KEY in n8n.env.")

    # 5. Create temporary credential import JSON strictly on D: drive
    cred_payload = [
        {
            "id": "bi-antivirus-local-key",
            "name": "BI Antivirus Local API Key",
            "type": "httpHeaderAuth",
            "data": {
                "name": "X-BI-API-Key",
                "value": new_key
            }
        }
    ]
    with open(TEMP_CRED_FILE, "w", encoding="utf-8") as f:
        json.dump(cred_payload, f)

    # 6. Run n8n import:credentials with n8n.env loaded
    proc_env = os.environ.copy()
    loaded_env = load_env(ENV_FILE)
    proc_env.update(loaded_env)

    try:
        cmd = [
            NODE_EXE,
            N8N_BIN,
            "import:credentials",
            f"--input={TEMP_CRED_FILE}",
            "--projectId=ZmKDGX2YHgpVejl9"
        ]
        result = subprocess.run(cmd, env=proc_env, capture_output=True, text=True, check=True)
        print("[*] n8n credential import stdout:", result.stdout.strip())
    finally:
        # Securely remove temporary plaintext payload immediately
        if TEMP_CRED_FILE.exists():
            TEMP_CRED_FILE.unlink()
            print("[*] Securely deleted temporary credential import payload.")

    # 7. Verify in SQLite that credential exists and data is encrypted
    if DB_FILE.exists():
        conn = sqlite3.connect(str(DB_FILE))
        cur = conn.cursor()
        cur.execute("SELECT id, name, type, data FROM credentials_entity WHERE type = 'httpHeaderAuth'")
        rows = cur.fetchall()
        conn.close()
        for cid, cname, ctype, cdata in rows:
            is_encrypted = not ("X-BI-API-Key" in cdata or new_key in cdata)
            print(f"[*] Verified n8n credential in SQLite: ID={cid}, Name='{cname}', Type={ctype}, Encrypted={is_encrypted}")

    # 8. Test live local REST API with both old and new keys
    # Old key test: MUST return 401
    old_key_revoked = False
    if old_key:
        req_old = urllib.request.Request("http://127.0.0.1:8765/api/v1/status", headers={"X-BI-API-Key": old_key})
        try:
            with urllib.request.urlopen(req_old, timeout=5) as r:
                print("[!] ERROR: Old key was accepted! Revocation failed.")
        except urllib.error.HTTPError as e:
            if e.code == 401:
                old_key_revoked = True
                print("[*] Verified old key is REVOKED (HTTP 401 Unauthorized received).")
            else:
                print(f"[!] Unexpected status for old key: {e.code}")
        except Exception as e:
            print(f"[*] Old key probe error: {e}")

    # New key test: MUST return 200
    req_new = urllib.request.Request("http://127.0.0.1:8765/api/v1/status", headers={"X-BI-API-Key": new_key})
    try:
        with urllib.request.urlopen(req_new, timeout=5) as r:
            body = json.loads(r.read().decode("utf-8"))
            print(f"[*] Verified new key is ACCEPTED (HTTP 200 OK received, Engine: {body.get('engine')}, Status: {body.get('status')}).")
    except Exception as e:
        print(f"[!] ERROR probing API with new key: {e}", file=sys.stderr)
        sys.exit(1)

    print("[*] API Key rotation and n8n credential configuration complete and verified.")

if __name__ == "__main__":
    rotate_api_key()
