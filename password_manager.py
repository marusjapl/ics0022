#!/usr/bin/env python3
"""
password_manager.py — Single-file secure password manager for single user
"""
import os
import sys
import json
import base64
import getpass
import datetime
import uuid
import re
import signal
import shutil
import string
from typing import Optional
# pip install bcrypt cryptography
import bcrypt
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================================================
#  SIGNAL HANDLING (Ctrl+C, Ctrl+Z, Ctrl+\ , kill)
# ============================================================
def graceful_terminal_exit(signum, _frame):
    signals = {
        signal.SIGINT: "Ctrl+C",
        signal.SIGTSTP: "Ctrl+Z",
        signal.SIGQUIT: "Ctrl+\\",
        signal.SIGTERM: "SIGTERM"
    }
    key = signals.get(signum, "Unknown")

    try:
        log_event("signal_exit", outcome="info", details={"signal": key})
    except Exception:
        pass

    print(f"\n\n✨ Program terminated ({key}). Your session has been safely closed. ✨")
    sys.exit(0)


# Handle Ctrl+C, Ctrl+Z, Ctrl+\, and SIGTERM with a friendly exit. If user the signal is used, run handler
signal.signal(signal.SIGINT, graceful_terminal_exit)  # Ctrl+C
signal.signal(signal.SIGTSTP, graceful_terminal_exit)  # Ctrl+Z
signal.signal(signal.SIGQUIT, graceful_terminal_exit)  # Ctrl+\
signal.signal(signal.SIGTERM, graceful_terminal_exit)  # kill <pid>

# ============================================================
#  CONFIGURATION
# ============================================================

USER_FILE = "user.json"  # stores only master password hash and KDF salt
VAULT_FILE = "vault.bin"  # encrypted vault of credentials
LOG_FILE = ".pm_events.log"

SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN = 32

# ============================================================
#  REGEX VALIDATION
# ============================================================

SITE_PATTERN = re.compile(r"^[A-Za-z0-9 _\-.\@:/?#&()[\]%+,'\"]{1,200}$")
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.@-]{1,100}$")
MENU_CHOICE_PATTERN = re.compile(r"^[0-9]+$")
CONFIRM_PATTERN = re.compile(r"^[A-Z]{3,20}$")


# ============================================================
#  BASE64 HELPERS
# ============================================================
# Encode bytes to base64 ASCII for JSON storage.
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


# Decode base64 ASCII string back to bytes.
def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


# ============================================================
#  LOGGING
# ============================================================
# Return current UTC time as ISO 8601 string with 'Z'.
def _now_iso():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def log_event(event: str, user: Optional[str] = None, session: Optional[str] = None,
              outcome: str = "info", details: Optional[dict] = None):
    try:
        rec = {
            "ts": _now_iso(),
            "event": event,
            "user": user,
            "session": session,
            "outcome": outcome,
            "details": details or {}
        }
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass


# ============================================================
#  FILE PERMISSIONS
# ============================================================

def set_owner_only_permissions(path: str):
    try:
        os.chmod(path, 0o600)  # owner read/write only
    except Exception:
        pass


# ============================================================
#  INPUT SANITIZATION
# ============================================================

def sanitize_field(s: Optional[str], maxlen: int = 200) -> str:
    if s is None:
        return ""
    s = str(s)
    sanitized = "".join(ch for ch in s if ord(ch) >= 0x20 and ord(ch) != 0x7f)
    return sanitized[:maxlen]


def validate_site(site: str) -> bool:
    site = site.strip()
    if not site:
        return False
    return bool(SITE_PATTERN.fullmatch(site))


def validate_account_username(username: str) -> bool:
    username = username.strip()
    if not username:
        return False
    return bool(USERNAME_PATTERN.fullmatch(username))


def validate_menu_choice(choice: str) -> bool:
    return bool(MENU_CHOICE_PATTERN.fullmatch(choice)) and len(choice) <= 3


def validate_confirmation(token: str) -> bool:
    return bool(CONFIRM_PATTERN.fullmatch(token))


# ============================================================
#  MEMORY WIPE
# ============================================================
# Overwrite each byte with zero to reduce risk of master password lingering in memory.
def wipe_bytearray(b: Optional[bytearray]):
    if not b:
        return
    try:
        for i in range(len(b)):
            b[i] = 0
    except Exception:
        pass


# ============================================================
#  CRYPTO
# ============================================================

def hash_master_password(password_bytes: bytes) -> bytes:
    return bcrypt.hashpw(password_bytes, bcrypt.gensalt())


def verify_master_password(password_bytes: bytes, bcrypt_hash: bytes) -> bool:
    try:
        return bcrypt.checkpw(password_bytes, bcrypt_hash)
    except Exception:
        return False


# From the master password derive an encryption key
def derive_key(password_bytes: bytes, salt: bytes,
               n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P) -> bytes:
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=n, r=r, p=p)
    return kdf.derive(password_bytes)


def encrypt_data(key: bytes, plaintext: bytes) -> bytes:
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, None)
    return nonce + ct  # this is stored in the vault: credentials


def decrypt_data(key: bytes, data: bytes) -> bytes:
    if len(data) < 13:
        raise ValueError("ciphertext too short")
    aes = AESGCM(key)
    return aes.decrypt(data[:12], data[12:], None)


# ============================================================
#  UTILITY: SAFE PASSWORD INPUT (prevents accidental paste)
# ============================================================

def safe_password_input(prompt: str = "Password: ", max_length: int = 128) -> Optional[str]:
    pwd = getpass.getpass(prompt)

    # Block extremely long inputs
    if len(pwd) > max_length:
        print("Error: Password too long — possible accidental paste.")
        log_event("password_input_rejected", outcome="failure", details={"reason": "too_long", "length": len(pwd)})
        return None

    return pwd


# ============================================================
#  USER MANAGEMENT
# ============================================================

def user_exists() -> bool:
    return os.path.exists(USER_FILE)  # return True if user exists


def create_user_interactive() -> bytes:
    print("No user detected. Create a master password.")
    pw = safe_password_input("Create master password (min 12 chars): ")
    if pw is None:
        return b""  # input violation or user aborted

    if not validate_password_strength(pw):
        print("Weak master password!")
        print("Requirements:")
        print("- At least 12 characters")
        print("- Must contain upper, lower, number, and special character")
        print("- No spaces")
        print("- Cannot be common (e.g., 'password', '123456')")
        return b""

    pw_ba = bytearray(pw.encode("utf-8"))  # convert to mutable array for memory wipe
    try:
        bcrypt_hash = hash_master_password(bytes(pw_ba))  # erase plaintext password from memory
    finally:
        wipe_bytearray(pw_ba)

    salt = os.urandom(16)  # 128-bit KDF salt

    data = {
        "bcrypt_hash_b64": b64e(bcrypt_hash),
        "kdf_salt_b64": b64e(salt),
        "kdf_params": {"n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P}
    }

    try:
        tmp = USER_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, USER_FILE)  # atomic replacement
        set_owner_only_permissions(USER_FILE)
        log_event("user_create", outcome="success")
    except Exception as e:
        log_event("user_create_failed", outcome="failure", details={"error": str(e)})
        print("Unable to create user.")
        return b""

    print("Master password created.")
    return salt


def authenticate_interactive() -> Optional[tuple]:
    if not user_exists():
        print("No user exists.")
        return None

    try:
        with open(USER_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        bcrypt_hash = b64d(data["bcrypt_hash_b64"])
        salt = b64d(data["kdf_salt_b64"])
    except Exception:
        log_event("user_meta_corrupt", outcome="failure")
        print("User metadata corrupt.")
        return None

    pw = safe_password_input("Enter master password: ")
    if pw is None:
        # Input violation detected (multi-line or too long)
        return None

    pw_ba = bytearray(pw.encode("utf-8"))

    try:
        ok = verify_master_password(bytes(pw_ba), bcrypt_hash)
        if not ok:
            log_event("login_attempt", outcome="failure")
            print("Authentication failed.")
            return None

        key = derive_key(bytes(pw_ba), salt)
    finally:
        wipe_bytearray(pw_ba)  # erase master password from memory

    session_id = str(uuid.uuid4())
    log_event("login_attempt", session=session_id, outcome="success")
    return key, session_id


# ============================================================
#  VAULT OPERATIONS
# ============================================================
# Load and decrypt the vault using key. Return vault as dict; if file missing, return empty vault.
def load_vault(key: bytes) -> dict:
    if not os.path.exists(VAULT_FILE):
        return {"credentials": []}

    try:
        with open(VAULT_FILE, "rb") as f:
            blob = f.read()
        plaintext = decrypt_data(key, blob)
        return json.loads(plaintext.decode("utf-8"))
    except Exception as e:
        log_event("vault_open_failed", outcome="failure", details={"error": str(e)})
        raise ValueError("Unable to open vault.")


# Encrypt vault and write to disk atomically; backup previous vault.
def save_vault(key: bytes, vault: dict):
    try:
        backup_vault_file()  # make timestamped backup before overwriting
        data = json.dumps(vault, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        blob = encrypt_data(key, data)
        tmp = VAULT_FILE + ".tmp"
        with open(tmp, "wb") as f:
            f.write(blob)
        os.replace(tmp, VAULT_FILE)  # atomic replace
        set_owner_only_permissions(VAULT_FILE)
    except Exception as e:
        log_event("vault_save_failed", outcome="failure", details={"error": str(e)})
        raise ValueError("Unable to save vault.")


# Create timestamped backup of vault for recovery purposes.
def backup_vault_file():
    if not os.path.exists(VAULT_FILE):
        return  # nothing to back up yet

    backup_dir = "vault_versions"
    os.makedirs(backup_dir, exist_ok=True)  # create folder if missing

    ts = _now_iso().replace(":", "-")  # safe timestamp for filename
    backup_path = os.path.join(backup_dir, f"vault_{ts}.bin")

    try:
        shutil.copy2(VAULT_FILE, backup_path)  # copy original vault
        set_owner_only_permissions(backup_path)
        log_event("vault_backup", user="local", outcome="success", details={"file": backup_path})
    except Exception as e:
        log_event("vault_backup_failed", user="local", outcome="failure", details={"error": str(e)})


# ============================================================
#  PASSWORD VALIDATION
# ============================================================

def validate_password_strength(pwd: str) -> bool:
    if len(pwd) < 12:
        return False

    if any(ch.isspace() for ch in pwd):
        return False

    has_upper = any(ch.isupper() for ch in pwd)
    has_lower = any(ch.islower() for ch in pwd)
    has_digit = any(ch.isdigit() for ch in pwd)
    has_special = any(ch in string.punctuation for ch in pwd)

    return has_upper and has_lower and has_digit and has_special


# ============================================================
#  VAULT INTERACTIVE FUNCTIONS
# ============================================================

def add_entry_interactive(vault, key, session_id):
    site = input("Site / service name: ").strip()
    if not validate_site(site):
        print("Invalid site.")
        return

    login = input("Account username: ").strip()
    if not validate_account_username(login):
        print("Invalid username.")
        return

    pwd = safe_password_input("Password: ")
    if pwd is None:  # input violation or empty
        return
    if not pwd:
        print("Password cannot be empty.")
        return

    if not validate_password_strength(pwd):
        print("Weak password! Must be 12 chars long and include upper, lower, number, special symbol.")
        return

    vault["credentials"].append({
        "id": str(uuid.uuid4()),
        "site": sanitize_field(site, 200),
        "username": sanitize_field(login, 100),
        "password": pwd
    })

    save_vault(key, vault)
    log_event("entry_add", session=session_id, outcome="success", details={"site": site})


def list_entries(vault):
    if not vault.get("credentials"):
        print("No entries found.")
        return

    print("\nStored credentials:")
    for i, e in enumerate(vault["credentials"], start=1):
        print(f"{i}. {e.get('site')} ({e.get('username')})")


def view_entry(vault, session_id):
    if not vault.get("credentials"):
        print("No entries to view.")
        return

    list_entries(vault)
    idx = input("Entry number to view: ").strip()

    if not idx.isdigit():
        print("Invalid input.")
        return

    i = int(idx) - 1
    if i < 0 or i >= len(vault["credentials"]):
        print("Invalid number.")
        return

    entry = vault["credentials"][i]

    confirm = input("Show password? (y/N): ").strip().lower()
    if confirm != "y":
        print("Aborted.")
        return

    print("\n--- Entry ---")
    print("Site:    ", entry["site"])
    print("Username:", entry["username"])
    print("Password:", entry["password"])
    print("-------------\n")

    log_event("entry_view", session=session_id, outcome="success", details={"site": entry["site"]})


def update_entry_interactive(vault, key, session_id):
    if not vault.get("credentials"):
        print("No entries to update.")
        return

    list_entries(vault)
    idx = input("Entry number to update: ").strip()

    if not idx.isdigit():
        print("Invalid input.")
        return

    i = int(idx) - 1
    if i < 0 or i >= len(vault["credentials"]):
        print("Invalid number.")
        return

    entry = vault["credentials"][i]

    print("Press ENTER to keep the existing value.")

    new_site = input(f"Site [{entry['site']}]: ").strip()
    if new_site and not validate_site(new_site):
        print("Invalid site.")
        return

    new_login = input(f"Username [{entry['username']}]: ").strip()
    if new_login and not validate_account_username(new_login):
        print("Invalid username.")
        return

    new_pwd = safe_password_input("New password (leave blank to keep): ")
    if new_pwd is None:  # allow blank (keep), None (paste error) or new password
        return

    if new_pwd and not validate_password_strength(new_pwd):
        print("Weak password! Update aborted.")
        return

    if new_site:
        entry["site"] = sanitize_field(new_site, 200)
    if new_login:
        entry["username"] = sanitize_field(new_login, 100)
    if new_pwd:
        entry["password"] = new_pwd

    save_vault(key, vault)
    log_event("entry_update", session=session_id, outcome="success", details={"site": entry["site"]})
    print("Updated.")


def delete_entry_interactive(vault, key, session_id):
    if not vault.get("credentials"):
        print("No entries to delete.")
        return

    list_entries(vault)
    idx = input("Entry number to delete: ").strip()

    if not idx.isdigit():
        print("Invalid input.")
        return

    i = int(idx) - 1
    if i < 0 or i >= len(vault["credentials"]):
        print("Invalid number.")
        return

    entry = vault["credentials"][i]
    print("To confirm deletion, type DELETE.")

    confirm = input("Confirm: ").strip()
    if confirm != "DELETE":
        print("Aborted.")
        return

    vault["credentials"].pop(i)
    save_vault(key, vault)

    log_event("entry_delete", session=session_id, outcome="success", details={"site": entry["site"]})
    print("Deleted.")


# ============================================================
#  MAIN APPLICATION FLOW
# ============================================================

def main():
    try:
        print("=== Secure Password Manager ===")

        if not user_exists():
            salt = create_user_interactive()
            if not salt:
                return
            print("Please log in using your new master password.")

        auth = authenticate_interactive()
        if not auth:
            return

        key, session_id = auth

        try:
            vault = load_vault(key)  # load the encrypted vault
        except ValueError:
            print("Could not open vault.")
            return

        while True:
            print("\nMenu:")
            print("1. Add credential")
            print("2. List credentials")
            print("3. View credential")
            print("4. Update credential")
            print("5. Delete credential")
            print("6. Exit")

            choice = input("> ").strip()

            if not validate_menu_choice(choice):
                print("Invalid choice.")
                continue

            if choice == "1":
                add_entry_interactive(vault, key, session_id)
            elif choice == "2":
                list_entries(vault)
            elif choice == "3":
                view_entry(vault, session_id)
            elif choice == "4":
                update_entry_interactive(vault, key, session_id)
            elif choice == "5":
                delete_entry_interactive(vault, key, session_id)
            elif choice == "6":
                log_event("logout", session=session_id, outcome="success")
                print("✨ Goodbye! ✨")
                break

    except Exception:
        # Catch any unexpected error to prevent crash and log it
        log_event("unhandled_exception", outcome="failure")
        print("Unexpected error — see log.")


# ============================================================
#  ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()
