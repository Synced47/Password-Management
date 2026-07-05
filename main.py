import json
import secrets
import base64
import os
import pyperclip
import argparse
from getpass import getpass
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

TIME_COST = 3
MEMORY_COST = 65536
PARALLELISM = 4

def prompt_master_password() -> str:
    while True:
        pw1 = getpass("Enter Password: ")
        pw2 = getpass("Confirm Password: ")
        if pw1 != pw2:
            print("Passwords did not match. Try again\n")
            continue
        if len(pw1) < 8:
            print("Password needs to be more than 8 characters\n")
            continue
        return pw1
    
def derive_key(password: str, salt: bytes, time_cost: int, memory_cost: int, parallelism: int) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=32,
        type=Type.ID,
    )

def init_vault(path: str = "vault.json"):
    if os.path.exists(path):
        overwrite = input(f"{path} already exists. Overwrite and destroy it? (yes/no): ").strip()
        if overwrite.lower() != "yes":
            print("Aborted.")
            return

    password = prompt_master_password()

    salt = secrets.token_bytes(16)
    time_cost = TIME_COST
    memory_cost = MEMORY_COST
    parallelism = PARALLELISM
    key = derive_key(password, salt, time_cost, memory_cost, parallelism)

    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key=key)

    empty_data = json.dumps({"entries": []}).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce=nonce, data=empty_data, associated_data=None)

    vault_file = {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "kdf_params": {
            "time_cost": time_cost,
            "memory_cost": memory_cost,
            "parallelism": parallelism,
        },
    }

    with open(path, "w") as f:
        json.dump(vault_file, f, indent=2)

    print(f"Vault created at {path}")

def load_vault_file(path: str = "vault.json") -> dict:
    with open(path, "r") as f:
        vault_file = json.load(f)

    salt = base64.b64decode(vault_file["salt"])
    nonce = base64.b64decode(vault_file["nonce"])
    ciphertext = base64.b64decode(vault_file["ciphertext"])
    kdf_params = vault_file["kdf_params"]

    return {
        "salt": salt,
        "nonce": nonce,
        "ciphertext": ciphertext,
        "kdf_params": kdf_params
    }

def unlock_vault(path: str = "vault.json") -> dict:
    vault_data = load_vault_file(path)
    kdf_params = vault_data["kdf_params"]

    password = getpass("Enter Password: ")

    key = derive_key(
        password,
        vault_data["salt"],
        kdf_params["time_cost"],
        kdf_params["memory_cost"],
        kdf_params["parallelism"],
    )

    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(
            vault_data["nonce"],
            vault_data["ciphertext"],
            associated_data=None,
        )
    except InvalidTag:
        print("Wrong Password.")
        return None
    
    entries = json.loads(plaintext)["entries"]
    return {
        "entries": entries,
        "password": password,
        "salt": vault_data["salt"],
        "kdf_params": kdf_params,
    }

def print_entries(entries: list):
    if not entries:
        print("No entries yet.")
        return
    
    for i, entry in enumerate(entries, start=1):
        print(f"[{i}] {entry['site']}")

def run_session(entries: list, password: str, salt: bytes, kdf_params: dict, path: str = "vault.json"):
    try:
        while True:
            print()
            print_entries(entries)
            print()
            command = input("Command (number to view, 'a' add, 'd' delete, 'q' quit): ").strip()

            if command == "q":
                pyperclip.copy("")
                print("Goodbye.")
                break
            elif command == "a":
                add_entry(entries, password, salt, kdf_params)
            elif command == "d":
                delete_entry(entries, password, salt, kdf_params)
            elif command.isdigit():
                index = int(command) - 1
                if 0 <= index < len(entries):
                    reveal_entry(entries[index])
                else:
                    print("Invalid number.")
            else:
                print("Invalid command")
    except KeyboardInterrupt:
        pyperclip.copy("")
        print("\nInterrupted. Goodbye.")

def reveal_entry(entry: dict):
    print()
    print(f"Site: {entry['site']}")
    confirm = input("Press Enter to copy password to clipboard or 'n' to cancel: ").strip()

    if confirm.lower() == 'n':
        print("Cancelled.")
        return
    
    pyperclip.copy(entry["password"])
    print("Password copied to clipboard.")

def generate_password(length: int = 16) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%&*()-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(length))

def prompt_new_entry() -> dict:
    site = input("Site name: ").strip()
    password_choice = input("Generate a random password? (y/n): ").strip().lower()
    if password_choice == "y":
        password = generate_password()
        print("Password generated.")
    else:
        password = getpass("Password: ")

    return {
        "site": site,
        "password": password
    }

def save_vault(entries: list, password: str, salt: bytes, kdf_params: dict, path: str = "vault.json"):
    key = derive_key(
        password,
        salt,
        kdf_params["time_cost"],
        kdf_params["memory_cost"],
        kdf_params["parallelism"],
    )

    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)

    data = json.dumps({"entries": entries}).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, data, associated_data=None)

    vault_file = {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "kdf_params": kdf_params
    }

    with open(path, "w") as f:
        json.dump(vault_file, f, indent=2)

def add_entry(entries: list, password: str, salt: bytes, kdf_params: dict, path: str = "vault.json"):
    new_entry = prompt_new_entry()
    entries.append(new_entry)
    save_vault(entries, password, salt, kdf_params)
    print("Entry added and saved.")

def delete_entry(entries: list, password: str, salt: bytes, kdf_params: dict, path: str = "vault.json"):
    print_entries(entries)
    target = input("Enter the number to delete (or press Enter to cancel): ").strip()
    if target == "":
        print("Cancelled.")
        return
    
    if not target.isdigit():
        print("Invalid number.")
        return
    
    index = int(target) - 1
    if not (0 <= index < len(entries)):
        print("Invalid number.")
        return
    
    confirm = input(f"Delete '{entries[index]['site']}'? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("Cancelled.")
        return
    
    entries.pop(index)
    save_vault(entries, password, salt, kdf_params)
    print("Entry deleted and saved.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", nargs="?", default="unlock", choices=["init", "unlock"])
    args = parser.parse_args()

    if args.command == "init":
        init_vault()
    elif args.command == "unlock":
        unlocked = unlock_vault()
        if unlocked is not None:
            run_session(
                unlocked["entries"],
                unlocked["password"],
                unlocked["salt"],
                unlocked["kdf_params"],
            )
