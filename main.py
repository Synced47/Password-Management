import json
import secrets
import base64
import os
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
        overwrite = input(f"{path} already exists. Overwrite and destroy it? (yes/no): ")
        if overwrite.lower() != "yes":
            print("Aborted.")
            return

    password = prompt_master_password()

    salt = secrets.token_bytes(16)
    time_cost = TIME_COST
    memory_cost = MEMORY_COST
    parallelism = PARALLELISM
    key = derive_key(password=password, salt=salt)

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
    
    entries = json.loads(plaintext)
    return entries
    
if __name__ == "__main__":
    # init_vault()
    result = unlock_vault()
    print(result)

