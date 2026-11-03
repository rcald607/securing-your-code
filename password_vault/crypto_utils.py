"""Password-based key derivation and Fernet encryption helpers."""

import base64
import hashlib
import hmac

from cryptography.fernet import Fernet, InvalidToken

PBKDF2_ITERATIONS = 600_000
SALT_LENGTH = 16
VERIFIER_CONTEXT = b"password-vault-master-password-verifier-v1"


def derive_key(
    master_password: str,
    salt: bytes,
    iterations: int = PBKDF2_ITERATIONS,
) -> bytes:
    """Derive a Fernet-compatible key from a master password and salt."""
    if not master_password.strip():
        raise ValueError("The master password must not be empty.")
    if len(salt) < SALT_LENGTH:
        raise ValueError(f"The salt must be at least {SALT_LENGTH} bytes.")
    if iterations < 1:
        raise ValueError("The iteration count must be positive.")

    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        master_password.encode("utf-8"),
        salt,
        iterations,
        dklen=32,
    )
    return base64.urlsafe_b64encode(derived_key)


def create_fernet(master_password: str, salt: bytes) -> Fernet:
    """Create a Fernet instance using the password-derived key."""
    return Fernet(derive_key(master_password, salt))


def create_key_verifier(master_password: str, salt: bytes) -> bytes:
    """Create a non-secret keyed verifier for the derived master key."""
    derived_key = derive_key(master_password, salt)
    return hmac.digest(derived_key, VERIFIER_CONTEXT, "sha256")


def verify_key_verifier(
    master_password: str,
    salt: bytes,
    stored_verifier: bytes,
) -> bool:
    """Compare a candidate master-key verifier in constant time."""
    candidate = create_key_verifier(master_password, salt)
    return hmac.compare_digest(candidate, stored_verifier)


def encrypt_secret(secret: str, cipher: Fernet) -> bytes:
    """Encrypt a non-empty secret and return its Fernet token."""
    if not secret:
        raise ValueError("The secret must not be empty.")
    return cipher.encrypt(secret.encode("utf-8"))


def decrypt_secret(token: bytes, cipher: Fernet) -> str:
    """Decrypt a Fernet token, raising a safe error for invalid tokens."""
    try:
        return cipher.decrypt(token).decode("utf-8")
    except InvalidToken as error:
        raise ValueError("Unable to decrypt the stored credential.") from error
