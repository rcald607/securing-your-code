"""Tests for password-based key derivation and Fernet encryption."""

import pytest

from crypto_utils import (
    SALT_LENGTH,
    create_fernet,
    create_key_verifier,
    decrypt_secret,
    derive_key,
    encrypt_secret,
    verify_key_verifier,
)


def test_key_derivation_is_deterministic_for_same_password_and_salt() -> None:
    """The same password and salt must produce the same key."""
    salt = b"s" * SALT_LENGTH

    assert derive_key("correct horse battery staple", salt) == derive_key(  # nosec B101
        "correct horse battery staple",
        salt,
    )


def test_different_salts_produce_different_keys() -> None:
    """Independent vault salts must derive independent keys."""
    assert derive_key("master password", b"a" * SALT_LENGTH) != derive_key(  # nosec B101
        "master password",
        b"b" * SALT_LENGTH,
    )


def test_key_verifier_accepts_only_the_matching_master_password() -> None:
    """The persisted verifier distinguishes passwords without storing them."""
    salt = b"x" * SALT_LENGTH
    verifier = create_key_verifier("correct master password", salt)

    assert verifier != b"correct master password"  # nosec B101
    assert verify_key_verifier("correct master password", salt, verifier)  # nosec B101
    assert not verify_key_verifier("wrong master password", salt, verifier)  # nosec B101


def test_fernet_encryption_round_trips() -> None:
    """A stored password can be encrypted and recovered."""
    cipher = create_fernet("master password", b"x" * SALT_LENGTH)

    encrypted = encrypt_secret("example password", cipher)

    assert encrypted != b"example password"  # nosec B101
    assert decrypt_secret(encrypted, cipher) == "example password"  # nosec B101


def test_wrong_master_password_cannot_decrypt_token() -> None:
    """A different master password must not decrypt an existing token."""
    salt = b"x" * SALT_LENGTH
    token = encrypt_secret("example password", create_fernet("first", salt))

    with pytest.raises(ValueError, match="Unable to decrypt"):
        decrypt_secret(token, create_fernet("second", salt))


@pytest.mark.parametrize(
    ("password", "salt", "iterations"),
    [
        ("", b"x" * SALT_LENGTH, 10),
        (" ", b"x" * SALT_LENGTH, 10),
        ("valid", b"short", 10),
        ("valid", b"x" * SALT_LENGTH, 0),
    ],
)
def test_key_derivation_rejects_invalid_input(
    password: str,
    salt: bytes,
    iterations: int,
) -> None:
    """Invalid master passwords, salts, and iteration counts are rejected."""
    with pytest.raises(ValueError):
        derive_key(password, salt, iterations)
