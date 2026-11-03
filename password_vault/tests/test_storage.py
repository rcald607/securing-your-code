"""Tests for SQLite vault storage and metadata-only reports."""

import sqlite3
from pathlib import Path

import pytest

from crypto_utils import (
    SALT_LENGTH,
    create_fernet,
    create_key_verifier,
    encrypt_secret,
)
from storage import VaultStorage
from vault_operations import VaultOperations


def test_storage_persists_salt_and_encrypted_credential(tmp_path: Path) -> None:
    """The salt is stable and only encrypted password bytes are persisted."""
    storage = VaultStorage(tmp_path / "vault.db")
    salt = storage.get_or_create_salt()
    cipher = create_fernet("master password", salt)
    encrypted = encrypt_secret("never stored as plaintext", cipher)

    storage.add_credential("Example", "alice", encrypted)

    assert len(salt) == SALT_LENGTH  # nosec B101
    assert storage.get_or_create_salt() == salt  # nosec B101
    assert storage.get_credential("Example") == ("alice", encrypted)  # nosec B101
    assert b"never stored as plaintext" not in encrypted  # nosec B101
    assert storage.list_credentials()[0].service == "Example"  # nosec B101


def test_duplicate_service_is_rejected(tmp_path: Path) -> None:
    """A service cannot be added twice, matching the original vault behavior."""
    storage = VaultStorage(tmp_path / "vault.db")
    encrypted = b"encrypted"
    storage.add_credential("Example", "bob", encrypted)

    with pytest.raises(sqlite3.IntegrityError):
        storage.add_credential("Example", "alice", encrypted)


def test_delete_credential_reports_whether_entry_existed(tmp_path: Path) -> None:
    """Delete returns true once and false after the entry is gone."""
    storage = VaultStorage(tmp_path / "vault.db")
    storage.add_credential("Example", "alice", b"encrypted")

    assert storage.delete_credential("Example") is True  # nosec B101
    assert storage.delete_credential("Example") is False  # nosec B101


def test_export_report_never_contains_password(tmp_path: Path) -> None:
    """The CSV report includes metadata but excludes decrypted credentials."""
    storage = VaultStorage(tmp_path / "vault.db")
    vault = VaultOperations(
        storage,
        create_fernet("master password", storage.get_or_create_salt()),
    )
    vault.add_credential("Example", "alice", "hidden credential")
    report_path = tmp_path / "report.csv"

    vault.export_report(report_path)

    report = report_path.read_text(encoding="utf-8")
    assert "Example" in report  # nosec B101
    assert "alice" in report  # nosec B101
    assert "hidden credential" not in report  # nosec B101


def test_validation_rejects_empty_service(tmp_path: Path) -> None:
    """Service names must not be empty."""
    storage = VaultStorage(tmp_path / "vault.db")
    vault = VaultOperations(
        storage,
        create_fernet("master password", storage.get_or_create_salt()),
    )

    with pytest.raises(ValueError, match="Service"):
        vault.add_credential(" ", "alice", "password")


def test_retrieve_credential_is_selected_by_service(tmp_path: Path) -> None:
    """Retrieval returns the original username and decrypted password."""
    storage = VaultStorage(tmp_path / "vault.db")
    vault = VaultOperations(
        storage,
        create_fernet("master password", storage.get_or_create_salt()),
    )
    vault.add_credential("Example", "alice", "private value")

    assert vault.retrieve_password("Example") == ("alice", "private value")  # nosec B101


def test_new_empty_vault_initializes_master_password(tmp_path: Path) -> None:
    """A newly initialized empty vault stores its first key verifier."""
    storage = VaultStorage(tmp_path / "vault.db")
    salt = storage.get_or_create_salt()
    cipher = create_fernet("correct master password", salt)

    storage.ensure_master_password(
        create_key_verifier("correct master password", salt),
        cipher,
    )
    storage.ensure_master_password(
        create_key_verifier("correct master password", salt),
        cipher,
    )


def test_wrong_master_password_is_rejected_without_changing_credentials(
    tmp_path: Path,
) -> None:
    """A wrong master password cannot alter an initialized vault's entries."""
    storage = VaultStorage(tmp_path / "vault.db")
    salt = storage.get_or_create_salt()
    correct_cipher = create_fernet("correct master password", salt)
    storage.ensure_master_password(
        create_key_verifier("correct master password", salt),
        correct_cipher,
    )
    token = encrypt_secret("unchanged credential", correct_cipher)
    storage.add_credential("Example", "alice", token)
    entries_before = storage.list_credentials()
    credential_before = storage.get_credential("Example")

    with pytest.raises(ValueError, match="does not match"):
        storage.ensure_master_password(
            create_key_verifier("wrong master password", salt),
            create_fernet("wrong master password", salt),
        )

    assert storage.list_credentials() == entries_before  # nosec B101
    assert storage.get_credential("Example") == credential_before  # nosec B101


def test_legacy_populated_vault_migrates_only_with_correct_key(
    tmp_path: Path,
) -> None:
    """A legacy vault without a verifier validates all tokens before migration."""
    storage = VaultStorage(tmp_path / "vault.db")
    salt = storage.get_or_create_salt()
    correct_cipher = create_fernet("correct master password", salt)
    storage.add_credential(
        "Example",
        "alice",
        encrypt_secret("legacy credential", correct_cipher),
    )
    entries_before = storage.list_credentials()
    credential_before = storage.get_credential("Example")

    with pytest.raises(ValueError, match="does not match"):
        storage.ensure_master_password(
            create_key_verifier("wrong master password", salt),
            create_fernet("wrong master password", salt),
        )

    assert storage.list_credentials() == entries_before  # nosec B101
    assert storage.get_credential("Example") == credential_before  # nosec B101

    storage.ensure_master_password(
        create_key_verifier("correct master password", salt),
        correct_cipher,
    )
