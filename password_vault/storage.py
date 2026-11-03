"""SQLite persistence for encrypted vault credentials and KDF metadata."""

import csv
import hmac
import secrets
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

from cryptography.fernet import Fernet

from crypto_utils import SALT_LENGTH, decrypt_secret


@dataclass(frozen=True)
# A value object intentionally exposes fields rather than behavior.
# pylint: disable=too-few-public-methods
class VaultEntry:
    """Non-secret metadata describing a stored credential."""

    service: str
    username: str
    created_at: str


class VaultStorage:
    """Manage a SQLite database containing encrypted credentials."""

    def __init__(self, database_path: str | Path) -> None:
        """Create the database schema if it does not already exist."""
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _initialize(self) -> None:
        """Create tables used for credentials and vault metadata."""
        with closing(sqlite3.connect(self.database_path)) as connection:
            with connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS vault_metadata (
                        key TEXT PRIMARY KEY,
                        value BLOB NOT NULL
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS credentials (
                        id INTEGER PRIMARY KEY,
                        service TEXT NOT NULL,
                        username TEXT NOT NULL,
                        password_token BLOB NOT NULL,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE (service)
                    )
                    """
                )

    def ensure_master_password(self, verifier: bytes, cipher: Fernet) -> None:
        """Verify or initialize the master key without modifying credentials."""
        with closing(sqlite3.connect(self.database_path)) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                stored = connection.execute(
                    "SELECT value FROM vault_metadata WHERE key = ?",
                    ("key_verifier",),
                ).fetchone()
                if stored is not None:
                    if not hmac.compare_digest(bytes(stored[0]), verifier):
                        raise ValueError("The master password does not match this vault.")
                else:
                    tokens = connection.execute(
                        "SELECT password_token FROM credentials"
                    ).fetchall()
                    try:
                        for row in tokens:
                            decrypt_secret(bytes(row[0]), cipher)
                    except ValueError as error:
                        raise ValueError(
                            "The master password does not match this vault."
                        ) from error

                    connection.execute(
                        "INSERT INTO vault_metadata (key, value) VALUES (?, ?)",
                        ("key_verifier", verifier),
                    )
                connection.commit()
            except (sqlite3.Error, ValueError):
                connection.rollback()
                raise

    def get_or_create_salt(self) -> bytes:
        """Read the persistent KDF salt, creating it for a new vault."""
        with closing(sqlite3.connect(self.database_path)) as connection:
            with connection:
                result = connection.execute(
                    "SELECT value FROM vault_metadata WHERE key = ?",
                    ("kdf_salt",),
                ).fetchone()
                if result is not None:
                    salt = bytes(result[0])
                    if len(salt) < SALT_LENGTH:
                        raise ValueError("The vault contains an invalid KDF salt.")
                    return salt

                salt = secrets.token_bytes(SALT_LENGTH)
                connection.execute(
                    "INSERT INTO vault_metadata (key, value) VALUES (?, ?)",
                    ("kdf_salt", salt),
                )
                return salt

    def add_credential(
        self,
        service: str,
        username: str,
        password_token: bytes,
    ) -> None:
        """Store an encrypted credential for a service and username."""
        with closing(sqlite3.connect(self.database_path)) as connection:
            with connection:
                connection.execute(
                    """
                    INSERT INTO credentials (service, username, password_token)
                    VALUES (?, ?, ?)
                    """,
                    (service, username, password_token),
                )

    def list_credentials(self) -> list[VaultEntry]:
        """Return credential metadata without retrieving password tokens."""
        with closing(sqlite3.connect(self.database_path)) as connection:
            rows = connection.execute(
                """
                SELECT service, username, created_at
                FROM credentials
                ORDER BY service COLLATE NOCASE, username COLLATE NOCASE
                """
            ).fetchall()
        return [VaultEntry(*row) for row in rows]

    def get_credential(self, service: str) -> tuple[str, bytes] | None:
        """Return a service's username and encrypted token, if it exists."""
        with closing(sqlite3.connect(self.database_path)) as connection:
            row = connection.execute(
                """
                SELECT username, password_token FROM credentials
                WHERE service = ?
                """,
                (service,),
            ).fetchone()
        return (str(row[0]), bytes(row[1])) if row is not None else None

    def delete_credential(self, service: str) -> bool:
        """Delete a service credential and report whether it existed."""
        with closing(sqlite3.connect(self.database_path)) as connection:
            with connection:
                cursor = connection.execute(
                    """
                    DELETE FROM credentials
                    WHERE service = ?
                    """,
                    (service,),
                )
                return cursor.rowcount > 0

    def export_report(self, report_path: str | Path) -> None:
        """Write a CSV report containing metadata, never password values."""
        with Path(report_path).open("w", encoding="utf-8", newline="") as report:
            writer = csv.writer(report)
            writer.writerow(("service", "username", "created_at"))
            for entry in self.list_credentials():
                writer.writerow((entry.service, entry.username, entry.created_at))
