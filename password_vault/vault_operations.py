"""Validated vault actions and secure password utilities."""

import secrets
import string
from pathlib import Path

from cryptography.fernet import Fernet

from crypto_utils import decrypt_secret, encrypt_secret
from storage import VaultEntry, VaultStorage

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128
MAX_FIELD_LENGTH = 200
MAX_STORED_PASSWORD_LENGTH = 4096


class VaultOperations:
    """Apply validation and encryption to user-facing vault operations."""

    def __init__(self, storage: VaultStorage, cipher: Fernet) -> None:
        """Bind operations to a database and its Fernet cipher."""
        self.storage = storage
        self.cipher = cipher

    def add_credential(self, service: str, username: str, password: str) -> None:
        """Validate and encrypt a credential before storing it."""
        clean_service = self._validate_field(service, "Service")
        clean_username = self._validate_field(username, "Username")
        if not password or len(password) > MAX_STORED_PASSWORD_LENGTH:
            raise ValueError(
                "The password must contain between 1 and "
                f"{MAX_STORED_PASSWORD_LENGTH} characters."
            )
        token = encrypt_secret(password, self.cipher)
        self.storage.add_credential(clean_service, clean_username, token)

    def list_credentials(self) -> list[VaultEntry]:
        """List service and username metadata without exposing secrets."""
        return self.storage.list_credentials()

    def retrieve_password(self, service: str) -> tuple[str, str]:
        """Decrypt and return the username and password for a service."""
        clean_service = self._validate_field(service, "Service")
        credential = self.storage.get_credential(clean_service)
        if credential is None:
            raise KeyError("No matching credential was found.")
        username, token = credential
        return username, decrypt_secret(token, self.cipher)

    def delete_credential(self, service: str) -> bool:
        """Delete a credential identified by its service."""
        clean_service = self._validate_field(service, "Service")
        return self.storage.delete_credential(clean_service)

    def export_report(self, report_path: str | Path) -> None:
        """Export a CSV inventory that excludes all stored passwords."""
        self.storage.export_report(report_path)

    @staticmethod
    def generate_password(
        length: int = 20,
        include_symbols: bool = True,
    ) -> str:
        """Generate a random password with at least one of each character type."""
        if not MIN_PASSWORD_LENGTH <= length <= MAX_PASSWORD_LENGTH:
            raise ValueError(
                f"Password length must be between {MIN_PASSWORD_LENGTH} "
                f"and {MAX_PASSWORD_LENGTH}."
            )

        character_groups = [
            string.ascii_lowercase,
            string.ascii_uppercase,
            string.digits,
        ]
        if include_symbols:
            character_groups.append(string.punctuation)

        password_characters = [secrets.choice(group) for group in character_groups]
        all_characters = "".join(character_groups)
        password_characters.extend(
            secrets.choice(all_characters)
            for _ in range(length - len(password_characters))
        )
        secrets.SystemRandom().shuffle(password_characters)
        return "".join(password_characters)

    @staticmethod
    def check_password_strength(password: str) -> str:
        """Classify a password using length and character diversity."""
        if not password:
            return "Weak"

        score = sum(
            (
                len(password) >= 12,
                any(character.islower() for character in password),
                any(character.isupper() for character in password),
                any(character.isdigit() for character in password),
                any(not character.isalnum() for character in password),
            )
        )
        if score >= 5:
            return "Strong"
        if score >= 3:
            return "Moderate"
        return "Weak"

    @staticmethod
    def _validate_field(value: str, field_name: str) -> str:
        """Trim and validate a service or username field."""
        clean_value = value.strip()
        if not clean_value or len(clean_value) > MAX_FIELD_LENGTH:
            raise ValueError(
                f"{field_name} must contain between 1 and "
                f"{MAX_FIELD_LENGTH} characters."
            )
        if any(character in clean_value for character in "\r\n\x00"):
            raise ValueError(f"{field_name} contains an unsupported character.")
        return clean_value
