"""Command-line interface for the encrypted Password Vault."""

import getpass
import logging
import os
import sqlite3
from pathlib import Path
from typing import Callable

from crypto_utils import create_fernet, create_key_verifier
from logger_config import configure_logging
from storage import VaultStorage
from vault_operations import VaultOperations

LOGGER = logging.getLogger("password_vault")


def _show_menu() -> None:
    """Print the available vault actions."""
    print(
        "\nPassword Vault\n"
        "1. Add password entry\n"
        "2. List stored services\n"
        "3. Retrieve credential\n"
        "4. Delete credential\n"
        "5. Generate secure password\n"
        "6. Check password strength\n"
        "7. Export vault report\n"
        "8. Exit"
    )


def _add_entry(vault: VaultOperations) -> None:
    """Prompt for and store a new service credential."""
    service = input("Service: ")
    username = input("Username: ")
    password = getpass.getpass("Password (input hidden): ")
    vault.add_credential(service, username, password)
    print("Credential saved.")
    LOGGER.info("Added credential for service %s.", service.strip())


def _list_entries(vault: VaultOperations) -> None:
    """List stored service names without exposing credentials."""
    entries = vault.list_credentials()
    if not entries:
        print("The vault is empty.")
    else:
        for entry in entries:
            print(f"- {entry.service}")
    LOGGER.info("Listed credential metadata.")


def _retrieve_entry(vault: VaultOperations) -> None:
    """Retrieve and display a service's username and password."""
    service = input("Service name to retrieve: ").strip()
    username, password = vault.retrieve_password(service)
    print(f"Service: {service}")
    print(f"Username: {username}")
    print(f"Password: {password}")
    LOGGER.info("Retrieved credential for service %s.", service)


def _delete_entry(vault: VaultOperations) -> None:
    """Confirm and delete a service credential."""
    service = input("Service name to delete: ").strip()
    if not any(entry.service == service for entry in vault.list_credentials()):
        print("Service not found in vault.")
        return
    confirmation = input(f"Delete '{service}'? (y/n): ").strip().lower()
    if confirmation != "y":
        print("Deletion cancelled.")
        return
    if vault.delete_credential(service):
        print("Credential deleted.")
        LOGGER.info("Deleted credential for service %s.", service)


def _generate_password(vault: VaultOperations) -> None:
    """Generate and display a secure password."""
    length = int(input("Password length (12-128): "))
    generated = vault.generate_password(length)
    print(f"Generated password: {generated}")
    LOGGER.info("Generated a password.")


def _check_strength(vault: VaultOperations) -> None:
    """Check password strength without echoing the entered value."""
    password = getpass.getpass("Password to check (input hidden): ")
    print(f"Strength: {vault.check_password_strength(password)}")
    LOGGER.info("Checked password strength.")


def _export_report(vault: VaultOperations) -> None:
    """Export a CSV inventory containing metadata only."""
    report_path = input("CSV report path: ").strip()
    vault.export_report(report_path)
    print(f"Metadata report exported to {report_path}.")
    LOGGER.info("Exported a metadata-only vault report.")


def _run_action(choice: str, vault: VaultOperations) -> bool:
    """Run a menu action and return whether the application should continue."""
    actions: dict[str, Callable[[VaultOperations], None]] = {
        "1": _add_entry,
        "2": _list_entries,
        "3": _retrieve_entry,
        "4": _delete_entry,
        "5": _generate_password,
        "6": _check_strength,
        "7": _export_report,
    }
    if choice == "8":
        print("Vault closed.")
        return False
    action = actions.get(choice)
    if action is None:
        print("Choose a menu option from 1 to 8.")
        return True
    action(vault)
    return True


def main() -> int:
    """Initialize the vault from environment configuration and run the menu."""
    app_directory = Path(__file__).resolve().parent
    logger = configure_logging(app_directory / "vault.log")
    logger.info("Password vault application started.")
    master_password = os.environ.get("VAULT_MASTER_PASSWORD")
    if master_password is None or not master_password.strip():
        logger.error("Set VAULT_MASTER_PASSWORD before starting the vault.")
        return 1

    database_path = os.environ.get("VAULT_DB_PATH")
    if database_path is None:
        database_path = app_directory / "vault.db"
    try:
        storage = VaultStorage(database_path)
        salt = storage.get_or_create_salt()
        cipher = create_fernet(master_password, salt)
        storage.ensure_master_password(
            create_key_verifier(master_password, salt),
            cipher,
        )
    except (OSError, sqlite3.Error, ValueError) as error:
        logger.error("Unable to initialize the vault: %s", error)
        return 1

    vault = VaultOperations(storage, cipher)
    print("Vault ready. Password values are encrypted in the SQLite database.")
    while True:
        _show_menu()
        choice = input("Select an option: ").strip()
        try:
            if not _run_action(choice, vault):
                logger.info("Password vault application exited.")
                break
        except (ValueError, KeyError, OSError, sqlite3.Error) as error:
            logger.warning("Vault operation failed: %s", error)
            print(f"Operation failed: {error}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
