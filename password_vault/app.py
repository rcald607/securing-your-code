"""Command-line interface for the encrypted Password Vault."""

import getpass
import logging
import os
import sqlite3
from pathlib import Path

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


def _read_identity() -> tuple[str, str]:
    """Prompt for the service and username that identify an entry."""
    return input("Service: "), input("Username: ")


def _run_action(choice: str, vault: VaultOperations) -> bool:
    """Run one menu action and return whether the application should continue."""
    if choice == "1":
        service, username = _read_identity()
        password = getpass.getpass("Password (input hidden): ")
        vault.add_credential(service, username, password)
        print("Credential saved.")
        LOGGER.info("Added credential for service %s.", service.strip())
    elif choice == "2":
        entries = vault.list_credentials()
        if not entries:
            print("The vault is empty.")
        else:
            for entry in entries:
                print(f"- {entry.service}")
        LOGGER.info("Listed credential metadata.")
    elif choice == "3":
        service = input("Service name to retrieve: ").strip()
        username, password = vault.retrieve_password(service)
        print(f"Service: {service}")
        print(f"Username: {username}")
        print(f"Password: {password}")
        LOGGER.info("Retrieved credential for service %s.", service.strip())
    elif choice == "4":
        service = input("Service name to delete: ").strip()
        if not any(entry.service == service for entry in vault.list_credentials()):
            print("Service not found in vault.")
        elif input(f"Delete '{service}'? (y/n): ").strip().lower() != "y":
            print("Deletion cancelled.")
        elif vault.delete_credential(service):
            print("Credential deleted.")
            LOGGER.info("Deleted credential for service %s.", service.strip())
    elif choice == "5":
        length = int(input("Password length (12-128): "))
        generated = vault.generate_password(length)
        print(f"Generated password: {generated}")
        LOGGER.info("Generated a password.")
    elif choice == "6":
        password = getpass.getpass("Password to check (input hidden): ")
        print(f"Strength: {vault.check_password_strength(password)}")
        LOGGER.info("Checked password strength.")
    elif choice == "7":
        report_path = input("CSV report path: ").strip()
        vault.export_report(report_path)
        print(f"Metadata report exported to {report_path}.")
        LOGGER.info("Exported a metadata-only vault report.")
    elif choice == "8":
        print("Vault closed.")
        return False
    else:
        print("Choose a menu option from 1 to 8.")
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
