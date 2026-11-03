"""Tests for secure password generation and strength classification."""

import string

import pytest

from vault_operations import VaultOperations


def test_generated_password_has_required_character_groups() -> None:
    """Generated passwords include lower, upper, digit, and symbol values."""
    password = VaultOperations.generate_password(24)

    assert len(password) == 24  # nosec B101
    assert any(character in string.ascii_lowercase for character in password)  # nosec B101
    assert any(character in string.ascii_uppercase for character in password)  # nosec B101
    assert any(character in string.digits for character in password)  # nosec B101
    assert any(character in string.punctuation for character in password)  # nosec B101


def test_generated_password_can_exclude_symbols() -> None:
    """Symbol-free generated passwords contain only letters and digits."""
    password = VaultOperations.generate_password(16, include_symbols=False)

    assert len(password) == 16  # nosec B101
    assert password.isalnum()  # nosec B101


@pytest.mark.parametrize("length", [0, 11, 129])
def test_generator_rejects_unsafe_length(length: int) -> None:
    """The password generator enforces its supported length range."""
    with pytest.raises(ValueError, match="Password length"):
        VaultOperations.generate_password(length)


def test_password_strength_classification() -> None:
    """Strength checking distinguishes weak, moderate, and strong values."""
    assert VaultOperations.check_password_strength("abc") == "Weak"  # nosec B101
    assert VaultOperations.check_password_strength("Mixedcase12") == "Moderate"  # nosec B101
    assert VaultOperations.check_password_strength("StrongExample42!") == "Strong"  # nosec B101
