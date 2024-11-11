"""Test module for password validation functionality."""

from typing import List, Tuple, Set
import pytest
from pathlib import Path

from vault_cli.password_validator import PasswordValidator

if TYPE_CHECKING:
    from _pytest.fixtures import FixtureRequest
    from pytest_mock.plugin import MockerFixture

@pytest.fixture
def validator() -> PasswordValidator:
    """Create a PasswordValidator instance for testing.

    Returns:
        PasswordValidator: Initialized password validator
    """
    return PasswordValidator()

@pytest.fixture
def common_passwords(tmp_path: Path) -> Path:
    """Create a temporary common passwords file.

    Args:
        tmp_path: Pytest temporary path fixture

    Returns:
        Path: Path to temporary common passwords file
    """
    passwords_file = tmp_path / "common_passwords.txt"
    passwords_file.write_text("\n".join([
        "password123",
        "admin123",
        "letmein",
        "welcome",
        "monkey123"
    ]))
    return passwords_file

class TestPasswordValidator:
    """Test cases for PasswordValidator class."""

    def test_password_length_validation(self, validator: PasswordValidator) -> None:
        """Test password length requirements.

        Args:
            validator: Initialized password validator
        """
        # Test too short password
        is_valid, issues = validator.validate_password("Short1!")
        assert not is_valid
        assert any("length" in issue.lower() for issue in issues)

        # Test minimum length password
        is_valid, issues = validator.validate_password("Abcd1234!@#$")
        assert is_valid
        assert not any("length" in issue.lower() for issue in issues)

    def test_password_complexity(self, validator: PasswordValidator) -> None:
        """Test password complexity requirements.

        Args:
            validator: Initialized password validator
        """
        test_cases = [
            ("lowercase123!", False, "uppercase"),
            ("UPPERCASE123!", False, "lowercase"),
            ("AbcdEFGHIJ!@#", False, "number"),
            ("Abcd1234", False, "special"),
            ("Abcd1234!@#$", True, None)
        ]

        for password, should_pass, missing in test_cases:
            is_valid, issues = validator.validate_password(password)
            assert is_valid == should_pass
            if not should_pass:
                assert any(missing in issue.lower() for issue in issues)

    def test_common_password_check(
        self,
        validator: PasswordValidator,
        common_passwords: Path,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test common password detection.

        Args:
            validator: Initialized password validator
            common_passwords: Path to test common passwords file
            monkeypatch: Pytest monkeypatch fixture
        """
        def mock_load_common_passwords() -> Set[str]:
            return {"password123", "admin123", "letmein"}

        monkeypatch.setattr(
            validator,
            '_load_common_passwords',
            mock_load_common_passwords
        )

        # Test common password
        is_valid, issues = validator.validate_password("Password123!")
        assert not is_valid
        assert any("common" in issue.lower() for issue in issues)

        # Test unique password
        is_valid, issues = validator.validate_password("UniquePass123!")
        assert is_valid
        assert not any("common" in issue.lower() for issue in issues)

    def test_keyboard_sequence_detection(self, validator: PasswordValidator) -> None:
        """Test keyboard pattern detection.

        Args:
            validator: Initialized password validator
        """
        sequences = [
            "qwerty",
            "asdfgh",
            "123456"
        ]

        for seq in sequences:
            password = f"Pass{seq}!"
            is_valid, issues = validator.validate_password(password)
            assert not is_valid
            assert any("keyboard sequence" in issue.lower() for issue in issues)

    def test_repeated_characters(self, validator: PasswordValidator) -> None:
        """Test repeated character detection.

        Args:
            validator: Initialized password validator
        """
        test_cases = [
            "Passwoooord123!",  # Three 'o's
            "Passworrrd123!",   # Three 'r's
            "Pass111word!",     # Three '1's
        ]

        for password in test_cases:
            is_valid, issues = validator.validate_password(password)
            assert not is_valid
            assert any("repeated" in issue.lower() for issue in issues)

    def test_sequential_numbers(self, validator: PasswordValidator) -> None:
        """Test sequential number detection.

        Args:
            validator: Initialized password validator
        """
        test_cases = [
            "Pass1234word!",
            "Pass3456word!",
            "Pass6789word!"
        ]

        for password in test_cases:
            is_valid, issues = validator.validate_password(password)
            assert not is_valid
            assert any("sequential" in issue.lower() for issue in issues)

    def test_password_scoring(self, validator: PasswordValidator) -> None:
        """Test password strength scoring.

        Args:
            validator: Initialized password validator
        """
        test_cases = [
            ("short", 0, 30),           # Very weak
            ("password123", 20, 50),    # Weak
            ("Password123", 40, 70),    # Medium
            ("Password123!", 60, 90),   # Strong
            ("P@ssw0rd!2#4", 80, 100)  # Very strong
        ]

        for password, min_score, max_score in test_cases:
            score = validator.generate_password_score(password)
            assert min_score <= score <= max_score

    def test_improvement_suggestions(self, validator: PasswordValidator) -> None:
        """Test password improvement suggestions.

        Args:
            validator: Initialized password validator
        """
        password = "pass"
        _, issues = validator.validate_password(password)
        suggestions = validator.suggest_improvements(password)

        assert len(suggestions) > 0
        assert any("longer" in sugg.lower() for sugg in suggestions)
        assert any("uppercase" in sugg.lower() for sugg in suggestions)
        assert any("numbers" in sugg.lower() for sugg in suggestions)
        assert any("special characters" in sugg.lower() for sugg in suggestions)

    def test_valid_password_examples(self, validator: PasswordValidator) -> None:
        """Test various valid password examples.

        Args:
            validator: Initialized password validator
        """
        valid_passwords = [
            "P@ssw0rd!2#4",
            "MySecureP@ss123",
            "C0mpl3x!P@ssw0rd",
            "Str0ng&P@ssphrase!",
            "N0t@CommonP@ss123"
        ]

        for password in valid_passwords:
            is_valid, issues = validator.validate_password(password)
            assert is_valid
            assert len(issues) == 0