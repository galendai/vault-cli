"""Password validation and strength checking module.

This module provides functionality for:
- Password strength validation
- Common password checking
- Password scoring
- Keyboard pattern detection
"""

import re
import string
from typing import List, Tuple, Set, Optional
from pathlib import Path

class PasswordValidator:
    """Validates password strength and generates password scores."""

    def __init__(self) -> None:
        """Initialize the password validator with security rules.

        Loads common passwords and keyboard sequences for validation.
        Sets up regex patterns and scoring rules.
        """
        self.common_passwords: Set[str] = self._load_common_passwords()
        self.keyboard_sequences: List[str] = [
            'qwerty', 'asdfgh', 'zxcvbn', '123456', 'qwertz', 'azerty'
        ]

        # Scoring weights for different criteria
        self.length_weight: float = 0.3
        self.complexity_weight: float = 0.4
        self.pattern_weight: float = 0.3

        # Minimum requirements
        self.min_length: int = 12
        self.required_chars: dict = {
            'uppercase': r'[A-Z]',
            'lowercase': r'[a-z]',
            'numbers': r'\d',
            'special': r'[!@#$%^&*(),.?":{}|<>]'
        }

    def _load_common_passwords(self) -> Set[str]:
        """Load list of common passwords from file.

        Returns:
            Set[str]: Set of common passwords to check against

        Note:
            Falls back to an empty set if the file cannot be loaded
        """
        try:
            common_passwords_file = Path(__file__).parent / 'common_passwords.txt'
            with open(common_passwords_file, 'r') as f:
                return set(line.strip().lower() for line in f)
        except FileNotFoundError:
            return set()

    def validate_password(self, password: str) -> Tuple[bool, List[str]]:
        """Validate password against security requirements.

        Args:
            password: The password to validate

        Returns:
            Tuple containing:
                - bool: True if password meets all requirements
                - List[str]: List of validation issues found
        """
        issues: List[str] = []

        # Check length
        if len(password) < self.min_length:
            issues.append(f"Password must be at least {self.min_length} characters long")

        # Check complexity requirements
        for char_type, pattern in self.required_chars.items():
            if not re.search(pattern, password):
                issues.append(f"Password must contain at least one {char_type} character")

        # Check common passwords
        if password.lower() in self.common_passwords:
            issues.append("Password is too common")

        # Check keyboard sequences
        for sequence in self.keyboard_sequences:
            if sequence in password.lower():
                issues.append("Password contains common keyboard sequence")
                break

        # Check repeated characters
        if re.search(r'(.)\1{2,}', password):
            issues.append("Password contains too many repeated characters")

        # Check sequential characters
        if re.search(r'(0123|1234|2345|3456|4567|5678|6789)', password):
            issues.append("Password contains sequential numbers")

        return len(issues) == 0, issues

    def generate_password_score(self, password: str) -> int:
        """Generate a numerical score for password strength.

        Args:
            password: The password to score

        Returns:
            int: Password strength score (0-100)
        """
        score = 0

        # Length score (0-30)
        length_score = min(len(password) / self.min_length * 30, 30)
        score += length_score * self.length_weight

        # Complexity score (0-40)
        complexity_score = 0
        for pattern in self.required_chars.values():
            if re.search(pattern, password):
                complexity_score += 10
        score += complexity_score * self.complexity_weight

        # Pattern score (0-30)
        pattern_score = 30
        if password.lower() in self.common_passwords:
            pattern_score -= 15
        for sequence in self.keyboard_sequences:
            if sequence in password.lower():
                pattern_score -= 10
        if re.search(r'(.)\1{2,}', password):
            pattern_score -= 5
        if re.search(r'(0123|1234|2345|3456|4567|5678|6789)', password):
            pattern_score -= 5

        score += max(0, pattern_score) * self.pattern_weight

        return round(score)

    def suggest_improvements(self, password: str) -> List[str]:
        """Generate suggestions for improving password strength.

        Args:
            password: The password to analyze

        Returns:
            List[str]: List of improvement suggestions
        """
        suggestions: List[str] = []
        _, issues = self.validate_password(password)

        for issue in issues:
            if "length" in issue:
                suggestions.append("Add more characters to make the password longer")
            elif "uppercase" in issue:
                suggestions.append("Add uppercase letters (A-Z)")
            elif "lowercase" in issue:
                suggestions.append("Add lowercase letters (a-z)")
            elif "numbers" in issue:
                suggestions.append("Add numbers (0-9)")
            elif "special" in issue:
                suggestions.append("Add special characters (!@#$%^&*)")
            elif "common" in issue:
                suggestions.append("Choose a less common password")
            elif "keyboard sequence" in issue:
                suggestions.append("Avoid keyboard patterns like 'qwerty'")
            elif "repeated" in issue:
                suggestions.append("Avoid repeating characters")
            elif "sequential" in issue:
                suggestions.append("Avoid sequential numbers")

        return suggestions