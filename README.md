# Local Password Manager

A secure command-line password manager that stores encrypted passwords locally using RSA encryption.

## Features

- Strong password encryption using RSA public/private key pairs
- Local storage with no database dependencies
- Password strength validation
- Password generation
- Tag-based organization
- Beautiful terminal UI
- Cross-platform support (Windows/Linux/Mac)

## Installation

You can install vault-cli directly from PyPI:

```bash
pip install vault-cli
```

Or install from source:

```bash
git clone https://github.com/yourusername/vault-cli.git
cd vault-cli
pip install -e .
```

## Usage

### Generating Keys

首先需要生成密钥对：

```bash
python -m password_manager generate-keys
```

### Adding a Password

```bash
python -m password_manager add github.com username123 --url https://github.com --tags work dev --notes "Work account"
```

Options:
- `--url` or `-u`: Website URL
- `--tags` or `-t`: Tags for organization (multiple allowed)
- `--notes` or `-n`: Additional notes

When adding a password, you will be prompted to either:
- Generate a strong password (recommended)
- Enter your own password (will be validated)

### Listing Passwords

List all passwords:
```bash
python -m password_manager list
```

Filter by tag:
```bash
python -m password_manager list --tag work
```

### Getting Password Details

```bash
python -m password_manager get github.com
```

## Security Features

### Password Storage
- Passwords are encrypted using RSA-2048 with OAEP padding
- Private/public key pair is generated on first run
- Keys are stored in `~/.password_manager/`
- File permissions are set to restrict access (Unix systems)

### Password Requirements
- Minimum length: 12 characters
- Must contain:
  - Uppercase letters
  - Lowercase letters
  - Numbers
  - Special characters
- Checked against common password patterns
- Prevents password reuse across sites

### File Structure

```
~/.password_manager/
├── private.pem  (600 permissions - owner read/write only)
└── public.pem   (644 permissions - owner read/write, others read)

./
└── passwords.json  (600 permissions - owner read/write only)
```

## Data Format

The password data is stored in JSON format:

```json
{
    "site.com": {
        "username": "user123",
        "password": "<encrypted>",
        "url": "https://site.com",
        "tags": ["work", "personal"],
        "notes": "Account notes",
        "created_at": "2024-03-15T10:30:45.123456",
        "modified_at": "2024-03-15T10:30:45.123456"
    }
}
```

## Command Reference

| Command | Description | Options |
|---------|-------------|---------|
| `generate-keys` | Generate new RSA key pair | None |
| `add` | Add new password | `site username [--url URL] [--tags TAG...] [--notes NOTES]` |
| `list` | List passwords | `[--tag TAG]` |
| `get` | Get password details | `site` |

## Security Considerations

1. **Key Management**:
   - Private key is stored in `~/.password_manager/private.pem`
   - Back up your private key - losing it means losing access to all passwords
   - Keep your private key secure - anyone with access can decrypt your passwords

2. **Password File Security**:
   - Passwords are stored in encrypted form
   - File permissions restrict access to owner only
   - Even if the file is compromised, passwords cannot be decrypted without the private key

3. **System Requirements**:
   - File permission security works best on Unix-like systems
   - Windows users should ensure directory security through Windows permissions

## Backup Instructions

To backup your password manager:

1. Backup your keys:
```bash
cp -r ~/.password_manager /your/backup/location
```

2. Backup your password file:
```bash
cp passwords.json /your/backup/location
```

IMPORTANT: Store backups securely! The private key can decrypt all passwords.

## Development

The project structure:
```
password-manager/
├─ src/
│   ├── __init__.py
│   ├── crypto.py      # Encryption functionality
│   ├── storage.py     # Password storage
│   ├── main.py        # CLI interface
│   └── password_validator.py  # Password validation
├── README.md
└── passwords.json
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Testing

To run the tests:

1. Install test dependencies:
```bash
pip install pytest
```

2. Run the tests:
```bash
pytest tests/
```