"""Command-line interface module for the password manager.

This module provides the main CLI functionality for the password manager, including:
- Password generation and validation
- Adding and retrieving password entries
- Listing stored passwords
- RSA key pair generation

The module uses Rich for enhanced terminal output and implements a secure
password management system with encryption.
"""

import argparse
import os
import getpass
import secrets
import string
from typing import List, Tuple, Optional, Dict, Union, Any
from argparse import Namespace
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint
from .crypto import CryptoManager
from .storage import PasswordStore
from .password_validator import PasswordValidator

# Initialize Rich console for enhanced terminal output
console = Console()

def custom_confirm(prompt: str, default: bool = True) -> bool:
    """Display a custom confirmation prompt with Y/n format.

    Args:
        prompt: The message to display to the user
        default: The default response if user hits enter

    Returns:
        bool: True for yes/Y, False for no/N
    """
    choices = ["y", "Y", "n", "N", "", " ", "\n"]
    return Confirm.ask(
        f"{prompt} (Y/n)",
        default=default,
        choices=["y", "Y", "n", "N", ""].extend([" "]),
        show_choices=False
    )

def get_password() -> Tuple[Optional[str], bool]:
    """Handle password input or generation process.

    Provides two methods of password creation:
    1. Automatic generation of a strong password
    2. Manual password input with strength validation

    Returns:
        Tuple containing:
            - str | None: The password if successful, None if cancelled
            - bool: Success flag indicating if a valid password was obtained
    """
    validator = PasswordValidator()

    if custom_confirm("Would you like to generate a strong password?"):
        try:
            length = int(Prompt.ask("Enter password length", default="16"))
        except ValueError:
            length = 16

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task("Generating secure password...", total=None)
            chars = string.ascii_letters + string.digits + "!@#$%^&*"

            while True:
                password = ''.join(secrets.choice(chars) for _ in range(length))
                is_valid, _ = validator.validate_password(password)
                if is_valid:
                    break

        panel = Panel.fit(
            f"[bold green]{password}[/]",
            title="Generated Password",
            border_style="green"
        )
        console.print(panel)

        if custom_confirm("Use this password?"):
            return password, True
        return None, False

    while True:
        password = getpass.getpass("Enter your password: ")
        if getpass.getpass("Confirm your password: ") != password:
            console.print("[red]Error: Passwords do not match[/]")
            continue

        is_valid, issues = validator.validate_password(password)
        if not is_valid:
            console.print("\n[yellow]Password strength check failed:[/]")
            for issue in issues:
                console.print(f"[red]• {issue}[/]")

            score = validator.generate_password_score(password)
            console.print(f"\nPassword strength score: [bold]{score}[/]/100")

            if not custom_confirm("Do you want to continue anyway?"):
                continue
        return password, True

def add_password(args: Namespace) -> None:
    """Add a new password entry to the password store.

    Args:
        args: Parsed command line arguments containing:
            site (str): Website or application name
            username (str): Username for the account
            url (Optional[str]): Website URL
            tags (Optional[List[str]]): Tags for organization
            notes (Optional[str]): Additional notes

    Raises:
        ValueError: If password entry already exists
        OSError: If encryption or storage fails
    """
    crypto = CryptoManager()
    store = PasswordStore('passwords.json')

    while True:
        password, proceed = get_password()
        if not proceed:
            if not custom_confirm("Would you like to try again?"):
                return
            continue
        break

    # Check for duplicate passwords
    for stored_site, stored_data in store.passwords.items():
        if stored_data['password'] == crypto.encrypt_password(password):
            console.print(f"\n[yellow]Warning: This password is already used for {stored_site}[/]")
            if not custom_confirm("Do you want to continue?"):
                return

    # Encrypt and save the password
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task("Encrypting and saving password...", total=None)
        encrypted_password = crypto.encrypt_password(password)
        store.add_password(
            site=args.site,
            username=args.username,
            encrypted_password=encrypted_password,
            url=args.url or "",
            tags=args.tags or [],
            notes=args.notes or ""
        )

    console.print(f"\n[green]Password for {args.site} has been saved successfully.[/]")

def list_passwords(args: Namespace) -> None:
    """List all password entries, optionally filtered by tag.

    Args:
        args: Parsed command line arguments containing:
            tag (Optional[str]): Tag to filter entries by
    """
    store = PasswordStore('passwords.json')
    sites = store.search_by_tags([args.tag]) if args.tag else store.list_sites()

    if not sites:
        console.print("[yellow]No passwords stored yet[/]")
        return

    # Create and configure the display table
    table = Table(
        title=f"Password Entries{f' (filtered by tag: {args.tag})' if args.tag else ''}",
        show_header=True,
        header_style="bold magenta"
    )

    # Add table columns
    table.add_column("No.", style="cyan", justify="right")
    table.add_column("Site", style="cyan")
    table.add_column("URL", style="blue")
    table.add_column("Username", style="green")
    table.add_column("Tags", style="yellow")
    table.add_column("Modified", style="magenta")

    # Reset index mapping for consistent numbering
    store.clear_index_mapping()

    # Add entries to table
    for idx, site in enumerate(sorted(sites), 1):
        entry = store.get_password(site)
        store.add_index_mapping(str(idx), site)
        table.add_row(
            str(idx),
            site,
            entry['url'] or '-',
            entry['username'],
            ', '.join(entry['tags']) or '-',
            entry['modified_at'].split('T')[0]
        )

    console.print(table)
    console.print(f"\n[bold]Total entries:[/] {len(sites)}")
    store._save_passwords()

def get_password_entry(args: Namespace) -> None:
    """Retrieve and display a specific password entry.

    Args:
        args: Parsed command line arguments containing:
            site (str): Website/application name or index number

    Raises:
        ValueError: If password decryption fails
    """
    store = PasswordStore('passwords.json')
    crypto = CryptoManager()

    # Try to get site name from index mapping, fallback to direct site name
    site = store.get_site_by_index(args.site) or args.site

    entry = store.get_password(site)
    if entry:
        # Display password entry details
        table = Table(show_header=True, header_style="bold magenta", title=f"Password Entry: {site}")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Site", site)
        table.add_row("URL", entry['url'] or '-')
        table.add_row("Username", entry['username'])
        table.add_row("Tags", ', '.join(entry['tags']) or '-')
        table.add_row("Notes", entry['notes'] or '-')

        console.print(table)

        # Optionally show decrypted password
        if custom_confirm("Show password?"):
            try:
                decrypted_password = crypto.decrypt_password(entry['password'])
                panel = Panel.fit(
                    f"[bold red]{decrypted_password}[/]",
                    title="Password",
                    border_style="red"
                )
                console.print(panel)
            except Exception as e:
                console.print(f"[red]Error decrypting password: {str(e)}[/]")
    else:
        console.print(f"[red]No password found for {site}[/]")

def generate_keys(args: Namespace) -> None:
    """Generate new RSA key pair for password encryption.

    Args:
        args: Parsed command line arguments (unused)

    Raises:
        OSError: If key generation or saving fails
    """
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task("Generating new RSA key pair...", total=None)
        crypto = CryptoManager()
        crypto._generate_key_pair()

    console.print("\n[green]Key pair has been generated and saved in ~/.password_manager/[/]")
    console.print("[yellow]Please make sure to backup your private key![/]")

def main() -> int:
    """Main entry point for the CLI application.

    Sets up argument parsing and handles command execution.

    Returns:
        int: Exit code (0 for success, 1 for error)
    """
    parser = argparse.ArgumentParser(description="Secure Password Manager")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Set up command parsers
    generate_parser = subparsers.add_parser("generate-keys", help="Generate new RSA key pair")

    add_parser = subparsers.add_parser("add", help="Add a new password entry")
    add_parser.add_argument("site", help="Website or application name")
    add_parser.add_argument("username", help="Username")
    add_parser.add_argument("--url", "-u", help="Website URL")
    add_parser.add_argument("--tags", "-t", nargs="+", help="Tags for the password entry")
    add_parser.add_argument("--notes", "-n", help="Notes for the password entry")

    list_parser = subparsers.add_parser("list", help="List password entries")
    list_parser.add_argument("--tag", "-t", help="Filter by tag")

    get_parser = subparsers.add_parser("get", help="Get a password entry")
    get_parser.add_argument("site", help="Website or application name")

    args = parser.parse_args()

    try:
        if args.command == "generate-keys":
            generate_keys(args)
        elif args.command == "add":
            add_password(args)
        elif args.command == "list":
            list_passwords(args)
        elif args.command == "get":
            get_password_entry(args)
        else:
            parser.print_help()
            return 1
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/]")
        return 1
    return 0

if __name__ == "__main__":
    exit(main())