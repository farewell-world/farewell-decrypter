#!/usr/bin/env python3
"""
Farewell Message Decrypter
==========================

A standalone tool for recipients to decrypt Farewell messages.

The Farewell protocol splits the AES decryption key into two halves:
  - s  (skShare) — stored on-chain via FHE, included in the claim package
  - s' — shared off-chain with the recipient

After a claimer retrieves and sends the message, the recipient uses this
tool to combine both halves and decrypt the payload.

Requirements:
    pip install colorama cryptography

Usage:
    python farewell_decrypter.py message.json
    python farewell_decrypter.py -f message.json
    python farewell_decrypter.py message.json -o decrypted.txt

Author: Farewell Protocol
License: BSD 3-Clause
"""

import os
import sys
import json
import argparse
from pathlib import Path
from typing import Optional, Dict

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    print("Please install colorama: pip install colorama")
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("Please install cryptography: pip install cryptography")
    sys.exit(1)

import hashlib


# ============ UI Helpers ============

def print_banner():
    """Print the Farewell banner with logo."""
    banner = f"""
{Fore.CYAN}                        ╭──────╮
                    ╭───╯      ╰───╮
                ╭───╯      {Fore.WHITE}│{Fore.CYAN}       ╰───╮
            ╭───╯          {Fore.WHITE}│{Fore.CYAN}           ╰───╮
          ╭─╯            {Fore.WHITE}╭─┴─╮{Fore.CYAN}             ╰─╮
        ╭─╯              {Fore.WHITE}│   │{Fore.CYAN}               ╰─╮
       ╭╯                {Fore.WHITE}│   │{Fore.CYAN}                 ╰╮
      ╭╯                 {Fore.WHITE}│   │{Fore.CYAN}                  ╰╮
      │                  {Fore.WHITE}╰───╯{Fore.CYAN}                   │
      │                                          │
      │      {Fore.WHITE}F A R E W E L L{Fore.CYAN}                    │
      │                                          │
      ╰╮                                        ╭╯
       ╰╮       {Fore.YELLOW}Message Decrypter{Fore.CYAN}             ╭╯
        ╰─╮                              ╭─╯
          ╰─╮                          ╭─╯
            ╰───╮                  ╭───╯
                ╰───╮          ╭───╯
                    ╰───╮  ╭───╯
                        ╰──╯
{Style.RESET_ALL}"""
    print(banner)


def print_section(title: str):
    """Print a section header."""
    print(f"\n{Fore.CYAN}{'─' * 60}")
    print(f"{Fore.CYAN}  {title}")
    print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}\n")


def print_success(msg: str):
    """Print success message."""
    print(f"{Fore.GREEN}✓ {msg}{Style.RESET_ALL}")


def print_error(msg: str):
    """Print error message."""
    print(f"{Fore.RED}✗ {msg}{Style.RESET_ALL}")


def print_info(msg: str):
    """Print info message."""
    print(f"{Fore.BLUE}ℹ {msg}{Style.RESET_ALL}")


def prompt(msg: str, default: str = "") -> str:
    """Prompt user for input."""
    if default:
        result = input(f"{Fore.WHITE}{msg} [{Fore.CYAN}{default}{Fore.WHITE}]: {Style.RESET_ALL}")
        return result if result else default
    return input(f"{Fore.WHITE}{msg}: {Style.RESET_ALL}")


def confirm(msg: str, default: bool = True) -> bool:
    """Ask for confirmation."""
    suffix = "[Y/n]" if default else "[y/N]"
    result = prompt(f"{msg} {suffix}").lower()
    if not result:
        return default
    return result in ('y', 'yes')


# ============ Key Derivation ============

def passphrase_to_s_prime(passphrase: str) -> str:
    """SHAKE128(passphrase) → 128 bits → hex string with 0x prefix."""
    h = hashlib.shake_128(passphrase.encode('utf-8'))
    return '0x' + h.hexdigest(16)  # 16 bytes = 128 bits


# ============ Decryption ============

def _parse_int(value: str) -> int:
    """Parse an integer from hex (0x-prefixed or a-f digits) or decimal string."""
    if value.startswith('0x') or value.startswith('0X'):
        return int(value, 16)
    if value.isdigit():
        return int(value, 10)
    return int(value, 16)


def decrypt_aes_gcm_packed(encrypted_hex: str, sk_share_str: str, s_prime_str: str) -> Optional[str]:
    """
    Decrypt AES-128-GCM packed payload using skShare XOR s'.

    Packed format (from lib/aes.ts): 0x + IV(12 bytes) + ciphertext(with GCM tag)
    Key derivation: sk = skShare XOR s' (128-bit), converted to 16-byte big-endian.

    skShare may be decimal (from BigInt.toString()) or hex (with/without 0x prefix).
    """
    # Strip 0x prefix for encrypted payload (always hex)
    encrypted = encrypted_hex[2:] if encrypted_hex.startswith('0x') else encrypted_hex

    # Compute sk = skShare XOR s' (as 128-bit integers)
    # skShare may be decimal or hex; s' is typically hex
    sk_int = _parse_int(sk_share_str.strip()) ^ _parse_int(s_prime_str.strip())

    # Convert to 16-byte key (big-endian, matching lib/aes.ts bigintToKey16)
    key = sk_int.to_bytes(16, byteorder='big')

    # Parse packed payload: first 12 bytes = IV, rest = ciphertext + GCM tag
    data = bytes.fromhex(encrypted)
    if len(data) < 28:  # 12 (IV) + 16 (min GCM tag)
        print_error("Encrypted payload too short (missing IV or GCM tag)")
        return None

    iv = data[:12]
    ciphertext_and_tag = data[12:]

    try:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(iv, ciphertext_and_tag, None)
        return plaintext.decode('utf-8')
    except Exception as e:
        print_error(f"AES-GCM decryption failed: {e}")
        print_info("This usually means the s' value is incorrect.")
        return None


# ============ File Loading ============

def load_claim_package(filepath: str) -> Optional[Dict]:
    """
    Load and validate a claim package JSON file.

    Supports the claim package format exported from the Farewell UI:
    {
        "type": "farewell-claim-package",
        "recipients": ["email@example.com"],
        "skShare": "0x...",
        "encryptedPayload": "0x...",
        "contentHash": "0x...",
        "subject": "..."
    }

    Also supports a simpler format with just skShare and encryptedPayload.
    """
    path = Path(filepath)
    if not path.exists():
        print_error(f"File not found: {filepath}")
        return None

    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print_error(f"Invalid JSON: {e}")
        return None

    # Validate required fields
    required = ['skShare', 'encryptedPayload']
    for field in required:
        if field not in data:
            print_error(f"Missing required field: '{field}'")
            return None

    return data


# ============ Main Flow ============

def main_flow(filepath: str, output_path: Optional[str] = None):
    """Orchestrate the decryption workflow."""
    print_banner()
    print_section("Loading Claim Package")

    data = load_claim_package(filepath)
    if data is None:
        return

    print_success(f"Loaded: {filepath}")

    # Show metadata
    if data.get('owner'):
        print_info(f"  Owner: {data['owner']}")
    if data.get('messageIndex') is not None:
        print_info(f"  Message index: {data['messageIndex']}")
    if data.get('recipients'):
        recipients = data['recipients']
        if isinstance(recipients, str):
            recipients = [r.strip() for r in recipients.split(',') if r.strip()]
        print_info(f"  Recipients: {', '.join(recipients)}")
    if data.get('subject'):
        print_info(f"  Subject: {data['subject']}")
    if data.get('contentHash'):
        content_hash = data['contentHash']
        print_info(f"  Content hash: {content_hash[:20]}...")

    # Determine key derivation mode from cryptoScheme
    crypto_scheme = data.get('cryptoScheme', '')
    passphrase_hint = data.get('passphraseHint', '')
    use_passphrase = ';' in crypto_scheme and 'SHAKE128' in crypto_scheme

    if crypto_scheme:
        print_info(f"  Crypto scheme: {crypto_scheme}")

    # Ask for s'
    print_section("AES Decryption")
    print_info("This claim package contains an encrypted message.")

    if use_passphrase:
        print_info("This message was encrypted with a passphrase.")
        if passphrase_hint:
            print_info(f"  Passphrase hint: {Fore.YELLOW}{passphrase_hint}{Style.RESET_ALL}")
        print()
        passphrase = prompt("Enter passphrase")
        s_prime = passphrase_to_s_prime(passphrase)
    else:
        print_info("You need the off-chain secret (s') to decrypt it.")
        print_info("The recipient should have received s' from the message sender.")
        print()
        s_prime = prompt("Enter s' (hex, starts with 0x)")
        if not s_prime.startswith('0x'):
            s_prime = '0x' + s_prime

    # Decrypt
    message = decrypt_aes_gcm_packed(data['encryptedPayload'], data['skShare'], s_prime)
    if message is None:
        return

    print()
    print_success("Message decrypted successfully!")

    # Output
    if output_path:
        # Write to file
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, 'w', encoding='utf-8') as f:
            f.write(message)
        print_success(f"Message saved to: {output_path}")
    else:
        # Ask user how to output
        print()
        if confirm("Display message in terminal?"):
            print_section("Decrypted Message")
            print(message)
        else:
            # Auto-generate filename
            source = Path(filepath)
            default_name = source.stem + "_decrypted.txt"
            out_path = prompt("Save to file", default_name)
            out = Path(out_path)
            out.parent.mkdir(parents=True, exist_ok=True)
            with open(out, 'w', encoding='utf-8') as f:
                f.write(message)
            print_success(f"Message saved to: {out_path}")


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Farewell Message Decrypter — decrypt messages from Farewell claim packages"
    )
    parser.add_argument(
        'file', nargs='?',
        help='Path to the claim package JSON file'
    )
    parser.add_argument(
        '-f', '--file', dest='file_flag',
        help='Path to the claim package JSON file (alternative to positional)'
    )
    parser.add_argument(
        '-o', '--output',
        help='Output file path for the decrypted message'
    )

    args = parser.parse_args()
    args.filepath = args.file or args.file_flag
    return args


def main():
    """Entry point."""
    args = parse_args()

    if not args.filepath:
        print_banner()
        print_error("No input file specified.")
        print_info("Usage: python farewell_decrypter.py <claim_package.json>")
        print_info("       python farewell_decrypter.py -f <claim_package.json>")
        sys.exit(1)

    try:
        main_flow(args.filepath, args.output)
    except KeyboardInterrupt:
        print()
        print_info("Aborted.")
        sys.exit(0)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
