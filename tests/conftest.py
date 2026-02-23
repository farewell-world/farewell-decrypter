"""
Pytest fixtures for farewell-decrypter tests.
"""

import os
import json
import pytest
import sys
from pathlib import Path
from unittest.mock import MagicMock

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Mock colorama before importing the module
mock_fore = MagicMock()
mock_fore.CYAN = ""
mock_fore.GREEN = ""
mock_fore.BLUE = ""
mock_fore.YELLOW = ""
mock_fore.RED = ""
mock_fore.WHITE = ""

mock_style = MagicMock()
mock_style.RESET_ALL = ""

# Patch colorama
sys.modules['colorama'] = MagicMock()
sys.modules['colorama'].init = MagicMock()
sys.modules['colorama'].Fore = mock_fore
sys.modules['colorama'].Style = mock_style

# Now we can import the module
import farewell_decrypter


@pytest.fixture
def sample_claim_package():
    """Create a sample claim package dict."""
    return {
        "type": "farewell-claim-package",
        "recipients": ["alice@example.com", "bob@example.com"],
        "skShare": "0xaabbccdd11223344aabbccdd11223344",
        "encryptedPayload": "0x000000000000000000000000abcdef",
        "contentHash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "subject": "A Farewell Message",
        "owner": "TestUser",
        "messageIndex": 0
    }


@pytest.fixture
def claim_package_file(tmp_path, sample_claim_package):
    """Write a sample claim package to a temp JSON file."""
    filepath = tmp_path / "claim.json"
    with open(filepath, 'w') as f:
        json.dump(sample_claim_package, f)
    return str(filepath)


@pytest.fixture
def encrypted_test_data():
    """
    Create a real AES-128-GCM encrypted payload for round-trip testing.

    Returns dict with sk_share, s_prime, encrypted_hex, and plaintext.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    plaintext = "Hello from beyond. This is my farewell message."

    # Generate random key parts
    import secrets
    sk_share_int = int.from_bytes(secrets.token_bytes(16), 'big')
    s_prime_int = int.from_bytes(secrets.token_bytes(16), 'big')

    # Derive AES key: sk = skShare XOR s'
    sk_int = sk_share_int ^ s_prime_int
    key = sk_int.to_bytes(16, byteorder='big')

    # Encrypt with AES-128-GCM (packed format: IV + ciphertext+tag)
    iv = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ciphertext_and_tag = aesgcm.encrypt(iv, plaintext.encode('utf-8'), None)

    # Pack: IV + ciphertext+tag
    packed = iv + ciphertext_and_tag
    encrypted_hex = "0x" + packed.hex()

    sk_share_hex = "0x" + format(sk_share_int, '032x')
    s_prime_hex = "0x" + format(s_prime_int, '032x')

    return {
        "sk_share_hex": sk_share_hex,
        "s_prime_hex": s_prime_hex,
        "encrypted_hex": encrypted_hex,
        "plaintext": plaintext,
    }
