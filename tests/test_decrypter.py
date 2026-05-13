"""
Tests for farewell_decrypter.
"""

import json
import secrets
import pytest
from pathlib import Path
from unittest.mock import patch

import farewell_decrypter
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============ decrypt_aes_gcm_packed ============

class TestDecryptAesGcmPacked:
    """Tests for the AES-GCM decryption function."""

    def test_round_trip(self, encrypted_test_data):
        """Encrypt and decrypt round-trip produces original plaintext."""
        result = farewell_decrypter.decrypt_aes_gcm_packed(
            encrypted_test_data["encrypted_hex"],
            encrypted_test_data["sk_share_hex"],
            encrypted_test_data["s_prime_hex"],
        )
        assert result == encrypted_test_data["plaintext"]

    def test_wrong_key_returns_none(self, encrypted_test_data):
        """Wrong s' value returns None."""
        wrong_s_prime = "0x00000000000000000000000000000001"
        result = farewell_decrypter.decrypt_aes_gcm_packed(
            encrypted_test_data["encrypted_hex"],
            encrypted_test_data["sk_share_hex"],
            wrong_s_prime,
        )
        assert result is None

    def test_short_payload_returns_none(self):
        """Payload shorter than IV + GCM tag returns None."""
        result = farewell_decrypter.decrypt_aes_gcm_packed(
            "0xaabbccdd",  # way too short
            "0xaabbccdd11223344aabbccdd11223344",
            "0xaabbccdd11223344aabbccdd11223344",
        )
        assert result is None

    def test_strips_0x_prefix(self, encrypted_test_data):
        """Works with or without 0x prefix on all inputs."""
        # Strip 0x from all inputs
        enc = encrypted_test_data["encrypted_hex"][2:]
        sk = encrypted_test_data["sk_share_hex"][2:]
        sp = encrypted_test_data["s_prime_hex"][2:]

        result = farewell_decrypter.decrypt_aes_gcm_packed(enc, sk, sp)
        assert result == encrypted_test_data["plaintext"]


# ============ load_claim_package ============

class TestLoadClaimPackage:
    """Tests for the claim package loader."""

    def test_valid_package(self, claim_package_file):
        """Loads a valid claim package JSON."""
        data = farewell_decrypter.load_claim_package(claim_package_file)
        assert data is not None
        assert data["skShare"] == "0xaabbccdd11223344aabbccdd11223344"
        assert data["encryptedPayload"] == "0x000000000000000000000000abcdef"
        assert data["type"] == "farewell-claim-package"

    def test_missing_fields(self, tmp_path):
        """Returns None when required fields are missing."""
        filepath = tmp_path / "bad.json"
        with open(filepath, 'w') as f:
            json.dump({"type": "farewell-claim-package", "skShare": "0x1234"}, f)

        data = farewell_decrypter.load_claim_package(str(filepath))
        assert data is None

    def test_file_not_found(self):
        """Returns None for non-existent file."""
        data = farewell_decrypter.load_claim_package("/nonexistent/file.json")
        assert data is None

    def test_invalid_json(self, tmp_path):
        """Returns None for invalid JSON."""
        filepath = tmp_path / "bad.json"
        with open(filepath, 'w') as f:
            f.write("this is not json {{{")

        data = farewell_decrypter.load_claim_package(str(filepath))
        assert data is None

    def test_minimal_package(self, tmp_path):
        """Loads a minimal package with just skShare and encryptedPayload."""
        filepath = tmp_path / "minimal.json"
        with open(filepath, 'w') as f:
            json.dump({
                "skShare": "0xaabb",
                "encryptedPayload": "0xccdd",
            }, f)

        data = farewell_decrypter.load_claim_package(str(filepath))
        assert data is not None
        assert data["skShare"] == "0xaabb"


# ============ UI Helpers ============

class TestUIHelpers:
    """Tests for UI helper functions."""

    def test_print_banner(self, capsys):
        """Banner prints without error."""
        farewell_decrypter.print_banner()
        captured = capsys.readouterr()
        assert len(captured.out) > 0

    def test_print_section(self, capsys):
        """Section header prints title."""
        farewell_decrypter.print_section("Test Section")
        captured = capsys.readouterr()
        assert "Test Section" in captured.out

    def test_print_success(self, capsys):
        """Success message prints."""
        farewell_decrypter.print_success("It worked")
        captured = capsys.readouterr()
        assert "It worked" in captured.out

    def test_print_error(self, capsys):
        """Error message prints."""
        farewell_decrypter.print_error("Something failed")
        captured = capsys.readouterr()
        assert "Something failed" in captured.out

    def test_print_info(self, capsys):
        """Info message prints."""
        farewell_decrypter.print_info("FYI")
        captured = capsys.readouterr()
        assert "FYI" in captured.out

    def test_confirm_yes(self, monkeypatch):
        """confirm() returns True for 'y'."""
        monkeypatch.setattr('builtins.input', lambda _: 'y')
        assert farewell_decrypter.confirm("Continue?") is True

    def test_confirm_no(self, monkeypatch):
        """confirm() returns False for 'n'."""
        monkeypatch.setattr('builtins.input', lambda _: 'n')
        assert farewell_decrypter.confirm("Continue?") is False

    def test_confirm_default_true(self, monkeypatch):
        """confirm() returns default=True on empty input."""
        monkeypatch.setattr('builtins.input', lambda _: '')
        assert farewell_decrypter.confirm("Continue?", default=True) is True

    def test_confirm_default_false(self, monkeypatch):
        """confirm() returns default=False on empty input."""
        monkeypatch.setattr('builtins.input', lambda _: '')
        assert farewell_decrypter.confirm("Continue?", default=False) is False

    def test_prompt_returns_input(self, monkeypatch):
        """prompt() returns user input."""
        monkeypatch.setattr('builtins.input', lambda _: 'hello')
        assert farewell_decrypter.prompt("Say something") == "hello"

    def test_prompt_returns_default(self, monkeypatch):
        """prompt() returns default on empty input."""
        monkeypatch.setattr('builtins.input', lambda _: '')
        assert farewell_decrypter.prompt("Say something", "default_val") == "default_val"


# ============ passphrase_to_s_prime ============

class TestPassphraseToSPrime:
    """Tests for the SHAKE128-based passphrase-to-key derivation."""

    def test_deterministic_output(self):
        """Same passphrase always produces the same s' value."""
        result1 = farewell_decrypter.passphrase_to_s_prime("my secret passphrase")
        result2 = farewell_decrypter.passphrase_to_s_prime("my secret passphrase")
        assert result1 == result2

    def test_different_inputs_different_outputs(self):
        """Different passphrases produce different s' values."""
        result1 = farewell_decrypter.passphrase_to_s_prime("passphrase one")
        result2 = farewell_decrypter.passphrase_to_s_prime("passphrase two")
        assert result1 != result2

    def test_empty_string(self):
        """Empty string produces a valid 0x-prefixed 128-bit hex string."""
        result = farewell_decrypter.passphrase_to_s_prime("")
        assert result.startswith("0x")
        # 0x prefix + 32 hex chars = 34 total (16 bytes = 128 bits)
        assert len(result) == 34

    def test_unicode_input(self):
        """Unicode passphrases produce valid output."""
        result = farewell_decrypter.passphrase_to_s_prime("café")  # e + combining accent
        assert result.startswith("0x")
        assert len(result) == 34
        # Different unicode representations produce different outputs
        result2 = farewell_decrypter.passphrase_to_s_prime("é")  # precomposed e-accent
        # These are different UTF-8 byte sequences, so they should differ
        assert result != result2

    def test_output_format(self):
        """Output is a 0x-prefixed lowercase hex string of 128 bits."""
        result = farewell_decrypter.passphrase_to_s_prime("test")
        assert result.startswith("0x")
        hex_part = result[2:]
        assert len(hex_part) == 32
        # Verify it's valid hex
        int(hex_part, 16)

    def test_output_usable_as_s_prime(self, encrypted_test_data):
        """
        A passphrase-derived s' can be used in the full decryption flow:
        encrypt with sk = skShare XOR passphrase_s_prime, then decrypt.
        """
        passphrase = "my test passphrase"
        s_prime_hex = farewell_decrypter.passphrase_to_s_prime(passphrase)

        # Create a known skShare
        sk_share_int = int.from_bytes(secrets.token_bytes(16), 'big')
        sk_share_hex = "0x" + format(sk_share_int, '032x')

        # Derive key
        s_prime_int = int(s_prime_hex, 16)
        sk_int = sk_share_int ^ s_prime_int
        key = sk_int.to_bytes(16, byteorder='big')

        # Encrypt
        iv = secrets.token_bytes(12)
        aesgcm = AESGCM(key)
        plaintext = "Test message for passphrase flow"
        ct = aesgcm.encrypt(iv, plaintext.encode('utf-8'), None)
        encrypted_hex = "0x" + (iv + ct).hex()

        # Decrypt using the tool
        result = farewell_decrypter.decrypt_aes_gcm_packed(encrypted_hex, sk_share_hex, s_prime_hex)
        assert result == plaintext


# ============ _parse_int ============

class TestParseInt:
    """Tests for the integer parsing helper."""

    def test_hex_with_0x_prefix(self):
        """Parses hex string with 0x prefix."""
        assert farewell_decrypter._parse_int("0xff") == 255
        assert farewell_decrypter._parse_int("0xFF") == 255

    def test_hex_with_0X_prefix(self):
        """Parses hex string with uppercase 0X prefix."""
        assert farewell_decrypter._parse_int("0Xff") == 255
        assert farewell_decrypter._parse_int("0XFF") == 255

    def test_hex_without_prefix(self):
        """Parses hex string without prefix (contains a-f characters)."""
        assert farewell_decrypter._parse_int("ff") == 255
        assert farewell_decrypter._parse_int("abcdef") == 0xabcdef

    def test_decimal_number(self):
        """Parses a pure decimal number string."""
        assert farewell_decrypter._parse_int("255") == 255
        assert farewell_decrypter._parse_int("0") == 0
        assert farewell_decrypter._parse_int("12345") == 12345

    def test_large_numbers(self):
        """Parses large 128-bit numbers in both decimal and hex."""
        # Max 128-bit value
        max_128 = (1 << 128) - 1
        hex_str = "0x" + format(max_128, 'x')
        assert farewell_decrypter._parse_int(hex_str) == max_128

        dec_str = str(max_128)
        assert farewell_decrypter._parse_int(dec_str) == max_128

    def test_zero(self):
        """Parses zero in both hex and decimal."""
        assert farewell_decrypter._parse_int("0") == 0
        assert farewell_decrypter._parse_int("0x0") == 0
        assert farewell_decrypter._parse_int("0x00") == 0

    def test_ambiguous_all_digits_hex_lookalike(self):
        """A string like '100' with only digits is parsed as decimal, not hex."""
        # '100' is all digits, so it's treated as decimal
        assert farewell_decrypter._parse_int("100") == 100
        # But '100' as hex would be 256 -- confirm it's decimal
        assert farewell_decrypter._parse_int("100") != 256


# ============ decrypt_aes_gcm_packed (additional edge cases) ============

class TestDecryptAesGcmPackedEdgeCases:
    """Additional edge case tests for AES-GCM decryption."""

    def test_corrupted_ciphertext_returns_none(self, encrypted_test_data):
        """Corrupting the ciphertext bytes causes decryption failure."""
        enc_hex = encrypted_test_data["encrypted_hex"]
        # Corrupt a byte in the middle of the ciphertext (after the 12-byte IV)
        enc_bytes = bytes.fromhex(enc_hex[2:])
        corrupted = bytearray(enc_bytes)
        # Flip a byte after the IV (position 15, well into the ciphertext)
        corrupted[15] ^= 0xFF
        corrupted_hex = "0x" + bytes(corrupted).hex()

        result = farewell_decrypter.decrypt_aes_gcm_packed(
            corrupted_hex,
            encrypted_test_data["sk_share_hex"],
            encrypted_test_data["s_prime_hex"],
        )
        assert result is None

    def test_empty_payload_returns_none(self):
        """Empty hex string returns None (too short)."""
        result = farewell_decrypter.decrypt_aes_gcm_packed(
            "0x",
            "0xaabbccdd11223344aabbccdd11223344",
            "0xaabbccdd11223344aabbccdd11223344",
        )
        assert result is None

    def test_exactly_iv_plus_tag_length(self):
        """Payload of exactly 28 bytes (12 IV + 16 tag) with no ciphertext -- decryption of empty plaintext."""
        # AES-GCM with empty plaintext is valid: IV(12) + tag(16) = 28 bytes
        sk_share_int = int.from_bytes(secrets.token_bytes(16), 'big')
        s_prime_int = int.from_bytes(secrets.token_bytes(16), 'big')
        sk_int = sk_share_int ^ s_prime_int
        key = sk_int.to_bytes(16, byteorder='big')

        iv = secrets.token_bytes(12)
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(iv, b"", None)
        encrypted_hex = "0x" + (iv + ct).hex()

        result = farewell_decrypter.decrypt_aes_gcm_packed(
            encrypted_hex,
            "0x" + format(sk_share_int, '032x'),
            "0x" + format(s_prime_int, '032x'),
        )
        assert result == ""

    def test_decimal_sk_share(self):
        """skShare provided as a decimal string (BigInt.toString() format) works."""
        sk_share_int = int.from_bytes(secrets.token_bytes(16), 'big')
        s_prime_int = int.from_bytes(secrets.token_bytes(16), 'big')
        sk_int = sk_share_int ^ s_prime_int
        key = sk_int.to_bytes(16, byteorder='big')

        iv = secrets.token_bytes(12)
        aesgcm = AESGCM(key)
        plaintext = "decimal skShare test"
        ct = aesgcm.encrypt(iv, plaintext.encode('utf-8'), None)
        encrypted_hex = "0x" + (iv + ct).hex()

        # Pass skShare as decimal string (no 0x prefix, all digits)
        result = farewell_decrypter.decrypt_aes_gcm_packed(
            encrypted_hex,
            str(sk_share_int),
            "0x" + format(s_prime_int, '032x'),
        )
        assert result == plaintext

    def test_whitespace_in_keys_handled(self):
        """Leading/trailing whitespace in key strings is stripped."""
        sk_share_int = int.from_bytes(secrets.token_bytes(16), 'big')
        s_prime_int = int.from_bytes(secrets.token_bytes(16), 'big')
        sk_int = sk_share_int ^ s_prime_int
        key = sk_int.to_bytes(16, byteorder='big')

        iv = secrets.token_bytes(12)
        aesgcm = AESGCM(key)
        plaintext = "whitespace test"
        ct = aesgcm.encrypt(iv, plaintext.encode('utf-8'), None)
        encrypted_hex = "0x" + (iv + ct).hex()

        # Add whitespace around key strings
        result = farewell_decrypter.decrypt_aes_gcm_packed(
            encrypted_hex,
            "  0x" + format(sk_share_int, '032x') + "  ",
            "  0x" + format(s_prime_int, '032x') + "\n",
        )
        assert result == plaintext


# ============ main_flow ============

class TestMainFlow:
    """Tests for the main decryption workflow with mocked I/O."""

    def _make_claim_file(self, tmp_path, plaintext="Hello World", crypto_scheme="", passphrase_hint=""):
        """Helper: create a valid claim package file with real encrypted data."""
        sk_share_int = int.from_bytes(secrets.token_bytes(16), 'big')
        s_prime_int = int.from_bytes(secrets.token_bytes(16), 'big')
        sk_int = sk_share_int ^ s_prime_int
        key = sk_int.to_bytes(16, byteorder='big')

        iv = secrets.token_bytes(12)
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(iv, plaintext.encode('utf-8'), None)
        encrypted_hex = "0x" + (iv + ct).hex()

        package = {
            "type": "farewell-claim-package",
            "recipients": ["test@example.com"],
            "skShare": "0x" + format(sk_share_int, '032x'),
            "encryptedPayload": encrypted_hex,
            "contentHash": "0x" + "00" * 32,
            "owner": "0x1234567890abcdef1234567890abcdef12345678",
            "messageIndex": 0,
        }
        if crypto_scheme:
            package["cryptoScheme"] = crypto_scheme
        if passphrase_hint:
            package["passphraseHint"] = passphrase_hint

        filepath = tmp_path / "claim.json"
        with open(filepath, 'w') as f:
            json.dump(package, f)

        return str(filepath), "0x" + format(s_prime_int, '032x'), plaintext

    def test_successful_raw_hex_path(self, tmp_path, capsys):
        """Full flow with raw hex s' input decrypts and saves to output file."""
        filepath, s_prime_hex, plaintext = self._make_claim_file(tmp_path)
        output_path = str(tmp_path / "decrypted.txt")

        # Mock the prompt for s' input
        with patch('builtins.input', return_value=s_prime_hex):
            farewell_decrypter.main_flow(filepath, output_path=output_path)

        # Verify the file was written with the decrypted message
        with open(output_path, 'r') as f:
            assert f.read() == plaintext

        captured = capsys.readouterr()
        assert "decrypted successfully" in captured.out

    def test_successful_passphrase_path(self, tmp_path, capsys):
        """Full flow with passphrase-derived s' decrypts correctly."""
        passphrase = "my secret test passphrase"
        s_prime_hex = farewell_decrypter.passphrase_to_s_prime(passphrase)

        # Create claim file where s' was derived from this passphrase
        sk_share_int = int.from_bytes(secrets.token_bytes(16), 'big')
        s_prime_int = int(s_prime_hex, 16)
        sk_int = sk_share_int ^ s_prime_int
        key = sk_int.to_bytes(16, byteorder='big')

        iv = secrets.token_bytes(12)
        aesgcm = AESGCM(key)
        plaintext = "Passphrase-encrypted farewell message"
        ct = aesgcm.encrypt(iv, plaintext.encode('utf-8'), None)
        encrypted_hex = "0x" + (iv + ct).hex()

        package = {
            "type": "farewell-claim-package",
            "skShare": "0x" + format(sk_share_int, '032x'),
            "encryptedPayload": encrypted_hex,
            "contentHash": "0x" + "00" * 32,
            "cryptoScheme": "AES-128-GCM;SHAKE128",
            "passphraseHint": "my hint",
        }
        filepath = tmp_path / "claim_passphrase.json"
        with open(filepath, 'w') as f:
            json.dump(package, f)

        output_path = str(tmp_path / "decrypted.txt")

        # Mock the passphrase prompt
        with patch('builtins.input', return_value=passphrase):
            farewell_decrypter.main_flow(str(filepath), output_path=output_path)

        with open(output_path, 'r') as f:
            assert f.read() == plaintext

        captured = capsys.readouterr()
        assert "decrypted successfully" in captured.out
        assert "my hint" in captured.out

    def test_file_not_found_error(self, capsys):
        """main_flow with a nonexistent file prints error and returns."""
        farewell_decrypter.main_flow("/nonexistent/path/claim.json")
        captured = capsys.readouterr()
        assert "File not found" in captured.out

    def test_wrong_s_prime_fails_gracefully(self, tmp_path, capsys):
        """Wrong s' value results in decryption failure without crashing."""
        filepath, _, _ = self._make_claim_file(tmp_path)
        wrong_s_prime = "0x00000000000000000000000000000001"
        output_path = str(tmp_path / "decrypted.txt")

        with patch('builtins.input', return_value=wrong_s_prime):
            farewell_decrypter.main_flow(filepath, output_path=output_path)

        # Output file should not be created
        assert not Path(output_path).exists()
        captured = capsys.readouterr()
        assert "decryption failed" in captured.out.lower() or "incorrect" in captured.out.lower()

    def test_display_to_terminal(self, tmp_path, capsys, monkeypatch):
        """When no output path and user confirms display, message is printed to terminal."""
        filepath, s_prime_hex, plaintext = self._make_claim_file(tmp_path)

        # Two prompts: first for s', second for confirm (display in terminal)
        inputs = iter([s_prime_hex, 'y'])
        monkeypatch.setattr('builtins.input', lambda _: next(inputs))

        farewell_decrypter.main_flow(filepath, output_path=None)

        captured = capsys.readouterr()
        assert plaintext in captured.out
