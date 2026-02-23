"""
Tests for farewell_decrypter.
"""

import json
import pytest
from pathlib import Path

import farewell_decrypter


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
