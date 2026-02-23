# CLAUDE.md - Farewell Decrypter

## Project Overview

Farewell Decrypter is a Python CLI tool that helps recipients decrypt Farewell messages using the off-chain secret (s') combined with the on-chain key share (skShare) from a claim package.

**Status**: Functional proof-of-concept. Works with the Farewell protocol on Sepolia testnet.

**Live Demo**: https://farewell.world

**License**: BSD 3-Clause

## Repository Structure

```
farewell-decrypter/
├── farewell_decrypter.py    # Main CLI application (single file)
├── tests/
│   ├── __init__.py
│   ├── conftest.py          # Test fixtures
│   └── test_decrypter.py    # Decryption and file loading tests
├── requirements.txt         # Runtime dependencies
├── requirements-dev.txt     # Development dependencies
├── pytest.ini               # Pytest configuration
├── README.md
├── CLAUDE.md
└── LICENSE
```

## Quick Start

```bash
# Create virtual environment (recommended for PEP 668 compliance)
python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS

# Install dependencies
pip install -r requirements.txt

# Run with a claim package JSON
python farewell_decrypter.py claim_package.json

# Run with output file
python farewell_decrypter.py claim_package.json -o decrypted.txt
```

## Key Technologies

- **Language**: Python 3.8+
- **Encryption**: AES-128-GCM via `cryptography` library
- **Terminal UI**: `colorama` for cross-platform colors
- **Testing**: pytest

## Application Architecture

### Single-File Design

The entire application is in `farewell_decrypter.py` for easy distribution and portability. Key components:

1. **UI Helpers** — Banner, colored output, prompts, confirmation
2. **Decryption** — `decrypt_aes_gcm_packed()` — XOR key reconstruction + AES-GCM
3. **File Loading** — `load_claim_package()` — JSON validation
4. **Main Flow** — `main_flow()` — orchestration: load → prompt s' → decrypt → output

### Key Functions

```python
def decrypt_aes_gcm_packed(encrypted_hex, sk_share_hex, s_prime_hex) -> Optional[str]:
    """Decrypt AES-128-GCM packed payload using skShare XOR s'."""

def load_claim_package(filepath) -> Optional[Dict]:
    """Load and validate a claim package JSON file."""

def main_flow(filepath, output_path=None):
    """Orchestrate the decryption workflow."""
```

### AES-128-GCM Packed Format

- **Packed format**: `0x` + IV (12 bytes) + ciphertext + GCM tag (16 bytes)
- **Key derivation**: `sk = skShare XOR s'` (128-bit integers, big-endian to 16-byte key)
- This matches the format in `farewell/packages/site/lib/aes.ts`

## Cross-Project Compatibility: Farewell UI

**IMPORTANT**: The `load_claim_package()` function parses the JSON exported from the Farewell UI's Claim tab (`ClaimPackageJson` in `Farewell.tsx`, located at `../farewell/packages/site/components/Farewell.tsx`). When modifying the claim package parsing:

1. The claim package is detected by `type: "farewell-claim-package"`
2. Required fields for decryption: `skShare` (hex), `encryptedPayload` (hex)
3. AES-128-GCM packed format: `0x` + IV(12 bytes) + ciphertext+GCM-tag; key = `skShare XOR s'` as 16-byte big-endian
4. If you change field names or the decryption logic, update `Farewell.tsx` and `farewell-claimer` accordingly

## Testing

```bash
# Activate virtual environment
source .venv/bin/activate

# Run all tests
pytest

# Run with coverage
pytest --cov=farewell_decrypter --cov-report=term-missing

# Run specific test class
pytest tests/test_decrypter.py::TestDecryptAesGcmPacked -v
```

### Test Fixtures (`conftest.py`)

- `sample_claim_package` — Dict with all claim package fields
- `claim_package_file` — Temp JSON file with sample claim package
- `encrypted_test_data` — Real AES-128-GCM encrypted payload for round-trip testing

## Development Guidelines

### Code Style
- Follow PEP 8
- Use type hints for function signatures
- Colorama for terminal colors (cross-platform)

### Error Handling
- All decryption operations wrapped in try/except
- User-friendly error messages with colorama formatting
- Return None on failure (never raise from public functions)

## Git Guidelines

- Use conventional commit messages (feat:, fix:, docs:, refactor:, etc.)
- Keep commits focused on a single logical change

## Maintenance Instructions

**IMPORTANT**: When making changes to this codebase:

1. **Update this CLAUDE.md** if CLI interface, functions, or architecture change
2. **Update README.md** if user-facing documentation changes
3. **Run tests** before committing: `pytest`
4. **Keep URL references** synchronized with https://farewell.world

Any AI agent working on this repository should ensure documentation stays synchronized with code changes.
