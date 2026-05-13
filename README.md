# Farewell Message Decrypter

[![CI](https://github.com/farewell-world/farewell-decrypter/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/farewell-world/farewell-decrypter/actions/workflows/ci.yml?query=branch%3Amain)


A standalone CLI tool for **recipients** to decrypt messages from the [Farewell protocol](https://farewell.world).

## How It Works

The Farewell protocol uses a key-splitting scheme to protect messages until they're released:

```
Sender (registration)                    Recipient (after release)
━━━━━━━━━━━━━━━━━━━━━                    ━━━━━━━━━━━━━━━━━━━━━━━━

   AES key (sk)                           skShare ──┐
       │                                  (from      │  XOR
       ├── s  (skShare)──→ On-chain FHE    claim)    │───→ sk
       │                                             │
       └── s' ──────────→ Off-chain to     s' ───────┘
                          recipient       (received
                                          off-chain)

                                           sk ──→ AES-GCM decrypt ──→ plaintext
```

1. The **sender** encrypts their message with a random AES-128 key (`sk`)
2. `sk` is split: `s` (stored on-chain via FHE) + `s'` (shared off-chain with recipient)
3. After the sender is marked deceased, a **claimer** retrieves `s` (now called `skShare`) and exports a claim package JSON
4. The **recipient** uses this tool to combine `skShare` + `s'` → recover `sk` → decrypt the message

## Installation

```bash
# Clone the repository
git clone https://github.com/farewell-world/farewell-decrypter.git
cd farewell-decrypter

# Create virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic usage

```bash
python farewell_decrypter.py claim_package.json
```

The tool will:
1. Load and validate the claim package
2. Display metadata (owner, recipients, subject)
3. Prompt you for `s'` (the off-chain secret you received from the sender)
4. Decrypt the message
5. Ask whether to display in terminal or save to a file

### Save to a file directly

```bash
python farewell_decrypter.py claim_package.json -o decrypted.txt
```

### Using the -f flag

```bash
python farewell_decrypter.py -f claim_package.json
```

## JSON Format

The tool accepts the **claim package** format exported from the Farewell UI:

```json
{
  "type": "farewell-claim-package",
  "recipients": ["alice@example.com"],
  "skShare": "0x...",
  "encryptedPayload": "0x...",
  "contentHash": "0x...",
  "subject": "A Farewell Message",
  "owner": "0x...",
  "senderName": "Alice",
  "messageIndex": 0
}
```

**Required fields**: `skShare`, `encryptedPayload`

**Optional fields**: `type`, `recipients`, `contentHash`, `subject`, `owner`, `senderName`, `messageIndex`

### Encryption details

- **Algorithm**: AES-128-GCM
- **Packed format**: `0x` + IV (12 bytes) + ciphertext + GCM tag (16 bytes)
- **Key derivation**: `sk = skShare XOR s'` (128-bit), big-endian

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `AES-GCM decryption failed` | Double-check the `s'` value — it must match exactly |
| `Missing required field` | The JSON file is incomplete — re-export from the Farewell UI |
| `Invalid JSON` | The file is corrupted — re-download the claim package |
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` |

## Development

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
pytest

# Run with coverage
pytest --cov=farewell_decrypter --cov-report=term-missing
```

## Support the Project

If you find Farewell interesting or useful, consider sending a donation on Ethereum or any EVM-compatible chain:

**`0x10fcc6f07a84bBaCd26e2827122be09830243da5`**

## Disclaimer

This is a proof-of-concept tool for the Farewell protocol. The Farewell protocol is experimental software developed by a [Zama](https://zama.ai) employee as a personal project. It is not a Zama product and carries no warranty.

## License

BSD 3-Clause License. See [LICENSE](LICENSE).

## Related Projects

- [Farewell UI](https://farewell.world) — Web application
- [Farewell Core](https://github.com/farewell-world/farewell-core) — Smart contracts
- [Farewell Claimer](https://github.com/farewell-world/farewell-claimer) — Email sending & proof generation tool
