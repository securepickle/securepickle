# secure-pickle

**A jar of pickles comes tamper-proof. So should your code.**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-green.svg)](https://python.org)

## Installation

```bash
pip install secure-pickle
```

Optional dependencies:
```bash
pip install secure-pickle[fast]      # xxhash for 5x faster mode
pip install secure-pickle[encrypt]   # cryptography for AES-256-GCM
pip install secure-pickle[all]       # both
```

## Why?

Regular `pickle.load()` will execute ANY code inside the file:

```python
class Evil:
    def __reduce__(self):
        return (os.system, ('whoami',))

# Attacker sends this. You pickle.load(). Game over.
```

This is real. `__reduce__` tells pickle how to reconstruct an object - and attackers use it to reconstruct *your system* into *their system*.

## Solution

`secure-pickle` checks the seal BEFORE opening the jar:

1. **Signs** every pickle with HMAC-SHA256
2. **Verifies** the signature before loading
3. **Refuses** to open if tampered

```python
from secure_pickle import secure_dump, secure_load

# Save (signs it)
secure_dump(data, "safe.pkl")

# Load (verifies first)
data = secure_load("safe.pkl")
```

## Modes

| Mode | Security | Speed | Use Case |
|------|----------|-------|----------|
| `mode="secure"` | HMAC-SHA256 | Normal | Default, production |
| `mode="fast"` | xxhash | 5x faster | Caches only (NOT attack-resistant) |
| `encrypt=True` | AES-256-GCM | Slower | Secrets, credentials, PII |

```python
# Fast mode - corruption detection only, NOT attack-resistant
secure_dump(data, "cache.pkl", mode="fast")

# Encrypted - requires cryptography package
secure_dump(secrets, "vault.pkl", encrypt=True)
```

## Performance

v1.2.0 uses optimized I/O patterns:

| Size | vs Raw Pickle |
|------|---------------|
| <16KB | **Faster than raw!** |
| 16-256KB | +30-40% |
| 256KB-2MB | +50-100% |
| >2MB | +30-50% |

## API

### Functions

```python
secure_dump(obj, path, key=None, encrypt=False, mode="secure")
secure_load(path, key=None, encrypt=None)
secure_dumps(obj, key=None, encrypt=False, mode="secure") -> bytes
secure_loads(data, key=None, encrypt=None) -> object
is_secure_pickle(path) -> bool
migrate_pickle(old_path, new_path=None, encrypt=False)
```

### Key Management

By default, keys are stored in `~/.secure_pickle/key`. Override with:

```python
from secure_pickle import set_key_path
set_key_path("/custom/path")
```

Or environment variable:
```bash
export SECURE_PICKLE_KEY_DIR=/custom/path
```

## CLI

```bash
# Check if file is secure
secure-pickle check data.pkl

# Migrate unsigned pickle
secure-pickle migrate old.pkl --output new.pkl

# Verify signature
secure-pickle verify data.pkl
```

## Security Notes

- **HMAC-SHA256** provides cryptographic integrity (mode="secure")
- **xxhash** provides fast corruption detection only (mode="fast")
- **AES-256-GCM** provides authenticated encryption (encrypt=True)
- Keys are auto-generated with `os.urandom(32)`
- Key files have `0600` permissions
- Signatures verified with timing-safe comparison

## Pop. Verify. Trust.

---

Apache 2.0 License | Copyright 2025 ECT Framework Contributors
