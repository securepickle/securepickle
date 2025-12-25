

```markdown
# securepickle
# If you're reading this, yes, pickle is still dangerous in 2025.

Secure pickle is the customs check for Python serialization: the package arrives at the border, we inspect it before we let it in. Common sense. That is all we do. No fancy tricks.

Description
–––––––––––
Securepickle is a defensive wrapper around Python’s pickle module that prevents
arbitrary code execution from tampered or malicious pickle data.

Securepickle is for systems that already rely on pickle and need a practical safety layer.
It is not an argument that pickle is ideal. It is mitigation for reality. We know pickle is out there, unsecured, rotting away in leaky jars. 

securepickle is for Python systems (including LLM pipelines) that already use pickle for performance and convenience, but need a guardrail when artifacts persist, move, or get reused.

LLMs don’t make pickle safer.
They make it easier to accidentally trust serialized code you didn’t write.

securepickle adds a cryptographic “did this come from us?” check before any code is executed.

💀 Executed.
Cause of death: unverified pickle.
Time of death: pickle.load()
Next of kin notified: HMAC-SHA256

Pop. Verify. Trust.

It enforces cryptographic integrity checks before unpickling and optionally
supports authenticated encryption. If verification fails, the data is never
deserialized.

This library is intended for environments where pickle compatibility is required
but untrusted or externally stored data is involved.

Why this exists
–––––––––––––––
pickle is not safe for untrusted input. Loading a malicious pickle can execute
arbitrary code.

securepickle mitigates this risk by requiring signed (and optionally encrypted)
payloads before deserialization.

What it does / does not do
––––––––––––––––––––––––––
✔ Prevents tampering and malicious payload execution
✔ Maintains pickle compatibility
✖ Does not sandbox Python objects
✖ Does not make pickle “safe” without a shared secret

 You gotta keep 'em separated!
 
     _____ ______ _____ _    _ _____  ______   _____ _____ _____ _  ___      _______ 
    / ____|  ____/ ____| |  | |  __ \|  ____| |  __ \_   _/ ____| |/ / |    |  ____|
   | (___ | |__ | |    | |  | | |__) | |__    | |__) || || |    | ' /| |    | |__   
    \___ \|  __|| |    | |  | |  _  /|  __|   |  ___/ | || |    |  < | |    |  __|  
    ____) | |___| |____| |__| | | \ \| |____  | |    _| || |____| . \| |____| |____ 
   |_____/|______\_____|\____/|_|  \_\______| |_|   |_____\_____|_|\_\______|______|
  
                           v1.2.0 - NOW SHIPPING
                           
              "A jar of pickles comes tamper-proof.
                      So should your code."
                      
                      Pop. Verify. Trust.



**A jar of pickles comes tamper-proof. So should your code.**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-green.svg)](https://python.org)

## Installation

```bash
pip install securepickle
```

Optional dependencies:

```bash
pip install securepickle[fast]      # xxhash for 5x faster mode
pip install securepickle[encrypt]   # cryptography for AES-256-GCM
pip install securepickle[all]       # both
```

Or install directly from GitHub:

```bash
pip install git+https://github.com/securepickle/securepickle.git
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

`securepickle` checks the seal BEFORE opening the jar:

1. **Signs** every pickle with HMAC-SHA256
1. **Verifies** the signature before loading
1. **Refuses** to open if tampered

```python
from secure_pickle import secure_dump, secure_load

# Save (signs it)
secure_dump(data, "safe.pkl")

# Load (verifies first)
data = secure_load("safe.pkl")
```

## Modes

|Mode           |Security   |Speed    |Use Case                          |
|---------------|-----------|---------|----------------------------------|
|`mode="secure"`|HMAC-SHA256|Normal   |Default, production               |
|`mode="fast"`  |xxhash     |5x faster|Caches only (NOT attack-resistant)|
|`encrypt=True` |AES-256-GCM|Slower   |Secrets, credentials, PII         |

```python
# Fast mode - corruption detection only, NOT attack-resistant
secure_dump(data, "cache.pkl", mode="fast")

# Encrypted - requires cryptography package
secure_dump(secrets, "vault.pkl", encrypt=True)
```

## Performance

v1.2.0 uses optimized I/O patterns:

|Size     |vs Raw Pickle       |
|---------|--------------------|
|<16KB    |**Faster than raw!**|
|16-256KB |+30-40%             |
|256KB-2MB|+50-100%            |
|>2MB     |+30-50%             |

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
securepickle check data.pkl

# Migrate unsigned pickle
securepickle migrate old.pkl --output new.pkl

# Verify signature
securepickle verify data.pkl
```

## Security Notes

- **HMAC-SHA256** provides cryptographic integrity (mode=“secure”)
- **xxhash** provides fast corruption detection only (mode=“fast”)
- **AES-256-GCM** provides authenticated encryption (encrypt=True)
- Keys are auto-generated with `os.urandom(32)`
- Key files have `0600` permissions
- Signatures verified with timing-safe comparison

## Pop. Verify. Trust.

-----

Apache 2.0 License | Copyright 2025 Michael Almeida, 1001224879 Ontario Inc.

```
## Development Notes

Writing the code: 10 minutes. Getting it on GitHub and PyPI: 3+ hours.

Name was "available" but somehow later its not really because too similar to a - version. Verify Better.  The open source infrastructure is held together with duct tape and gatekeeping. If you've ever tried to publish a package, you know.

But it shipped. Pop. Verify. Trust.


## FAQ

**Q: Why not just use protobuf / JSON / msgpack?**  
A: If you can, you should. This is for when you can’t.


### Note on LLM pipelines

pickle is commonly used in LLM workflows for caching embeddings, model artifacts,
agent state, and intermediate results. These artifacts are often reused across
runs or shared between systems.

securepickle adds an integrity check to ensure those artifacts are verified before
being deserialized.


```
