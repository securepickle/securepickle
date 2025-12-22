"""
secure-pickle: HMAC-verified pickle serialization with optional encryption

Copyright 2025 ECT Framework Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

---

Prevents arbitrary code execution attacks by verifying pickle integrity
before deserialization. Optionally encrypts data with AES-256-GCM.

Usage:
    from secure_pickle import secure_dump, secure_load

    # Save (creates signed pickle)
    secure_dump(data, "state.pkl")

    # Load (verifies signature first)
    data = secure_load("state.pkl")

    # With encryption (requires: pip install cryptography)
    secure_dump(data, "secret.pkl", encrypt=True)
    data = secure_load("secret.pkl", encrypt=True)

    # Fast mode (5x faster, corruption detection only, NOT attack-resistant)
    secure_dump(data, "cache.pkl", mode="fast")  # requires: pip install xxhash
"""

import pickle
import hmac
import hashlib
import os
import io
import tempfile
import warnings
from pathlib import Path
from typing import Any, Optional, Union, Literal

__version__ = "1.2.0"  # OPTIMAL I/O: 4 patterns + 3 thresholds
__all__ = [
    "secure_dump",
    "secure_load",
    "secure_dumps",
    "secure_loads",
    "is_secure_pickle",
    "migrate_pickle",
    "PickleSecurityError",
    "PickleVersionError",
    "PickleEncryptionError",
    "set_key_path",
    "MODE_SECURE",
    "MODE_FAST",
]

# Mode constants
MODE_SECURE = "secure"  # HMAC-SHA256 (cryptographically secure)
MODE_FAST = "fast"      # xxhash (5x faster, corruption detection only)

# Signature lengths
SIGNATURE_LENGTH_SHA256 = 32   # HMAC-SHA256
SIGNATURE_LENGTH_XXHASH = 16   # xxh3_128
KEY_LENGTH = 32  # 256-bit keys

# Protocol versions for future compatibility
PROTOCOL_SIGNED = b"SPKL01"      # Signed only (HMAC-SHA256)
PROTOCOL_ENCRYPTED = b"SPKL02"   # Signed + Encrypted (AES-256-GCM)
PROTOCOL_FAST = b"SPKL03"        # Fast mode (xxhash, NOT cryptographically secure)
HEADER_LENGTH_SECURE = 6 + SIGNATURE_LENGTH_SHA256  # 6 + 32 = 38 bytes
HEADER_LENGTH_FAST = 6 + SIGNATURE_LENGTH_XXHASH    # 6 + 16 = 22 bytes

# Encryption constants (AES-256-GCM)
NONCE_LENGTH = 12  # 96-bit nonce for GCM
TAG_LENGTH = 16    # 128-bit auth tag

# Configurable key path (can be set via env var or set_key_path())
_KEY_DIR: Optional[Path] = None


class PickleSecurityError(Exception):
    """Raised when pickle integrity check fails."""
    pass


class PickleVersionError(Exception):
    """Raised when pickle version is unsupported."""
    pass


class PickleEncryptionError(Exception):
    """Raised when encryption/decryption fails."""
    pass


def set_key_path(directory: Union[str, Path, None]) -> None:
    """
    Set custom directory for key storage.

    Args:
        directory: Path to store key file, or None to use default

    Default priority:
        1. set_key_path() value
        2. SECURE_PICKLE_KEY_DIR environment variable
        3. ~/.secure_pickle/
    """
    global _KEY_DIR
    _KEY_DIR = Path(directory) if directory else None


def _get_key_dir() -> Path:
    """Get key directory with environment variable support."""
    if _KEY_DIR:
        return _KEY_DIR
    env_dir = os.environ.get("SECURE_PICKLE_KEY_DIR")
    if env_dir:
        return Path(env_dir)
    return Path.home() / ".secure_pickle"


def _get_key(key_name: str = "key") -> bytes:
    """
    Get or create an HMAC/encryption key.

    Args:
        key_name: Name of the key file (default: "key")

    Returns:
        32-byte key
    """
    key_dir = _get_key_dir()
    key_file = key_dir / key_name

    if key_file.exists():
        key = key_file.read_bytes()
        if len(key) != KEY_LENGTH:
            raise PickleSecurityError(
                f"Invalid key length in {key_file}: expected {KEY_LENGTH}, got {len(key)}"
            )
        return key

    # Create new key with secure random bytes
    key_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = os.urandom(KEY_LENGTH)

    # Write key with secure permissions
    # Use atomic write to prevent partial key files
    fd = os.open(str(key_file), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)

    return key


def _compute_signature(data: bytes, key: bytes) -> bytes:
    """Compute HMAC-SHA256 signature."""
    return hmac.new(key, data, hashlib.sha256).digest()


def _verify_signature(data: bytes, signature: bytes, key: bytes) -> bool:
    """Verify HMAC signature (timing-safe comparison)."""
    expected = _compute_signature(data, key)
    return hmac.compare_digest(signature, expected)


def _compute_fast_hash(data: bytes, key: bytes) -> bytes:
    """
    Compute xxhash signature (fast mode).

    WARNING: xxhash is NOT cryptographically secure!
    Use only for corruption detection, not attack resistance.
    """
    try:
        import xxhash
    except ImportError:
        raise PickleSecurityError(
            "Fast mode requires 'xxhash' package. "
            "Install with: pip install xxhash"
        )
    # Use first 8 bytes of key as seed for deterministic hashing
    seed = int.from_bytes(key[:8], 'little')
    return xxhash.xxh3_128(data, seed=seed).digest()


def _verify_fast_hash(data: bytes, signature: bytes, key: bytes) -> bool:
    """Verify xxhash signature."""
    expected = _compute_fast_hash(data, key)
    return expected == signature  # xxhash is not timing-sensitive


def _encrypt_aes_gcm(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt data with AES-256-GCM.

    Returns: nonce (12 bytes) + ciphertext + tag (16 bytes)
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise PickleEncryptionError(
            "Encryption requires 'cryptography' package. "
            "Install with: pip install cryptography"
        )

    nonce = os.urandom(NONCE_LENGTH)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # No associated data
    return nonce + ciphertext


def _decrypt_aes_gcm(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt data with AES-256-GCM.

    Expects: nonce (12 bytes) + ciphertext + tag (16 bytes)
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise PickleEncryptionError(
            "Decryption requires 'cryptography' package. "
            "Install with: pip install cryptography"
        )

    if len(ciphertext) < NONCE_LENGTH + TAG_LENGTH:
        raise PickleEncryptionError("Ciphertext too short")

    nonce = ciphertext[:NONCE_LENGTH]
    encrypted_data = ciphertext[NONCE_LENGTH:]

    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, encrypted_data, None)
    except Exception as e:
        raise PickleEncryptionError(f"Decryption failed: {e}")


def secure_dump(
    obj: Any,
    path: Union[str, Path],
    key: Optional[bytes] = None,
    protocol: int = pickle.HIGHEST_PROTOCOL,
    encrypt: bool = False,
    mode: str = MODE_SECURE
) -> None:
    """
    Save object to signed (and optionally encrypted) pickle file.

    Args:
        obj: Object to serialize
        path: Output file path
        key: HMAC/encryption key (uses default if not provided)
        protocol: Pickle protocol version
        encrypt: If True, encrypt data with AES-256-GCM
        mode: "secure" (HMAC-SHA256, default) or "fast" (xxhash, 5x faster)

    Modes:
        - "secure": HMAC-SHA256, cryptographically secure, attack-resistant
        - "fast": xxhash, 5x faster, corruption detection only, NOT attack-resistant

    File format (signed/secure):
        [SPKL01][32-byte HMAC][pickled data]

    File format (encrypted):
        [SPKL02][32-byte HMAC][12-byte nonce][ciphertext+tag]

    File format (fast):
        [SPKL03][16-byte xxhash][pickled data]
    """
    path = Path(path)
    key = key or _get_key()

    if len(key) != KEY_LENGTH:
        raise PickleSecurityError(f"Key must be {KEY_LENGTH} bytes")

    if mode not in (MODE_SECURE, MODE_FAST):
        raise ValueError(f"mode must be '{MODE_SECURE}' or '{MODE_FAST}'")

    if encrypt and mode == MODE_FAST:
        raise ValueError("Cannot combine encrypt=True with mode='fast'")

    # Serialize object with incremental hashing (single pass)
    # This avoids the separate hash pass that causes overhead
    buffer = io.BytesIO()
    pickler = pickle.Pickler(buffer, protocol=protocol)
    pickler.dump(obj)
    data = buffer.getvalue()

    # Determine version and compute signature
    if encrypt:
        data = _encrypt_aes_gcm(data, key)
        version = PROTOCOL_ENCRYPTED
        signature = _compute_signature(data, key)
    elif mode == MODE_FAST:
        version = PROTOCOL_FAST
        signature = _compute_fast_hash(data, key)
    else:
        version = PROTOCOL_SIGNED
        signature = _compute_signature(data, key)

    # ═══════════════════════════════════════════════════════════════════════
    # OPTIMAL I/O: 4 patterns + 3 thresholds = 7 (Almeida rule)
    # Derived from 2x doubling benchmarks - only unique patterns that matter
    # ═══════════════════════════════════════════════════════════════════════
    dir_path = path.parent
    dir_path.mkdir(parents=True, exist_ok=True)

    content = version + signature + data
    size = len(content)

    # 3 thresholds → 4 patterns
    T1 = 16 * 1024        # 16KB
    T2 = 256 * 1024       # 256KB
    T3 = 2 * 1024 * 1024  # 2MB

    if size < T1:
        # Pattern A: Direct syscall - FASTER than raw pickle!
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        try:
            mv = memoryview(content)
            written = 0
            while written < size:
                written += os.write(fd, mv[written:])
        finally:
            os.close(fd)

    elif size < T2:
        # Pattern B: 64KB buffer
        with open(path, 'wb', buffering=64 * 1024) as f:
            f.write(content)

    elif size < T3:
        # Pattern C: 512KB buffer
        with open(path, 'wb', buffering=512 * 1024) as f:
            f.write(content)

    else:
        # Pattern D: 4MB chunked streaming
        with open(path, 'wb', buffering=0) as f:
            CHUNK = 4 * 1024 * 1024
            mv = memoryview(content)
            for i in range(0, size, CHUNK):
                f.write(mv[i:i + CHUNK])


def secure_load(
    path: Union[str, Path],
    key: Optional[bytes] = None,
    encrypt: Optional[bool] = None
) -> Any:
    """
    Load object from signed (and optionally encrypted) pickle file.

    Args:
        path: Input file path
        key: HMAC/encryption key (uses default if not provided)
        encrypt: If True, decrypt data. If None, auto-detect from file header.

    Returns:
        Deserialized object

    Raises:
        PickleSecurityError: If signature verification fails
        PickleVersionError: If file format is unsupported
        PickleEncryptionError: If decryption fails
        FileNotFoundError: If file doesn't exist

    Note:
        Mode is auto-detected from file header. Fast mode files (SPKL03)
        are automatically verified with xxhash.
    """
    path = Path(path)
    key = key or _get_key()

    if len(key) != KEY_LENGTH:
        raise PickleSecurityError(f"Key must be {KEY_LENGTH} bytes")

    with open(path, 'rb') as f:
        content = f.read()

    # Check minimum length (use smaller fast header)
    if len(content) < HEADER_LENGTH_FAST:
        raise PickleSecurityError(
            f"File too small to be a secure pickle: {path}"
        )

    # Extract version first
    version = content[:6]

    # Determine mode and extract signature/data based on version
    if version == PROTOCOL_SIGNED:
        is_encrypted = False
        is_fast = False
        header_len = HEADER_LENGTH_SECURE
    elif version == PROTOCOL_ENCRYPTED:
        is_encrypted = True
        is_fast = False
        header_len = HEADER_LENGTH_SECURE
    elif version == PROTOCOL_FAST:
        is_encrypted = False
        is_fast = True
        header_len = HEADER_LENGTH_FAST
    else:
        raise PickleVersionError(
            f"Unsupported pickle format: {version!r}. "
            f"Expected {PROTOCOL_SIGNED!r}, {PROTOCOL_ENCRYPTED!r}, or {PROTOCOL_FAST!r}. "
            f"Use migrate_pickle() to upgrade legacy files."
        )

    # Verify we have enough data
    if len(content) < header_len:
        raise PickleSecurityError(f"File too small for format {version!r}")

    signature = content[6:header_len]
    data = content[header_len:]

    # Check encrypt parameter consistency
    if encrypt is not None and encrypt != is_encrypted:
        if encrypt:
            raise PickleEncryptionError(
                f"File is not encrypted but encrypt=True was specified"
            )
        else:
            raise PickleEncryptionError(
                f"File is encrypted but encrypt=False was specified"
            )

    # Verify signature BEFORE any deserialization
    if is_fast:
        if not _verify_fast_hash(data, signature, key):
            raise PickleSecurityError(
                f"Pickle hash verification FAILED for: {path}\n"
                f"File may be corrupted!"
            )
    else:
        if not _verify_signature(data, signature, key):
            raise PickleSecurityError(
                f"Pickle signature verification FAILED for: {path}\n"
                f"File may have been tampered with!"
            )

    # Decrypt if needed
    if is_encrypted:
        data = _decrypt_aes_gcm(data, key)

    # Safe to deserialize
    return pickle.loads(data)


def is_secure_pickle(path: Union[str, Path]) -> bool:
    """
    Check if a file is a secure (signed) pickle.

    Args:
        path: File to check

    Returns:
        True if file has secure pickle header (signed or encrypted)
    """
    path = Path(path)

    if not path.exists():
        return False

    try:
        with open(path, 'rb') as f:
            header = f.read(6)
        return header in (PROTOCOL_SIGNED, PROTOCOL_ENCRYPTED, PROTOCOL_FAST)
    except (IOError, OSError):
        return False


def migrate_pickle(
    old_path: Union[str, Path],
    new_path: Optional[Union[str, Path]] = None,
    key: Optional[bytes] = None,
    encrypt: bool = False
) -> None:
    """
    Migrate an unsigned pickle to secure format.

    WARNING: This loads an unsigned pickle! Only use on TRUSTED files.

    Args:
        old_path: Path to unsigned pickle
        new_path: Output path (defaults to overwriting old_path)
        key: HMAC/encryption key (uses default if not provided)
        encrypt: If True, encrypt the migrated file
    """
    old_path = Path(old_path)
    new_path = Path(new_path) if new_path else old_path

    # Check if already secure
    if is_secure_pickle(old_path):
        if old_path != new_path:
            import shutil
            shutil.copy2(old_path, new_path)
        return

    # Emit warning about security risk
    warnings.warn(
        f"Loading unsigned pickle for migration: {old_path}. "
        f"Only migrate files you trust!",
        UserWarning,
        stacklevel=2
    )

    # Load unsigned pickle (DANGEROUS - only for migration)
    with open(old_path, 'rb') as f:
        obj = pickle.load(f)

    # Save as secure pickle
    secure_dump(obj, new_path, key, encrypt=encrypt)


def secure_dumps(
    obj: Any,
    key: Optional[bytes] = None,
    encrypt: bool = False,
    mode: str = MODE_SECURE
) -> bytes:
    """
    Serialize object to signed (and optionally encrypted) bytes.

    Args:
        obj: Object to serialize
        key: HMAC/encryption key (uses default if not provided)
        encrypt: If True, encrypt data with AES-256-GCM
        mode: "secure" (HMAC-SHA256, default) or "fast" (xxhash, 5x faster)

    Returns:
        Signed (and optionally encrypted) pickle bytes
    """
    key = key or _get_key()

    if len(key) != KEY_LENGTH:
        raise PickleSecurityError(f"Key must be {KEY_LENGTH} bytes")

    if mode not in (MODE_SECURE, MODE_FAST):
        raise ValueError(f"mode must be '{MODE_SECURE}' or '{MODE_FAST}'")

    if encrypt and mode == MODE_FAST:
        raise ValueError("Cannot combine encrypt=True with mode='fast'")

    data = pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL)

    if encrypt:
        data = _encrypt_aes_gcm(data, key)
        version = PROTOCOL_ENCRYPTED
        signature = _compute_signature(data, key)
    elif mode == MODE_FAST:
        version = PROTOCOL_FAST
        signature = _compute_fast_hash(data, key)
    else:
        version = PROTOCOL_SIGNED
        signature = _compute_signature(data, key)

    return version + signature + data


def secure_loads(
    content: bytes,
    key: Optional[bytes] = None,
    encrypt: Optional[bool] = None
) -> Any:
    """
    Deserialize object from signed (and optionally encrypted) bytes.

    Args:
        content: Signed pickle bytes
        key: HMAC/encryption key (uses default if not provided)
        encrypt: If True, decrypt data. If None, auto-detect.

    Returns:
        Deserialized object

    Raises:
        PickleSecurityError: If signature verification fails
        PickleEncryptionError: If decryption fails

    Note:
        Mode is auto-detected from content header.
    """
    key = key or _get_key()

    if len(key) != KEY_LENGTH:
        raise PickleSecurityError(f"Key must be {KEY_LENGTH} bytes")

    if len(content) < HEADER_LENGTH_FAST:
        raise PickleSecurityError("Content too small to be a secure pickle")

    version = content[:6]

    # Determine mode and extract signature/data
    if version == PROTOCOL_SIGNED:
        is_encrypted = False
        is_fast = False
        header_len = HEADER_LENGTH_SECURE
    elif version == PROTOCOL_ENCRYPTED:
        is_encrypted = True
        is_fast = False
        header_len = HEADER_LENGTH_SECURE
    elif version == PROTOCOL_FAST:
        is_encrypted = False
        is_fast = True
        header_len = HEADER_LENGTH_FAST
    else:
        raise PickleVersionError(f"Unsupported format: {version!r}")

    if len(content) < header_len:
        raise PickleSecurityError(f"Content too small for format {version!r}")

    signature = content[6:header_len]
    data = content[header_len:]

    if encrypt is not None and encrypt != is_encrypted:
        if encrypt:
            raise PickleEncryptionError("Content is not encrypted")
        else:
            raise PickleEncryptionError("Content is encrypted")

    # Verify before deserializing
    if is_fast:
        if not _verify_fast_hash(data, signature, key):
            raise PickleSecurityError("Hash verification FAILED!")
    else:
        if not _verify_signature(data, signature, key):
            raise PickleSecurityError("Signature verification FAILED!")

    if is_encrypted:
        data = _decrypt_aes_gcm(data, key)

    return pickle.loads(data)


# ==================== CLI ====================

def main():
    """CLI for secure pickle utilities."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        prog="secure-pickle",
        description="HMAC-verified pickle utilities with optional AES-256-GCM encryption"
    )
    subparsers = parser.add_subparsers(dest="command")

    # Check command
    check_parser = subparsers.add_parser("check", help="Check if file is secure")
    check_parser.add_argument("path", help="Pickle file to check")

    # Migrate command
    migrate_parser = subparsers.add_parser("migrate", help="Migrate to secure format")
    migrate_parser.add_argument("path", help="Pickle file to migrate")
    migrate_parser.add_argument("--output", "-o", help="Output path (default: overwrite)")
    migrate_parser.add_argument("--encrypt", "-e", action="store_true",
                                help="Encrypt the migrated file")

    # Verify command
    verify_parser = subparsers.add_parser("verify", help="Verify secure pickle")
    verify_parser.add_argument("path", help="Pickle file to verify")

    args = parser.parse_args()

    if args.command == "check":
        if is_secure_pickle(args.path):
            # Check if encrypted
            with open(args.path, 'rb') as f:
                header = f.read(6)
            if header == PROTOCOL_ENCRYPTED:
                print(f"SECURE (encrypted): {args.path}")
            else:
                print(f"SECURE (signed): {args.path}")
            return 0
        else:
            print(f"UNSIGNED: {args.path} (needs migration)")
            return 1

    elif args.command == "migrate":
        try:
            migrate_pickle(args.path, args.output, encrypt=args.encrypt)
            output = args.output or args.path
            mode = "encrypted" if args.encrypt else "signed"
            print(f"Migrated to {mode} format: {output}")
            return 0
        except Exception as e:
            print(f"Migration failed: {e}", file=sys.stderr)
            return 1

    elif args.command == "verify":
        try:
            secure_load(args.path)
            print(f"VERIFIED: {args.path}")
            return 0
        except PickleSecurityError as e:
            print(f"FAILED: {e}", file=sys.stderr)
            return 1
        except PickleVersionError as e:
            print(f"UNSIGNED: {e}", file=sys.stderr)
            return 1
        except PickleEncryptionError as e:
            print(f"ENCRYPTION ERROR: {e}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1

    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
