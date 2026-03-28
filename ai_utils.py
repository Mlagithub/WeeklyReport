"""
AI utility functions for encryption and API operations.

Per SEC-01: API Key encryption using Fernet symmetric encryption.
Per CONTEXT.md D-locked: Key from AI_ENCRYPTION_KEY environment variable.
"""

import os
from cryptography.fernet import Fernet


def get_fernet_key():
    """Get Fernet key from environment variable.

    Returns:
        bytes: URL-safe base64-encoded 32-byte key

    Raises:
        ValueError: If AI_ENCRYPTION_KEY environment variable not set
    """
    key = os.environ.get("AI_ENCRYPTION_KEY")
    if not key:
        raise ValueError("AI_ENCRYPTION_KEY environment variable not set")
    return key.encode()


def get_fernet():
    """Get Fernet instance for encryption/decryption.

    Returns:
        Fernet: Initialized Fernet instance
    """
    return Fernet(get_fernet_key())


def encrypt_api_key(api_key: str) -> str:
    """Encrypt API key for storage.

    Args:
        api_key: Plain text API key

    Returns:
        str: Encrypted key as string (safe for database storage)
    """
    if not api_key:
        raise ValueError("API key cannot be empty")
    f = get_fernet()
    return f.encrypt(api_key.encode()).decode()


def decrypt_api_key(encrypted_key: str) -> str:
    """Decrypt API key for use.

    Args:
        encrypted_key: Encrypted key from database

    Returns:
        str: Decrypted plain text API key

    Raises:
        cryptography.fernet.InvalidToken: If decryption fails (wrong key)
    """
    if not encrypted_key:
        raise ValueError("Encrypted key cannot be empty")
    f = get_fernet()
    return f.decrypt(encrypted_key.encode()).decode()


def mask_api_key(api_key: str) -> str:
    """Mask API key showing only last 4 characters.

    Per CONTEXT.md D-locked: Show masked value (last 4 chars visible).

    Args:
        api_key: Plain text API key

    Returns:
        str: Masked key like '****abcd'
    """
    if not api_key:
        return ""
    if len(api_key) <= 4:
        return "****"
    return "*" * (len(api_key) - 4) + api_key[-4:]