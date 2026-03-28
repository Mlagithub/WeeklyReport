"""
AI utility functions for encryption and API operations.

Per SEC-01: API Key encryption using Fernet symmetric encryption.
Per CONTEXT.md D-locked: Key from AI_ENCRYPTION_KEY environment variable.
"""

import os

import requests
from cryptography.fernet import Fernet
from requests.exceptions import ConnectionError, RequestException, Timeout


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


def test_ai_connection(api_url: str, api_key: str, timeout: int = 30):
    """Test connection to AI API endpoint.

    Per CONFIG-02: Verify AI service availability.
    Per RESEARCH.md: Use GET /models endpoint (lightweight, no token consumption).

    Args:
        api_url: Base API URL (e.g., 'https://api.openai.com/v1')
        api_key: Plain text API key for authentication
        timeout: Request timeout in seconds (default 30)

    Returns:
        tuple: (success: bool, message: str)
        - (True, "连接成功") on successful connection
        - (False, "连接失败：{具体错误信息}") on failure with Chinese error
    """
    if not api_url or not api_key:
        return (False, "连接失败：API URL或API Key未配置")

    # Ensure URL ends without trailing slash for consistent path joining
    base_url = api_url.rstrip("/")
    models_url = f"{base_url}/models"

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.get(
            models_url,
            headers=headers,
            timeout=timeout
        )

        if response.status_code == 200:
            return (True, "连接成功")
        elif response.status_code == 401:
            return (False, "连接失败：API Key无效")
        elif response.status_code == 404:
            return (False, "连接失败：API URL不正确")
        elif response.status_code == 429:
            return (False, "连接失败：请求过于频繁，请稍后再试")
        else:
            return (False, f"连接失败：服务器返回错误 {response.status_code}")

    except ConnectionError:
        return (False, "连接失败：网络连接失败，请检查API URL")
    except Timeout:
        return (False, "连接失败：请求超时，请检查网络或API服务状态")
    except RequestException as e:
        return (False, f"连接失败：{str(e)}")
    except Exception:
        return (False, "连接失败：未知错误")