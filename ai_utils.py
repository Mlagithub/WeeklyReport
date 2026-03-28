"""
AI utility functions for encryption and API operations.

Per SEC-01: API Key encryption using Fernet symmetric encryption.
Per CONTEXT.md D-locked: Key from AI_ENCRYPTION_KEY environment variable.
Per API-01: OpenAI-compatible POST /chat/completions
Per API-02: Chinese error messages
Per API-03: 30-second timeout
Per SEC-02: Audit logging without full content
"""

import os
import logging

import requests
from cryptography.fernet import Fernet
from flask import has_app_context, current_app
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


def call_ai_api(prompt: str, user_id: int, function_type: str, timeout: int = 30) -> tuple[bool, str | None, str | None]:
    """Call OpenAI-compatible API for AI generation.

    Per API-01: OpenAI-compatible POST /chat/completions
    Per API-02: Chinese error messages
    Per API-03: 30-second timeout

    Args:
        prompt: The user prompt to send to AI
        user_id: User ID for audit logging
        function_type: Type of AI function (summary, polish, filtered_summary)
        timeout: Request timeout in seconds (default 30)

    Returns:
        tuple: (success: bool, content: str | None, error_message: str | None)
        - (True, "AI response", None) on success
        - (False, None, "Chinese error message") on failure
    """
    from models import AIConfig

    # Log the call start
    input_length = len(prompt) if prompt else 0
    log_ai_call(user_id, function_type, input_length, "started")

    # Get AI configuration
    config = AIConfig.get_config()
    if not config:
        log_ai_call(user_id, function_type, input_length, "failure", "AI服务未配置")
        return (False, None, "AI服务未配置")

    # Decrypt API key
    try:
        api_key = decrypt_api_key(config.api_key_encrypted)
    except Exception:
        log_ai_call(user_id, function_type, input_length, "failure", "API Key解密失败")
        return (False, None, "API Key解密失败")

    # Build request
    base_url = config.api_url.rstrip("/")
    url = f"{base_url}/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": config.model_name,
        "messages": [{"role": "user", "content": prompt}]
    }

    try:
        response = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=timeout
        )

        if response.status_code == 200:
            result = response.json()
            content = result.get("choices", [{}])[0].get("message", {}).get("content")
            if content:
                log_ai_call(user_id, function_type, input_length, "success")
                return (True, content, None)
            else:
                error_msg = "API返回内容为空"
                log_ai_call(user_id, function_type, input_length, "failure", error_msg)
                return (False, None, error_msg)
        elif response.status_code == 401:
            log_ai_call(user_id, function_type, input_length, "failure", "API Key无效")
            return (False, None, "API Key无效")
        elif response.status_code == 404:
            log_ai_call(user_id, function_type, input_length, "failure", "模型名称无效或不可用")
            return (False, None, "模型名称无效或不可用")
        elif response.status_code == 429:
            log_ai_call(user_id, function_type, input_length, "failure", "请求过于频繁，请稍后再试")
            return (False, None, "请求过于频繁，请稍后再试")
        else:
            error_msg = f"服务器返回错误 {response.status_code}"
            log_ai_call(user_id, function_type, input_length, "failure", error_msg)
            return (False, None, error_msg)

    except ConnectionError:
        error_msg = "网络连接失败，请检查API URL"
        log_ai_call(user_id, function_type, input_length, "failure", error_msg)
        return (False, None, error_msg)
    except Timeout:
        error_msg = "请求超时"
        log_ai_call(user_id, function_type, input_length, "failure", error_msg)
        return (False, None, error_msg)
    except RequestException as e:
        error_msg = f"请求失败：{str(e)}"
        log_ai_call(user_id, function_type, input_length, "failure", error_msg)
        return (False, None, error_msg)
    except Exception:
        error_msg = "未知错误"
        log_ai_call(user_id, function_type, input_length, "failure", error_msg)
        return (False, None, error_msg)


def log_ai_call(user_id: int, function_type: str, input_length: int, status: str, error_message: str | None = None):
    """Log AI API call for audit without sensitive content.

    Per SEC-02: Log time, user, function type, status, without full content.

    Args:
        user_id: User who initiated the call
        function_type: Type of AI function (summary, polish, filtered_summary)
        input_length: Length of input prompt (not content)
        status: 'started', 'success', or 'failure'
        error_message: Error message if status is 'failure'
    """
    log_message = f"AI调用 [{function_type}] 用户:{user_id} 输入长度:{input_length} 状态:{status}"

    if error_message:
        log_message += f" 错误:{error_message}"

    # Try to use Flask app logger if in app context
    if has_app_context():
        if status == "failure":
            current_app.logger.warning(log_message)
        else:
            current_app.logger.info(log_message)
    else:
        # Fall back to standard logging if no Flask context
        logger = logging.getLogger(__name__)
        if status == "failure":
            logger.warning(log_message)
        else:
            logger.info(log_message)