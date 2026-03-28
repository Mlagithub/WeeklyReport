"""
Unit tests for AI API integration layer.

Phase 15 requirements:
- API-01: System can send requests to OpenAI-compatible API endpoints
- API-02: Friendly Chinese error messages for various failure scenarios
- API-03: 30-second timeout with proper notification
- API-04: Response processing (Markdown to HTML, whitespace handling)
- SEC-02: Audit logging without full content
"""

import pytest
from unittest.mock import patch, MagicMock
from requests.exceptions import ConnectionError, Timeout

from app import app
from ai_utils import call_ai_api, log_ai_call


class TestAIAPICall:
    """Tests for call_ai_api function (API-01, API-02, API-03)."""

    def test_call_ai_api_success(self, client):
        """call_ai_api should return parsed response on successful API call.

        Expected behavior:
        - POST request to API endpoint with proper headers
        - Return tuple (success: bool, content: str | None, error: str | None)
        - Content should be processed AI-generated text (Markdown converted to HTML)
        """
        with client.application.app_context():
            # Mock AIConfig.get_config to return a valid config
            mock_config = MagicMock()
            mock_config.api_url = "https://api.example.com/v1"
            mock_config.api_key_encrypted = "encrypted_key"
            mock_config.model_name = "gpt-4"

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "choices": [{"message": {"content": "AI generated response"}}]
            }

            with patch("models.AIConfig.get_config", return_value=mock_config):
                with patch("ai_utils.decrypt_api_key", return_value="test_api_key"):
                    with patch("requests.post", return_value=mock_response):
                        success, content, error = call_ai_api(
                            prompt="Test prompt", user_id=1, function_type="summary"
                        )

            assert success is True
            # Content is processed: plain text wrapped in <p> tags
            assert content == "<p>AI generated response</p>"
            assert error is None

    def test_call_ai_api_network_error(self, client):
        """call_ai_api should return friendly Chinese message on network failure.

        Expected behavior:
        - Catch ConnectionError from requests
        - Return (False, None, "网络连接失败，请检查API URL")
        """
        with client.application.app_context():
            mock_config = MagicMock()
            mock_config.api_url = "https://api.example.com/v1"
            mock_config.api_key_encrypted = "encrypted_key"
            mock_config.model_name = "gpt-4"

            with patch("models.AIConfig.get_config", return_value=mock_config):
                with patch("ai_utils.decrypt_api_key", return_value="test_api_key"):
                    with patch("requests.post", side_effect=ConnectionError()):
                        success, content, error = call_ai_api(
                            prompt="Test prompt", user_id=1, function_type="summary"
                        )

            assert success is False
            assert content is None
            assert error == "网络连接失败，请检查API URL"

    def test_call_ai_api_auth_error(self, client):
        """call_ai_api should return friendly Chinese message on authentication failure.

        Expected behavior:
        - Handle 401 status code
        - Return (False, None, "API Key无效")
        """
        with client.application.app_context():
            mock_config = MagicMock()
            mock_config.api_url = "https://api.example.com/v1"
            mock_config.api_key_encrypted = "encrypted_key"
            mock_config.model_name = "gpt-4"

            mock_response = MagicMock()
            mock_response.status_code = 401

            with patch("models.AIConfig.get_config", return_value=mock_config):
                with patch("ai_utils.decrypt_api_key", return_value="test_api_key"):
                    with patch("requests.post", return_value=mock_response):
                        success, content, error = call_ai_api(
                            prompt="Test prompt", user_id=1, function_type="summary"
                        )

            assert success is False
            assert content is None
            assert error == "API Key无效"

    def test_call_ai_api_rate_limit(self, client):
        """call_ai_api should return friendly Chinese message on rate limit.

        Expected behavior:
        - Handle 429 status code
        - Return (False, None, "请求过于频繁，请稍后再试")
        """
        with client.application.app_context():
            mock_config = MagicMock()
            mock_config.api_url = "https://api.example.com/v1"
            mock_config.api_key_encrypted = "encrypted_key"
            mock_config.model_name = "gpt-4"

            mock_response = MagicMock()
            mock_response.status_code = 429

            with patch("models.AIConfig.get_config", return_value=mock_config):
                with patch("ai_utils.decrypt_api_key", return_value="test_api_key"):
                    with patch("requests.post", return_value=mock_response):
                        success, content, error = call_ai_api(
                            prompt="Test prompt", user_id=1, function_type="summary"
                        )

            assert success is False
            assert content is None
            assert error == "请求过于频繁，请稍后再试"

    def test_call_ai_api_model_error(self, client):
        """call_ai_api should return friendly Chinese message on invalid model.

        Expected behavior:
        - Handle 404 status code for invalid model/endpoint
        - Return (False, None, "模型名称无效或不可用")
        """
        with client.application.app_context():
            mock_config = MagicMock()
            mock_config.api_url = "https://api.example.com/v1"
            mock_config.api_key_encrypted = "encrypted_key"
            mock_config.model_name = "gpt-4"

            mock_response = MagicMock()
            mock_response.status_code = 404

            with patch("models.AIConfig.get_config", return_value=mock_config):
                with patch("ai_utils.decrypt_api_key", return_value="test_api_key"):
                    with patch("requests.post", return_value=mock_response):
                        success, content, error = call_ai_api(
                            prompt="Test prompt", user_id=1, function_type="summary"
                        )

            assert success is False
            assert content is None
            assert error == "模型名称无效或不可用"

    def test_call_ai_api_timeout(self, client):
        """call_ai_api should handle timeout gracefully.

        Expected behavior:
        - Use 30-second timeout for API calls
        - Catch Timeout exception
        - Return (False, None, "请求超时")
        """
        with client.application.app_context():
            mock_config = MagicMock()
            mock_config.api_url = "https://api.example.com/v1"
            mock_config.api_key_encrypted = "encrypted_key"
            mock_config.model_name = "gpt-4"

            with patch("models.AIConfig.get_config", return_value=mock_config):
                with patch("ai_utils.decrypt_api_key", return_value="test_api_key"):
                    with patch("requests.post", side_effect=Timeout()):
                        success, content, error = call_ai_api(
                            prompt="Test prompt", user_id=1, function_type="summary"
                        )

            assert success is False
            assert content is None
            assert error == "请求超时"

    def test_call_ai_api_missing_config(self, client):
        """call_ai_api should handle missing AI configuration gracefully.

        Expected behavior:
        - Check for AIConfig record before making API call
        - Return (False, None, "AI服务未配置") if no config exists
        """
        with client.application.app_context():
            with patch("models.AIConfig.get_config", return_value=None):
                success, content, error = call_ai_api(
                    prompt="Test prompt", user_id=1, function_type="summary"
                )

            assert success is False
            assert content is None
            assert error == "AI服务未配置"


class TestAIResponseProcessing:
    """Tests for process_ai_response function (API-04)."""

    def test_process_ai_response_strips_whitespace(self, client):
        """process_ai_response should strip leading/trailing whitespace.

        Expected behavior:
        - Input: "  Hello World  \n"
        - Output: "<p>Hello World</p>"
        """
        from ai_utils import process_ai_response

        result = process_ai_response("  Hello World  \n")
        assert result == "<p>Hello World</p>"

    def test_process_ai_response_converts_markdown_to_html(self, client):
        """process_ai_response should convert Markdown to HTML.

        Expected behavior:
        - Input: "**Bold** and *italic*"
        - Output: "<p><strong>Bold</strong> and <em>italic</em></p>"
        - Uses markdown library with safe configuration
        """
        from ai_utils import process_ai_response

        result = process_ai_response("**Bold** and *italic*")
        assert result == "<p><strong>Bold</strong> and <em>italic</em></p>"

    def test_process_ai_response_handles_plain_text(self, client):
        """process_ai_response should handle plain text without modification.

        Expected behavior:
        - Input: "Just plain text without formatting"
        - Output: "<p>Just plain text without formatting</p>"
        - Should still wrap in paragraph tag for consistency
        """
        from ai_utils import process_ai_response

        result = process_ai_response("Just plain text without formatting")
        assert result == "<p>Just plain text without formatting</p>"

    def test_process_ai_response_handles_empty_response(self, client):
        """process_ai_response should handle empty AI responses.

        Expected behavior:
        - Input: "" or None
        - Output: "" (empty string, not None)
        """
        from ai_utils import process_ai_response

        assert process_ai_response("") == ""
        assert process_ai_response(None) == ""

    def test_process_ai_response_handles_code_blocks(self, client):
        """process_ai_response should properly handle code blocks.

        Expected behavior:
        - Input: "```python\nprint('hello')\n```"
        - Output: properly formatted code block in HTML with 'extra' extension
        """
        from ai_utils import process_ai_response

        result = process_ai_response("```python\nprint('hello')\n```")
        # The 'extra' extension handles fenced code blocks
        assert "<code" in result or "<pre>" in result


class TestAIAuditLogging:
    """Tests for log_ai_call function (SEC-02)."""

    def test_log_ai_call_logs_metadata(self, client):
        """log_ai_call should log timestamp, user_id, function_type, input_length, status.

        Expected behavior:
        - Log entry contains: timestamp, user_id, function_type, input_length, status
        - Uses current_app.logger.info
        """
        with client.application.app_context():
            with patch("ai_utils.current_app") as mock_app:
                mock_app.logger.info = MagicMock()
                log_ai_call(
                    user_id=1,
                    function_type="summary",
                    input_length=100,
                    status="success"
                )
                # Verify log was called with metadata
                mock_app.logger.info.assert_called_once()
                call_args = mock_app.logger.info.call_args[0][0]
                assert "summary" in call_args
                assert "1" in call_args
                assert "100" in call_args
                assert "success" in call_args

    def test_log_ai_call_does_not_log_content(self, client):
        """log_ai_call should NOT log full prompt or response content.

        Expected behavior:
        - Log entry does NOT contain full prompt text
        - Log entry does NOT contain full response text
        - Only logs metadata (lengths, status, user)
        """
        with client.application.app_context():
            with patch("ai_utils.current_app") as mock_app:
                mock_app.logger.info = MagicMock()
                log_ai_call(
                    user_id=1,
                    function_type="summary",
                    input_length=100,
                    status="success"
                )
                # Verify log format doesn't include content
                call_args = mock_app.logger.info.call_args[0][0]
                # Should not have any "content=" or "prompt=" pattern
                assert "content=" not in call_args
                assert "prompt=" not in call_args

    def test_log_ai_call_logs_error_on_failure(self, client):
        """log_ai_call should log error message when API call fails.

        Expected behavior:
        - On failure, log entry contains error message
        - Uses current_app.logger.warning for failures
        - Still respects content exclusion (no full prompt/response)
        """
        with client.application.app_context():
            with patch("ai_utils.current_app") as mock_app:
                mock_app.logger.warning = MagicMock()
                log_ai_call(
                    user_id=1,
                    function_type="summary",
                    input_length=100,
                    status="failure",
                    error_message="API Key无效"
                )
                mock_app.logger.warning.assert_called_once()
                call_args = mock_app.logger.warning.call_args[0][0]
                assert "failure" in call_args
                assert "API Key无效" in call_args

    def test_log_ai_call_logs_function_type(self, client):
        """log_ai_call should distinguish between different AI functions.

        Expected behavior:
        - function_type parameter distinguishes: 'summary', 'polish', 'filtered_summary'
        - Log entry clearly shows which AI function was called
        """
        with client.application.app_context():
            with patch("ai_utils.current_app") as mock_app:
                mock_app.logger.info = MagicMock()
                log_ai_call(
                    user_id=1,
                    function_type="polish",
                    input_length=50,
                    status="success"
                )
                call_args = mock_app.logger.info.call_args[0][0]
                assert "polish" in call_args