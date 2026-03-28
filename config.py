import os

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    """Base configuration with common settings."""

    SECRET_KEY = os.environ.get("SECRET_KEY", "1pvDt-8miZXlUfTnNfEzVVTuEOLIEzKxrHMIQICS_0I")
    SECURITY_PASSWORD_SALT = os.environ.get("SECURITY_PASSWORD_SALT", "1pvDt-8miZXlUfTnNfEzVVTuEOLIEzKxrHMIQICS_0I")
    AI_ENCRYPTION_KEY = os.environ.get("AI_ENCRYPTION_KEY", "test-encryption-key-not-for-production")  # Fernet key for API encryption
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///" + os.path.join(basedir, "instance", "app.db"))
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 3600,
        "pool_size": 10,
        "max_overflow": 20,
    }
    CKEDITOR_FILE_UPLOADER = "upload"
    CKEDITOR_SERVER_LOCAL = True
    UPLOADED_PATH = os.path.join(basedir, "uploads")
    BOOTSTRAP_SERVE_LOCAL = True
    SECURITY_REGISTERABLE = False
    SECURITY_RECOVERABLE = True
    SECURITY_SEND_REGISTER_EMAIL = False
    SECURITY_USERNAME_ENABLE = True
    SECURITY_USERNAME_REQUIRED = True
    SECURITY_CHANGEABLE = True
    SECURITY_SEND_PASSWORD_RESET_EMAIL = False
    SECURITY_SEND_PASSWORD_RESET_NOTICE_EMAIL = False
    SECURITY_USERNAME_MIN_LENGTH = 2
    SECURITY_PASSWORD_LENGTH_MIN = 8
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024


class DevelopmentConfig(Config):
    """Development configuration."""

    DEBUG = True


class ProductionConfig(Config):
    """Production configuration - requires environment variables for secrets."""

    DEBUG = False
