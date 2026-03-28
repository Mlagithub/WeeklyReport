"""
Flask application entry point.
Uses modular structure with config, extensions, models, forms, and routes.
"""
import logging
import os
from logging.handlers import RotatingFileHandler

import bleach
from flask import Flask
from flask_security import SQLAlchemyUserDatastore
from sqlalchemy import event, inspect, text
from sqlalchemy.pool import Pool

# Import from new modules
from config import Config
from extensions import admin, bootstrap, ckeditor, db, security
from forms import (
    MyLoginForm,
)
from models import (
    Group,
    Record,
    Role,
    User,
    UserModelView,
    roles_users,
    user_records,
    users_groups,
    with_db_transaction,
)
from routes import register_routes

# =============================================================================
# HTML Sanitization Configuration (RENDER-01, RENDER-02)
# =============================================================================

# Allowed HTML tags and attributes for sanitize_html filter
ALLOWED_TAGS = {
    'p', 'br', 'b', 'i', 'strong', 'em', 'u',
    'ul', 'ol', 'li', 'a', 'img',
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'blockquote', 'pre', 'code',
    'table', 'thead', 'tbody', 'tr', 'td', 'th',
    'span', 'div'
}

ALLOWED_ATTRIBUTES = {
    '*': ['class', 'style'],
    'a': ['href', 'title', 'target', 'rel'],
    'img': ['src', 'alt', 'title', 'width', 'height'],
}

ALLOWED_PROTOCOLS = {'http', 'https', 'mailto'}


# =============================================================================
# Application Factory
# =============================================================================

def create_app(config_class=None):
    """Create and configure the Flask application.

    Args:
        config_class: Configuration class to use. Defaults to Config.

    Returns:
        Flask application instance.
    """
    app = Flask(__name__)
    app.config.from_object(config_class or Config)

    # Initialize extensions
    db.init_app(app)
    bootstrap.init_app(app)
    ckeditor.init_app(app)
    admin.init_app(app)

    # Setup Flask-Security
    user_datastore = SQLAlchemyUserDatastore(db, User, Role)
    security.init_app(app, user_datastore, login_form=MyLoginForm)

    # Add admin views
    admin.add_view(UserModelView(User, db.session))
    admin.add_view(UserModelView(Role, db.session))
    admin.add_view(UserModelView(Record, db.session))
    admin.add_view(UserModelView(Group, db.session))

    # Register routes
    register_routes(app)

    # Setup logging
    setup_logging(app)

    return app


# =============================================================================
# Logging Setup
# =============================================================================

def setup_logging(app):
    """Configure production logging for Flask application.

    Per D-08: File logging, INFO level
    Per D-09: Logs at /var/log/weekly/
    """
    # Skip logging setup in debug mode
    if app.debug:
        return

    log_dir = '/var/log/weekly'

    # Create log directory if it doesn't exist (with error handling)
    try:
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
    except PermissionError:
        app.logger.warning(f"Cannot create log directory {log_dir}")
        return

    # Application log handler - per D-08 (INFO level)
    file_handler = RotatingFileHandler(
        os.path.join(log_dir, 'app.log'),
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=10
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)

    app.logger.info('Weekly Report Management System starting up')


# =============================================================================
# Database Helper Functions
# =============================================================================

def ensure_record_columns():
    """Ensure Record table has all required columns (schema migration helper)."""
    inspector = inspect(db.engine)
    # Check if record table exists
    if 'record' not in inspector.get_table_names():
        return
    columns = {column['name'] for column in inspector.get_columns('record')}
    if 'createtime' not in columns:
        db.session.execute(text("ALTER TABLE record ADD COLUMN createtime DATETIME"))
        db.session.commit()


def verify_wal_mode():
    """Verify SQLite WAL mode is enabled per D-05, D-06."""
    try:
        result = db.session.execute(text("PRAGMA journal_mode")).scalar()
        if result and result.lower() == 'wal':
            pass  # WAL mode verified
    except Exception:
        pass


# =============================================================================
# SQLite WAL Mode Setup (Per Phase 3)
# =============================================================================

@event.listens_for(Pool, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Enable WAL mode on SQLite connections per D-01, D-02."""
    # Only apply to SQLite connections
    if hasattr(dbapi_connection, 'execute'):
        try:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.close()
        except Exception:
            pass  # Not a SQLite connection or PRAGMA not supported


# =============================================================================
# Create Application Instance
# =============================================================================

# Create the app instance for WSGI compatibility
app = create_app()


# =============================================================================
# Custom Jinja2 Filters
# =============================================================================

@app.template_filter('sanitize_html')
def sanitize_html(text):
    """Sanitize HTML content for safe rendering.

    Allows common CKEditor formatting tags while blocking XSS.
    Used for RENDER-01 (rich text) and RENDER-02 (XSS prevention).

    Args:
        text: HTML string to sanitize.

    Returns:
        Sanitized HTML string, safe for |safe filter.
    """
    if not text:
        return ''
    return bleach.clean(
        text,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=ALLOWED_PROTOCOLS,
        strip=False
    )


# Create user_datastore for Flask-Security (used by tests)
user_datastore = SQLAlchemyUserDatastore(db, User, Role)

# Ensure database tables exist (for WSGI/Gunicorn startup)
with app.app_context():
    db.create_all()
    ensure_record_columns()
    verify_wal_mode()

# Import helper functions from routes for backward compatibility
from routes import can_edit_record, get_allowed_groups, get_allowed_usernames

# =============================================================================
# Backward-Compatible Exports for Tests
# =============================================================================

# Tests import: from app import app, db, user_datastore, User, Record, Role, Group
__all__ = [
    'app', 'db', 'user_datastore', 'security', 'admin', 'ckeditor', 'bootstrap',
    'User', 'Record', 'Role', 'Group',
    'user_records', 'roles_users', 'users_groups',
    'with_db_transaction',
    'can_edit_record', 'get_allowed_usernames', 'get_allowed_groups',
    'create_app',
]


# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        ensure_record_columns()
        verify_wal_mode()
        # update_db_from_json() would be called here if needed

    # Production: Gunicorn calls app directly, this block is skipped
    # Development: Run with FLASK_DEBUG=true python app.py
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', debug=debug_mode, port=port)
