# Technology Stack

**Analysis Date:** 2026-03-26

## Summary

A Python Flask web application for weekly report management with SQLite database, Flask-Security authentication, and a rich text editor. Designed for local/server deployment with Gunicorn and systemd service management.

## Languages

**Primary:**
- Python 3.10.12 - All application logic, backend services

**Secondary:**
- HTML/Jinja2 - Template rendering (`templates/` directory)
- JavaScript - CKEditor integration, minimal client-side interactivity
- CSS - Bootstrap 5 styling with Bootswatch theme support

## Runtime

**Environment:**
- Python Virtual Environment (`.venv/`)
- Linux (WSL2 on Microsoft platform per `os-release`)
- Gunicorn WSGI server for production

**Package Manager:**
- pip - Python package installer
- Requirements file: `requirements.txt` (17 dependencies)

## Frameworks

**Core:**
- Flask 3.0.3 - Web application framework, routing, templating, request handling
- Flask-SQLAlchemy 3.1.1 - ORM for database operations
- Flask-Security 5.5.2 - Authentication and authorization
- Flask-Admin 2.0.0a2 - Admin interface for database models
- Flask-CKEditor 1.0.0 - Rich text editor integration
- Bootstrap-Flask 2.4.1 - Bootstrap 5 integration (Bootstrap5 class)

**Testing:**
- pytest 8.3.5 - Test runner and framework
- pytest-cov 5.0.0 - Code coverage plugin
- Faker 30.8.2 - Test data generation

**Production Server:**
- Gunicorn 25.1.0 - WSGI HTTP server with sync workers

## Key Dependencies

**Critical:**
- SQLAlchemy - ORM core (via Flask-SQLAlchemy)
- WTForms 3.2.1 - Form validation and rendering
- argon2_cffi 23.1.0 - Password hashing algorithm
- bleach 6.2.0 - HTML sanitization for XSS prevention
- beautifulsoup4 4.12.3 - HTML parsing for content transformation

**Data Processing:**
- openpyxl 3.1.5 - Excel file generation for report downloads
- python-dateutil 2.9.0.post0 - Date range calculations

**Frontend/UI:**
- Bootstrap 5 - CSS framework (served locally via BOOTSTRAP_SERVE_LOCAL)
- CKEditor 4 - Rich text editor (static files at `static/ckeditor4/`)
- Bootstrap Icons - Icon library

## Configuration

**Environment Variables:**
- `SECRET_KEY` - Session signing key (has fallback in `config.py:9`)
- `SECURITY_PASSWORD_SALT` - Password hashing salt (has fallback in `config.py:10`)
- `DATABASE_URL` - Database connection string (defaults to SQLite)
- `PORT` - Server port (defaults to 5000)
- `FLASK_DEBUG` - Enable debug mode (defaults to false)

**Configuration Classes (`config.py`):**
- `Config` - Base configuration with common settings
- `DevelopmentConfig` - Debug mode enabled
- `ProductionConfig` - Debug disabled, requires environment variables

**Application Settings:**
- SQLAlchemy connection pooling: `pool_pre_ping`, `pool_recycle=3600`, `pool_size=10`, `max_overflow=20`
- Max content length: 5MB for uploads
- Password minimum length: 8 characters
- Username minimum length: 2 characters

## Platform Requirements

**Development:**
- Python 3.10+
- SQLite 3.x
- Virtual environment recommended
- Run with: `python app.py` or `flask run`

**Production:**
- Linux server with systemd support
- Gunicorn WSGI server
- SQLite database with WAL mode enabled
- Log directory: `/var/log/weekly/`
- File upload directory: `uploads/` with write permissions

## Deployment

**Service Configuration:**
- `weekly.service` - System-level systemd service
- `weekly-user.service` - User-level systemd service
- `gunicorn.conf.py` - Gunicorn configuration

**Gunicorn Settings (`gunicorn.conf.py`):**
- Bind: `0.0.0.0:5000`
- Workers: `(CPU cores * 2) + 1`, capped at 4
- Worker class: sync
- Timeout: 30 seconds
- Log files: `/var/log/weekly/gunicorn-*.log`

**Installation:**
- `install.sh` - Offline installation script
- Supports `--service` flag for systemd service configuration
- Creates virtual environment and installs from `offline_packages/`

## Database

**Type:**
- SQLite (file-based) with WAL mode for concurrent access

**Location:**
- Default: `instance/app.db`
- Configurable via `DATABASE_URL` environment variable

**Schema:**
- `user` - User accounts with username, email, password
- `role` - User roles with permissions
- `group` - User groups for organization
- `record` - Weekly report records with content and dates
- Association tables: `user_records`, `roles_users`, `users_groups`

## Related Files

- `/home/one/weekly/requirements.txt` - Python dependencies
- `/home/one/weekly/config.py` - Configuration classes
- `/home/one/weekly/app.py` - Application factory and entry point
- `/home/one/weekly/gunicorn.conf.py` - Gunicorn configuration
- `/home/one/weekly/install.sh` - Installation script

---

*Stack analysis: 2026-03-26*