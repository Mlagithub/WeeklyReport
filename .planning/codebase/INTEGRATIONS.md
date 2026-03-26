# External Integrations

**Analysis Date:** 2026-03-26

## Summary

A self-contained Flask web application with no external API integrations. Uses local SQLite database, file-based storage, and Flask-Security for authentication. Designed for offline deployment with all assets served locally.

## APIs & External Services

**None detected.**
The application is fully self-contained:
- No third-party API calls
- No external authentication providers (OAuth, SAML, etc.)
- No payment gateways
- No cloud services integration
- No external CDN dependencies (Bootstrap served locally)

## Data Storage

**Databases:**
- SQLite
  - Connection string: `sqlite:///instance/app.db` (default) or `DATABASE_URL` env var
  - ORM: SQLAlchemy via Flask-SQLAlchemy
  - WAL mode enabled for concurrent access (`app.py:164-174`)
  - Connection pooling: `pool_pre_ping=True`, `pool_recycle=3600`, `pool_size=10`, `max_overflow=20` (`config.py:12-17`)

**File Storage:**
- Local filesystem only
  - Upload directory: `uploads/` (`config.py:20`)
  - Served via Flask's `send_from_directory` (`routes.py:408-415`)
  - Allowed file types: jpg, gif, png, jpeg only (`routes.py:428`)
  - Max file size: 5MB total request (`config.py:32`)
  - UUID-based filenames for upload uniqueness (`routes.py:433`)

**Caching:**
- Request-level caching via Flask's `g` object for user permissions (`models.py:129-133`)

## Authentication & Identity

**Auth Provider:**
- Flask-Security (local authentication)
  - Implementation: Username/password based (`routes.py:178-192`)
  - Password hashing: argon2 via `hash_password()` and `verify_password()` (`routes.py:12`)
  - Session management: Flask-Security sessions with remember-me support

**User Model (`models.py:96-165`):**
- Fields: email, username, password, roles, groups
- Custom `is_admin` property checking role membership
- Permission system: `view_self`, `view_group`, `view_all`, `edit_database`

**Role-Based Access Control:**
- Roles stored in database with permissions array
- `employee`: view_self
- `group_leader`: view_group
- `teacher`: view_all
- `admin`: view_all, edit_database

**Password Management:**
- Minimum length: 8 characters (`config.py:31`)
- Username minimum length: 2 characters (`config.py:30`)
- Change password: `/change_password` route (`routes.py:214-225`)
- Admin password reset: `/forgot_password` route (`routes.py:200-212`)

## Frontend Integrations

**Rich Text Editor:**
- CKEditor 4 (local static files at `static/ckeditor4/`)
- Flask-CKEditor integration (`extensions.py:13`)
- File upload endpoint: `/upload` (`routes.py:417-438`)
- Image serving endpoint: `/files/<filename>` (`routes.py:408-415`)

**CSS Framework:**
- Bootstrap 5 via Bootstrap-Flask (`extensions.py:14`)
- Local serving enabled: `BOOTSTRAP_SERVE_LOCAL = True` (`config.py:21`)
- Theme switching: 24 Bootswatch themes available (`forms.py:85-112`)
- Theme stored in session (`routes.py:391-394`)

**Admin Interface:**
- Flask-Admin at `/admin` (`extensions.py:12`)
- Models exposed: User, Role, Record, Group
- Access restricted to admin role or users with `edit_database` permission (`models.py:210-215`)

## Monitoring & Observability

**Error Tracking:**
- None detected

**Logs:**
- Production logging to `/var/log/weekly/app.log` (`app.py:98-131`)
- RotatingFileHandler with 10MB max size, 10 backups
- INFO level in production
- Gunicorn access/error logs: `/var/log/weekly/gunicorn-*.log` (`gunicorn.conf.py:23-25`)

## CI/CD & Deployment

**Hosting:**
- Linux server with systemd support
- Gunicorn WSGI server with sync workers

**CI Pipeline:**
- None detected

**Deployment Artifacts:**
- `install.sh` - Offline installation script
- `weekly.service` - System-level systemd service
- `weekly-user.service` - User-level systemd service
- `gunicorn.conf.py` - Gunicorn configuration

## Webhooks & Callbacks

**Incoming:**
- None detected

**Outgoing:**
- None detected

## Import/Export Features

**Export:**
- Excel export via openpyxl (`utils.py:156-235`)
- Generates `.xlsx` files with styled headers and data
- HTML to text conversion for Excel cells (`utils.py:104-143`)
- Download endpoint: `/download_records` (`routes.py:289-319`)

**Import:**
- Initial data seeding from JSON (`static/db_table_data.json`)
- Bootstrap data for roles, groups, and initial users

## Environment Configuration

**Required env vars:**
- `SECRET_KEY` - Session signing (has hardcoded fallback - use env var in production)
- `SECURITY_PASSWORD_SALT` - Password hashing salt (has hardcoded fallback - use env var in production)
- `DATABASE_URL` - Optional, defaults to SQLite
- `PORT` - Optional, defaults to 5000
- `FLASK_DEBUG` - Optional, defaults to false

**Secrets location:**
- Default values in `config.py:9-10` (development only)
- Production requires environment variables per `install.sh:139-148`

**File System Dependencies:**
- `uploads/` - User uploaded images (created by `install.sh`)
- `instance/` - SQLite database storage
- `static/` - Frontend assets (CKEditor, Bootstrap icons, favicon)
- `logs/` - Local log files for user-level deployment

## Security Considerations

**HTML Sanitization:**
- bleach library for XSS prevention (`app.py:204-210`)
- Allowed tags: p, br, b, i, strong, em, u, ul, ol, li, a, img, h1-h6, blockquote, pre, code, table elements, span, div
- Allowed protocols: http, https, mailto

**File Upload Security:**
- UUID-based filenames prevent overwrites (`routes.py:433`)
- `secure_filename()` applied (`routes.py:413`)
- Image-only uploads enforced (`routes.py:428`)

## Related Files

- `/home/one/weekly/config.py` - Configuration and environment variables
- `/home/one/weekly/extensions.py` - Flask extension initialization
- `/home/one/weekly/models.py` - Database models and authentication
- `/home/one/weekly/routes.py` - Route handlers and business logic
- `/home/one/weekly/utils.py` - Export utilities and date handling
- `/home/one/weekly/install.sh` - Installation script with env var guidance

---

*Integration audit: 2026-03-26*