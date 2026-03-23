# Technology Stack

**Analysis Date:** 2026-03-23

## Languages

**Primary:**
- Python 3.10.12 - Backend application logic, all server-side code

**Secondary:**
- HTML/Jinja2 - Frontend templates in `templates/` directory
- JavaScript - Minimal client-side interactions in templates
- CSS - Custom styling in base templates

## Runtime

**Environment:**
- Python 3.10.12 (from `.venv/pyvenv.cfg`)
- Virtual environment at `.venv/`

**Package Manager:**
- pip (Python package manager)
- requirements.txt: present with 14 dependencies

## Frameworks

**Core:**
- Flask 3.0.3 - Web application framework (`app.py:28`)

**Testing:**
- Faker 30.8.2 - Test data generation (in requirements.txt)

**Build/Dev:**
- PyInstaller - Standalone executable build (`app.spec`)
- Werkzeug (Flask dependency) - WSGI utilities, file uploads (`app.py:19`)

## Key Dependencies

**Critical:**
- flask_sqlalchemy 3.1.1 - ORM for database operations (`app.py:8`)
- flask_security 5.5.2 - Authentication and authorization (`app.py:2`)
- flask_wtf 1.2.2 - Form handling and CSRF protection (`app.py:12`)
- WTForms 3.2.1 - Form validation and rendering (`app.py:13`)

**Frontend/UI:**
- Bootstrap_Flask 2.4.1 - Bootstrap 5 integration (`app.py:11`, `templates/base.html:1`)
- Flask_CKEditor 1.0.0 - Rich text editor integration (`app.py:15`)
- Bootstrap Icons (static files in `static/css/`)

**Data Processing:**
- openpyxl 3.1.5 - Excel file generation for report downloads (`utils.py:96`)
- beautifulsoup4 4.12.3 - HTML parsing for text conversion (`utils.py:99`)
- bleach 6.2.0 - HTML sanitization for security

**Security:**
- argon2_cffi 23.1.0 - Password hashing algorithm (`app.py:5`)

**Date Handling:**
- python_dateutil 2.9.0.post0 - Date range calculations (`utils.py:4`)

## Configuration

**Environment:**
- Environment variables: `DATABASE_URL`, `SECRET_KEY`, `SECURITY_PASSWORD_SALT`, `DEFAULT_USER_PASSWORD`
- SQLite database path: `sqlite:///app.db` (configurable via `DATABASE_URL`)
- Default values hardcoded in `app.py:29-55`

**Build:**
- PyInstaller spec file: `app.spec`
- Bundles templates and static files into executable

**Application Config (`app.py:27-55`):**
- SQLAlchemy database URI with connection pooling
- Secret key for session signing
- CKEditor file upload configuration
- Flask-Security settings (password policies, username requirements)
- Max content length: 5MB for uploads

## Platform Requirements

**Development:**
- Python 3.10+
- SQLite 3.x
- Virtual environment recommended

**Production:**
- WSGI server (e.g., Gunicorn, uWSGI) for production deployment
- SQLite database file persisted in `instance/` directory
- File upload directory `uploads/` with write permissions

## Database

**Type:**
- SQLite (file-based)

**Location:**
- `instance/app.db` (110KB as of last analysis)

**Schema:**
- User accounts with roles and groups
- Weekly report records with content and dates
- Many-to-many relationships for users-groups and users-records

---

*Stack analysis: 2026-03-23*