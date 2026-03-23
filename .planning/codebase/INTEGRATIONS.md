# External Integrations

**Analysis Date:** 2026-03-23

## APIs & External Services

**None detected.**
The application is self-contained with no external API integrations. All functionality is local:
- No third-party API calls
- No external authentication providers
- No payment gateways
- No cloud services integration

## Data Storage

**Databases:**
- SQLite
  - Connection: `sqlite:///app.db` (`app.py:29`)
  - ORM: SQLAlchemy via Flask-SQLAlchemy
  - Database file: `instance/app.db`
  - Connection pooling: Enabled with `pool_pre_ping`, `pool_recycle=3600` (`app.py:31-36`)

**File Storage:**
- Local filesystem only
  - Upload directory: `uploads/` (`app.py:41`)
  - Served via Flask's `send_from_directory` (`app.py:654-661`)
  - Allowed file types: jpg, gif, png, jpeg only (`app.py:671`)
  - Max file size: 5MB total request (`app.py:55`)

**Caching:**
- Request-level caching via Flask's `g` object for user permissions (`app.py:128-132`)

## Authentication & Identity

**Auth Provider:**
- Flask-Security (local authentication)
  - Implementation: Username/password based (`app.py:431-461`)
  - Password hashing: argon2 via `hash_password()` and `verify_password()` (`app.py:5`)
  - Session management: Flask-Security sessions with remember-me support

**User Model (`app.py:98-161`):**
- Fields: email, username, password, roles, groups
- Custom `is_admin` property checking role membership
- Permission system: `view_self`, `view_group`, `view_all`, `edit_database`

**Role-Based Access Control:**
- Roles defined in `static/db_table_data.json`:
  - `employee`: view_self
  - `group_leader`: view_group
  - `teacher`: view_all
  - `admin`: view_all, edit_database

**Password Management:**
- Minimum length: 8 characters (`app.py:54`)
- Username minimum length: 2 characters (`app.py:53`)
- Change password: via Flask-Security's ChangePasswordForm (`app.py:463-474`)
- Admin password reset: custom route at `/forgot_password` (`app.py:449-461`)

## Frontend Integrations

**Rich Text Editor:**
- CKEditor 4 (local static files at `static/ckeditor4/`)
- Flask-CKEditor integration (`app.py:15, 251`)
- File upload endpoint: `/upload` (`app.py:664-680`)
- Image serving endpoint: `/files/<filename>` (`app.py:654-661`)

**CSS Framework:**
- Bootstrap 5 via Bootstrap-Flask (`app.py:11, 248`)
- Theme switching: 24 Bootswatch themes available (`app.py:280-308`)
- Bootstrap Icons (local at `static/css/`)

**Admin Interface:**
- Flask-Admin at `/admin` (`app.py:16-18, 209-213`)
- Models exposed: User, Role, Record, Group
- Access restricted to admin role or users with `edit_database` permission

## Monitoring & Observability

**Error Tracking:**
- None detected

**Logs:**
- Flask's built-in development server logging
- No production logging configuration detected

## CI/CD & Deployment

**Hosting:**
- Not configured - designed for local/server deployment
- Can be packaged as standalone executable via PyInstaller (`app.spec`)

**CI Pipeline:**
- None detected

**Deployment Artifacts:**
- PyInstaller build configuration at `app.spec`
- Build and dist directories present (`build/`, `dist/`)

## Webhooks & Callbacks

**Incoming:**
- None detected

**Outgoing:**
- None detected

## Import/Export Features

**Export:**
- Excel export via openpyxl (`utils.py:154-233`)
- Generates `.xlsx` files with styled headers and data
- HTML to text conversion for Excel cells (`utils.py:102-141`)

**Import:**
- Initial data seeding from JSON (`static/db_table_data.json`)
- Populates roles, groups, and users on first run (`app.py:683-739`)

## Environment Configuration

**Required env vars:**
- `DATABASE_URL` (optional, defaults to SQLite)
- `SECRET_KEY` (has hardcoded fallback - should use env var in production)
- `SECURITY_PASSWORD_SALT` (has hardcoded fallback - should use env var in production)
- `DEFAULT_USER_PASSWORD` (optional, defaults to "12345678")

**Secrets location:**
- Currently hardcoded in source (`app.py:37, 44`) - SECURITY CONCERN
- Comment shows intent to use environment variables in production

**File System Dependencies:**
- `uploads/` - User uploaded images
- `instance/` - SQLite database storage
- `static/` - Frontend assets (CKEditor, Bootstrap icons, favicon)

---

*Integration audit: 2026-03-23*