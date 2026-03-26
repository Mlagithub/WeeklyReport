# Architecture

> Last updated: 2026-03-26

## Summary

A Flask-based monolithic web application for weekly report management using the Application Factory pattern with modular organization. The system follows a layered architecture with clear separation between routes, models, forms, and utilities, using SQLAlchemy ORM with SQLite for data persistence and Flask-Security for authentication.

## Pattern Overview

**Overall:** Monolithic Flask Application with Application Factory Pattern

**Key Characteristics:**
- Extension initialization pattern: Extensions defined in `extensions.py`, bound via `init_app()` in `app.py`
- Route registration pattern: Routes defined in `routes.py`, registered via `register_routes()` function
- Database transaction decorator pattern: `@with_db_transaction` for unified error handling
- Request-level caching: Permission caching on Flask's `g` object to avoid repeated queries

## Layers

### Entry Point Layer
- Purpose: Application initialization, extension binding, logging setup
- Location: `/home/one/weekly/app.py`
- Contains: `create_app()` factory, SQLAlchemy event handlers, Jinja2 filters
- Depends on: All other modules (config, extensions, models, forms, routes)
- Used by: WSGI server (Gunicorn) or direct Python execution

### Configuration Layer
- Purpose: Centralize application settings
- Location: `/home/one/weekly/config.py`
- Contains: `Config`, `DevelopmentConfig`, `ProductionConfig` classes
- Depends on: Environment variables
- Used by: Application factory in `app.py`

### Routes Layer
- Purpose: HTTP request handling, business logic orchestration
- Location: `/home/one/weekly/routes.py`
- Contains: All route handlers, permission helpers (`can_edit_record`, `get_allowed_usernames`, `get_allowed_groups`), query builders
- Depends on: models, forms, utils, extensions
- Used by: Registered with Flask app via `register_routes(app)`

### Models Layer
- Purpose: Data representation, database operations, permission logic
- Location: `/home/one/weekly/models.py`
- Contains: SQLAlchemy models (`User`, `Record`, `Role`, `Group`), association tables, `UserModelView`, `with_db_transaction` decorator
- Depends on: extensions (db), Flask-Security mixins
- Used by: routes, app

### Forms Layer
- Purpose: Input validation and form rendering
- Location: `/home/one/weekly/forms.py`
- Contains: WTForms classes (`RecordForm`, `RecordFilterForm`, `MyLoginForm`, `MyRegisterForm`, `ThemeForm`)
- Depends on: utils (DateRange), WTForms validators
- Used by: routes

### Utilities Layer
- Purpose: Shared helper functionality
- Location: `/home/one/weekly/utils.py`
- Contains: `DateRange` class for time calculations, `RecordDownloader` for Excel export, `html_to_text` conversion
- Depends on: openpyxl, BeautifulSoup, dateutil
- Used by: routes, forms

### Extension Layer
- Purpose: Flask extension initialization
- Location: `/home/one/weekly/extensions.py`
- Contains: Extension instances (`db`, `security`, `admin`, `ckeditor`, `bootstrap`)
- Depends on: Flask extension packages
- Used by: app, models, routes

## Data Flow

### Request Flow:
1. HTTP request received by WSGI server (Gunicorn)
2. Request routed to Flask application instance
3. `@app.before_request` applies user theme from session
4. Route handler invoked, validates authentication via `@login_required`
5. Form data validated via WTForms
6. Database operations via SQLAlchemy ORM
7. Response rendered via Jinja2 templates

### Record Creation Flow:
1. User submits form at `/create_records`
2. `RecordForm` validates input
3. `@with_db_transaction` wraps operation for error handling
4. `Record` model instance created and linked to `current_user`
5. Changes committed to SQLite database
6. User redirected to `/manage_records`

### Record Query Flow:
1. User accesses `/manage_records` with filter parameters
2. Default filters applied (current user, this week) if no parameters
3. `build_record_query()` constructs SQLAlchemy query with joins
4. Permission filtering via `get_allowed_usernames()` and `get_allowed_groups()`
5. Date range filtering via `DateRange.get_range()`
6. Pagination applied (5 records per page)
7. Results rendered with edit/delete action buttons

## Key Abstractions

### Permission System
- Purpose: Role-based access control with group-level permissions
- Examples: `/home/one/weekly/models.py` (User.all_permissions, User.can_view_group)
- Pattern: Permissions stored on Role model, cached per-request on `g` object

### Database Transaction Wrapper
- Purpose: Unified error handling for write operations
- Examples: `/home/one/weekly/models.py` (`with_db_transaction` decorator)
- Pattern: Try/except with rollback, logging, user-friendly flash messages

### HTML Sanitization
- Purpose: Prevent XSS while allowing rich text from CKEditor
- Examples: `/home/one/weekly/app.py` (`sanitize_html` Jinja2 filter)
- Pattern: Bleach library with whitelisted tags and attributes

## Entry Points

### WSGI Entry Point
- Location: `/home/one/weekly/app.py` (module-level `app` instance)
- Triggers: Gunicorn WSGI server
- Responsibilities: Creates application, initializes database tables, sets up logging

### Direct Execution
- Location: `/home/one/weekly/app.py` (`if __name__ == '__main__'` block)
- Triggers: `python app.py`
- Responsibilities: Development server with debug mode support

### Admin Interface
- Location: `/admin/*` routes (Flask-Admin)
- Triggers: Users with admin role or 'edit_database' permission
- Responsibilities: CRUD operations on User, Role, Record, Group models

## Error Handling

**Strategy:** Decorator-based with rollback and logging

**Patterns:**
- `@with_db_transaction` decorator catches `SQLAlchemyError`, rolls back, logs, flashes message, re-raises
- HTTP 404/403 handled via `abort()` in route handlers
- Authentication errors handled by Flask-Security

## Cross-Cutting Concerns

**Logging:** Rotating file handler at INFO level to `/var/log/weekly/app.log` (production only)

**Validation:** WTForms validators in forms.py, custom validation in route handlers

**Authentication:** Flask-Security with Argon2 password hashing, session-based auth, role/permission model

**Theme:** User theme preference stored in session, applied via `@app.before_request`

**File Uploads:** UUID-based filenames, secure_filename validation, image-only restriction

---

*Architecture analysis: 2026-03-26*