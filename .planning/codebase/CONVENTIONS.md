# Coding Conventions

**Analysis Date:** 2026-03-26

## Summary

This Flask application follows Python PEP 8 conventions with Chinese comments for business logic. Code is organized into modular files (`app.py`, `models.py`, `routes.py`, `forms.py`, `utils.py`, `config.py`, `extensions.py`) with clear separation of concerns. No formal linter/formatter configuration exists; style is maintained through consistency.

## Naming Patterns

**Files:**
- Python modules use snake_case: `app.py`, `utils.py`, `forms.py`, `routes.py`
- Template files use snake_case with `.html` extension: `create_records.html`, `manage_records.html`
- Test files follow pytest convention: `test_models.py`, `test_routes.py`, `test_utils.py`

**Functions:**
- Route handlers use snake_case: `create_records()`, `manage_records()`, `download_records()`
- Helper/utility functions use snake_case: `get_allowed_groups()`, `build_record_query()`, `can_edit_record()`
- Static methods on classes use snake_case: `DateRange.this_week()`, `User.all_permissions()`

**Variables:**
- Local variables use snake_case: `user_weekly_data`, `start_date`, `end_date`
- Flask-Security's `current_user` is accessed directly
- Database table association variables use plural: `user_records`, `roles_users`, `users_groups`

**Classes:**
- Models use PascalCase: `User`, `Record`, `Role`, `Group`
- Form classes use PascalCase with "Form" suffix: `RecordForm`, `RecordFilterForm`, `ThemeForm`
- View classes use PascalCase with "View" suffix: `UserModelView`
- Utility classes use PascalCase: `DateRange`, `RecordDownloader`
- Test classes use PascalCase with "Test" prefix: `TestUserPermissions`, `TestDateRange`

**Constants:**
- Module-level constants use SCREAMING_SNAKE_CASE: `ALLOWED_TAGS`, `ALLOWED_ATTRIBUTES`, `ALLOWED_PROTOCOLS`
- Class-level constants use SCREAMING_SNAKE_CASE: `DateRange.TIME_RANGES`

## Code Style

**Formatting:**
- No explicit formatter configuration (no `.prettierrc`, `pyproject.toml`, or `.editorconfig`)
- 4-space indentation (Python standard)
- Lines typically under 100 characters
- UTF-8 encoding declared at top of files: `# -*- coding: utf-8 -*-`

**Linting:**
- No explicit linter configuration (no `flake8`, `ruff`, or `pylint` config)
- Code follows PEP 8 style implicitly
- Test configuration in `pytest.ini` with `-v --tb=short` options

**Docstrings:**
- Module-level docstrings describe purpose: `"""Flask application entry point..."""`
- Function docstrings use triple quotes with Args/Returns sections
- Example from `/home/one/weekly/app.py`:
```python
def create_app(config_class=None):
    """Create and configure the Flask application.

    Args:
        config_class: Configuration class to use. Defaults to Config.

    Returns:
        Flask application instance.
    """
```

## Import Organization

**Order:**
1. Standard library imports (`os`, `logging`, `uuid`, `datetime`)
2. Third-party packages (Flask, SQLAlchemy, etc.)
3. Local application imports

**Example from `/home/one/weekly/routes.py`:**
```python
from flask import render_template, redirect, flash, url_for, request, send_from_directory, abort, session, g, current_app
from flask_security import login_required, login_user, logout_user, current_user
from flask_security.utils import hash_password, verify_password
from werkzeug.utils import secure_filename
from sqlalchemy import func, case, and_
from sqlalchemy.orm import joinedload
import uuid
import os
from datetime import datetime

from extensions import db, security, admin, ckeditor
from models import User, Record, Role, Group, user_records, roles_users, users_groups, with_db_transaction
from forms import RecordFilterForm, RecordDownloadForm, ThemeForm, MyLoginForm, MyRegisterForm
from utils import DateRange, RecordDownloader
```

**Path Aliases:**
- None used; all imports use full module paths

**Inline Imports:**
- Used for functionality that requires app context: `from flask_ckeditor import CKEditorField, upload_fail, upload_success`

## Error Handling

**HTTP Errors:**
- Use `abort()` for HTTP error responses: `abort(404)`, `abort(403)`
- Example from `/home/one/weekly/routes.py`:
```python
if not record:
    abort(404)
if not can_edit_record(record, current_user):
    abort(403)
```

**Database Errors:**
- Use `@with_db_transaction` decorator for write operations
- Pattern from `/home/one/weekly/models.py`:
```python
def with_db_transaction(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except SQLAlchemyError as e:
            current_app.logger.error(f"Database error in {func.__name__}: {str(e)}", exc_info=True)
            db.session.rollback()
            flash('操作失败，请重试', 'warning')
            raise
    return wrapper
```

**User Feedback:**
- Use `flash()` with category: `flash('用户名已存在', 'warning')`
- Flash categories: `'warning'` for errors, default for success

**Form Validation:**
- WTForms validators: `DataRequired()`, `Length(min=8, max=18)`, `EqualTo("password")`

## Logging

**Framework:** Python `logging` module with `RotatingFileHandler`

**Configuration:**
- Production logs to `/var/log/weekly/app.log`
- 10MB max file size, 10 backup files
- INFO level for production
- Format: `%(asctime)s - %(name)s - %(levelname)s - %(message)s [in %(pathname)s:%(lineno)d]`

**Pattern from `/home/one/weekly/app.py`:**
```python
def setup_logging(app):
    if app.debug:
        return
    file_handler = RotatingFileHandler(
        os.path.join('/var/log/weekly', 'app.log'),
        maxBytes=10 * 1024 * 1024,
        backupCount=10
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
```

## Comments

**When to Comment:**
- Chinese comments for complex business logic explanations
- Section headers using `# ====` dividers for code organization
- Reference design decisions with tags: `Per D-01`, `Per RENDER-01`

**Section Headers:**
```python
# =============================================================================
# Database Helper Functions
# =============================================================================
```

**Inline Comments:**
```python
# Per D-11: Use UUID for unique filename
filename = f"{uuid.uuid4().hex}_{secure_filename(f.filename)}"
```

## Function Design

**Size:**
- Route handlers typically 10-30 lines
- Complex routes like `manage_records()` extend to ~50 lines
- Helper functions kept small and focused (5-15 lines)

**Parameters:**
- Route handlers follow Flask conventions: `def edit_record(record_id):`
- Utility functions accept explicit parameters rather than global state
- Use Flask's `current_user` for user context in routes

**Return Values:**
- Routes return `render_template()` or `redirect(url_for())`
- Utility functions return data structures (tuples, lists, dicts)
- Permission checks return booleans

## Module Design

**Exports:**
- `app.py` exports `app` for WSGI deployment and test imports
- Explicit `__all__` list for public API:
```python
__all__ = [
    'app', 'db', 'user_datastore', 'security', 'admin', 'ckeditor', 'bootstrap',
    'User', 'Record', 'Role', 'Group',
    ...
]
```

**Barrel Files:**
- Not used; direct imports from specific modules

**Configuration:**
- Configuration classes: `Config`, `DevelopmentConfig`, `ProductionConfig`
- Environment variables with fallbacks: `os.environ.get('SECRET_KEY', 'default')`

## Form Handling

**Pattern:**
1. Define WTForms class with validators
2. Instantiate form in route handler
3. Check `form.validate_on_submit()` for POST processing
4. Access form data via `form.field_name.data`

**Example from `/home/one/weekly/routes.py`:**
```python
@app.route('/create_records', methods=('GET', 'POST'))
@login_required
@with_db_transaction
def create_records():
    form = RecordForm()
    if form.validate_on_submit():
        record_date = form.date.data
        body = form.body.data
        # ... create record
        return redirect(url_for('manage_records'))
    return render_template('create_records.html', form=form)
```

**Dynamic Field Patching:**
- CKEditor field patched at route registration time:
```python
RecordForm.body = CKEditorField('内容', validators=[])
```

## Decorators

**Route Protection:**
- `@login_required` for authenticated routes
- `@with_db_transaction` for database write operations

**Order (outermost first):**
```python
@app.route('/edit_record/<int:record_id>', methods=['POST', 'GET'])
@login_required
@with_db_transaction
def edit_record(record_id):
```

## Security Patterns

**Password Handling:**
- Use `hash_password()` from Flask-Security
- Use `verify_password()` for authentication
- Minimum password length: 8 characters

**HTML Sanitization:**
- Custom Jinja2 filter `sanitize_html` using bleach
- Allowed tags whitelist in `ALLOWED_TAGS`
- Removes XSS vectors: `<script>`, `onclick`, `javascript:` URLs

**File Upload Security:**
- `secure_filename()` to sanitize uploaded filenames
- UUID prefix for unique filenames: `f"{uuid.uuid4().hex}_{secure_filename(f.filename)}"`
- Extension whitelist: `['jpg', 'gif', 'png', 'jpeg']`
- Maximum content size: 5MB

**Access Control:**
- Permission-based: `User.all_permissions(user)` with caching
- Role-based: `current_user.is_admin` property
- Record-level: `can_edit_record(record, current_user)` function

---

*Convention analysis: 2026-03-26*