# Coding Conventions

**Analysis Date:** 2026-03-23

## Naming Patterns

**Files:**
- Python files use snake_case: `app.py`, `utils.py`
- Template files use snake_case with `.html` extension: `create_records.html`, `manage_records.html`
- Static assets follow conventional naming: `db_table_data.json`

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

**Constants:**
- Class-level constants use SCREAMING_SNAKE_CASE: `DateRange.TIME_RANGES`

## Code Style

**Formatting:**
- No explicit formatter configuration detected (no `.prettierrc`, `pyproject.toml`, or `.editorconfig`)
- 4-space indentation (Python standard)
- Lines typically under 100 characters

**Linting:**
- No explicit linter configuration detected (no `.eslintrc`, `flake8`, `ruff`, or `pylint` config)
- Code follows PEP 8 style implicitly

**Imports:**
- Grouped by source: standard library, third-party packages, local modules
- Example from `app.py` lines 1-26:
```python
from flask import Flask, render_template, redirect, flash, url_for, request, send_from_directory, abort, session, g
from flask_security import Security, SQLAlchemyUserDatastore, login_required, login_user, logout_user, current_user
# ... more flask extensions
from utils import DateRange, RecordDownloader

import os
from datetime import date, datetime
import json
```

## Import Organization

**Order:**
1. Flask and extension imports (multiple imports per line grouped by package)
2. Local application imports (`from utils import ...`)
3. Standard library imports (os, datetime, json)
4. Inline imports for specific functionality (e.g., `from openpyxl import Workbook` in `utils.py`)

**Path Aliases:**
- None used; all imports use full module paths

## Error Handling

**Patterns:**
- HTTP errors via `abort()`: `abort(404)`, `abort(403)` in `app.py` lines 504, 506, 532-534
- User feedback via `flash()`: `flash('用户名已存在', 'warning')` in `app.py` line 416
- Form validation via WTForms validators: `DataRequired()`, `Length()`, `EqualTo()`
- Return value checks: `if not record: abort(404)`

**Flash Message Categories:**
- `'warning'` for errors and validation issues
- Default category for success messages

## Security Patterns

**Password Handling:**
- Use `hash_password()` from flask_security for password hashing: `app.py` lines 424, 732
- Use `verify_password()` for authentication: `app.py` line 436
- Minimum password length enforced: `SECURITY_PASSWORD_LENGTH_MIN = 8`

**CSRF Protection:**
- Flask-WTF provides CSRF protection for forms
- CKEditor CSRF explicitly commented out: `app.py` line 40
```python
# app.config['CKEDITOR_ENABLE_CSRF'] = True  # if you want to enable CSRF protect, uncomment this line
```

**File Upload Security:**
- Use `secure_filename()` to sanitize uploaded filenames: `app.py` lines 658, 675
- Extension whitelist for uploads: `['jpg', 'gif', 'png', 'jpeg']` in `app.py` line 671
- Maximum content size: `MAX_CONTENT_LENGTH = 5 * 1024 * 1024` (5MB)

**Access Control:**
- `@login_required` decorator for protected routes
- Permission checking via `User.all_permissions(user)` with result caching in `g`
- Role-based access: `current_user.is_admin` property
- Record-level authorization: `can_edit_record(record, current_user)` function

**Secrets:**
- `SECRET_KEY` and `SECURITY_PASSWORD_SALT` should come from environment variables in production
- Current code has hardcoded values (security concern): `app.py` lines 37, 44

## Database Session Management

**Patterns:**
- Explicit commits after modifications:
```python
# app.py line 488-489
db.session.add(record)
db.session.commit()
```

- Connection pool configuration for long-running processes:
```python
# app.py lines 30-36
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,      # Detect stale connections
    'pool_recycle': 3600,       # Recycle connections every hour
    'pool_size': 10,            # Pool size
    'max_overflow': 20,         # Max overflow connections
}
```

- Eager loading to prevent N+1 queries:
```python
# app.py line 140
Group.query.options(joinedload(Group.users)).all()
```

- Request-level caching for permissions:
```python
# app.py lines 127-132
cache_key = f'_user_perms_{user.id}'
if not hasattr(g, cache_key):
    perms = tuple(set(p for role in user.roles for p in role.permissions))
    setattr(g, cache_key, perms)
return list(getattr(g, cache_key))
```

## Comments

**When to Comment:**
- Chinese comments for complex business logic explanations
- Inline comments for configuration options
- Section headers for code organization

**Example from `app.py` lines 30-36:**
```python
# 数据库连接池配置，防止长时间运行导致连接泄漏
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,      # 检测失效连接
    'pool_recycle': 3600,       # 每小时回收连接
    ...
}
```

**Docstrings:**
- Sparse usage; most functions lack docstrings
- Some functions have docstrings: `User.all_permissions()` at line 127
```python
def all_permissions(user):
    """获取用户所有权限（请求级缓存，避免跨请求权限过期问题）"""
```

## Function Design

**Size:**
- Route handlers typically 10-30 lines
- Complex routes like `manage_records()` extend to ~50 lines
- Helper functions kept small and focused

**Parameters:**
- Route handlers follow Flask conventions: `def edit_record(record_id):`
- Utility functions accept explicit parameters rather than global state

**Return Values:**
- Routes return template renders or redirects
- Utility functions return data structures (tuples, lists, dicts)
- Permission checks return booleans

## Module Design

**Exports:**
- `app.py` exports `app` for WSGI deployment
- `utils.py` exports utility classes: `DateRange`, `RecordDownloader`

**Barrel Files:**
- Not used; direct imports from specific modules

**Configuration:**
- Configuration via Flask `app.config` dictionary
- Environment variables with fallbacks: `os.environ.get("DATABASE_URL", 'sqlite:///app.db')`

## Form Handling

**Pattern:**
- WTForms classes with validators
- Form instantiation in route handler
- `form.validate_on_submit()` for POST processing
- Pre-populating form data for edit operations:
```python
# app.py lines 517-518
form.date.data = record.date
form.body.data = record.content
```

---

*Convention analysis: 2026-03-23*