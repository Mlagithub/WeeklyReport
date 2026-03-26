# Codebase Structure

> Last updated: 2026-03-26

## Summary

Flask application organized as a flat module structure with clear separation of concerns. Each module handles a specific layer (routes, models, forms, utilities, config, extensions). Templates follow Jinja2 inheritance with a base template pattern. Static assets include CKEditor for rich text editing.

## Directory Layout

```
/home/one/weekly/
├── app.py              # Application factory and entry point
├── config.py           # Configuration classes
├── extensions.py       # Flask extension initialization
├── models.py           # SQLAlchemy models
├── forms.py            # WTForms form definitions
├── routes.py           # Route handlers
├── utils.py            # Utility functions and classes
├── requirements.txt    # Python dependencies
├── pytest.ini          # Test configuration
├── gunicorn.conf.py    # WSGI server configuration
├── instance/           # Database files (SQLite)
│   └── app.db          # Main database
├── static/             # Static assets
│   ├── css/            # Stylesheets
│   ├── ckeditor4/      # CKEditor assets
│   └── favicon-*.png   # Favicons
├── templates/          # Jinja2 templates
│   ├── base.html       # Base template
│   ├── home.html       # Home page
│   ├── config.html     # Theme configuration
│   ├── create_records.html
│   ├── manage_records.html
│   ├── _macros.html    # Template macros
│   ├── _menu.html      # Menu partial
│   ├── security/       # Auth-related templates
│   │   ├── login_user.html
│   │   ├── register_user.html
│   │   ├── change_password.html
│   │   └── forgot_password.html
│   └── admin/          # Flask-Admin templates
├── tests/              # Test suite
│   ├── __init__.py
│   ├── conftest.py     # Pytest fixtures
│   ├── test_models.py
│   ├── test_routes.py
│   └── test_utils.py
├── uploads/            # User uploaded files
└── .planning/          # Planning documents
    ├── codebase/       # Codebase analysis docs
    └── phases/         # Phase execution records
```

## Directory Purposes

### Root Python Files
Application code organized as a flat module structure (no package subdirectory):

**`app.py`:**
- Purpose: Application factory, WSGI entry point
- Contains: `create_app()`, `setup_logging()`, SQLAlchemy event handlers, `sanitize_html` filter
- Key exports: `app`, `db`, `user_datastore`, `create_app`

**`routes.py`:**
- Purpose: All HTTP route handlers
- Contains: `register_routes()`, permission helpers, query builders
- Routes: `/`, `/login`, `/logout`, `/register`, `/create_records`, `/manage_records`, `/edit_record`, `/delete_record`, `/download_records`, `/config`

**`models.py`:**
- Purpose: Database models and ORM configuration
- Contains: `User`, `Record`, `Role`, `Group` models, association tables, `UserModelView`, `with_db_transaction`

**`forms.py`:**
- Purpose: Form validation
- Contains: `RecordForm`, `RecordFilterForm`, `MyLoginForm`, `MyRegisterForm`, `MyChangePasswordForm`, `ThemeForm`

**`utils.py`:**
- Purpose: Shared utilities
- Contains: `DateRange` (time calculations), `RecordDownloader` (Excel export), `html_to_text`

**`config.py`:**
- Purpose: Environment configuration
- Contains: `Config` base class, `DevelopmentConfig`, `ProductionConfig`

**`extensions.py`:**
- Purpose: Extension instances
- Contains: `db`, `security`, `admin`, `ckeditor`, `bootstrap` instances

### instance/
- Purpose: Instance-specific data (database, secrets)
- Contains: SQLite database files (`app.db`, WAL files)
- Key files: `app.db` - main application database

### static/
- Purpose: Static web assets served directly
- Contains: CSS, CKEditor assets, favicons
- Key files: `css/bootstrap-icons.css`, `ckeditor4/` directory

### templates/
- Purpose: Jinja2 HTML templates
- Contains: All HTML templates organized by feature
- Key files: `base.html` (master layout), `home.html` (dashboard), `manage_records.html` (record list)

### tests/
- Purpose: Automated test suite
- Contains: pytest tests and fixtures
- Key files: `conftest.py` (fixtures), `test_routes.py` (integration tests)

### uploads/
- Purpose: User uploaded files (CKEditor images)
- Contains: Uploaded image files with UUID filenames

### .planning/
- Purpose: Project planning and phase documentation
- Contains: `codebase/` (analysis docs), `phases/` (execution records)

## Key File Locations

### Entry Points
- `/home/one/weekly/app.py`: WSGI application object and factory
- `/home/one/weekly/gunicorn.conf.py`: Production server configuration

### Configuration
- `/home/one/weekly/config.py`: Application configuration classes
- `/home/one/weekly/requirements.txt`: Python dependencies
- `/home/one/weekly/pytest.ini`: Test configuration

### Core Logic
- `/home/one/weekly/routes.py`: All route handlers (438 lines)
- `/home/one/weekly/models.py`: Data models and ORM (219 lines)
- `/home/one/weekly/utils.py`: Business utilities (238 lines)

### Templates
- `/home/one/weekly/templates/base.html`: Base template with navigation, scripts
- `/home/one/weekly/templates/home.html`: Dashboard with statistics
- `/home/one/weekly/templates/manage_records.html`: Record listing with filters

### Testing
- `/home/one/weekly/tests/conftest.py`: Test fixtures (`client`, `test_user`, `auth_client`)
- `/home/one/weekly/tests/test_routes.py`: Route integration tests
- `/home/one/weekly/tests/test_models.py`: Model unit tests

## Naming Conventions

### Files
- Python modules: lowercase with underscores (`routes.py`, `models.py`)
- Templates: lowercase with underscores (`create_records.html`, `manage_records.html`)
- Configuration: lowercase with underscores (`gunicorn.conf.py`)
- Tests: `test_<module>.py` pattern (`test_routes.py`, `test_models.py`)

### Directories
- lowercase without separators (`tests`, `templates`, `static`, `instance`)

### Python Identifiers
- Classes: PascalCase (`User`, `RecordFilterForm`, `DateRange`)
- Functions: snake_case (`create_app`, `get_allowed_usernames`, `build_record_query`)
- Constants: UPPER_SNAKE_CASE (`ALLOWED_TAGS`, `ALLOWED_ATTRIBUTES`)
- Decorators: snake_case (`with_db_transaction`)

### Database
- Tables: lowercase (`user`, `record`, `role`, `group`)
- Association tables: snake_case (`user_records`, `roles_users`, `users_groups`)

## Where to Add New Code

### New Feature (e.g., new record type)
- Route handler: `/home/one/weekly/routes.py` (add inside `register_routes()`)
- Model: `/home/one/weekly/models.py` (add new class)
- Form: `/home/one/weekly/forms.py` (add form class)
- Template: `/home/one/weekly/templates/<feature>.html`
- Tests: `/home/one/weekly/tests/test_routes.py` (add test class/function)

### New Model
- Implementation: `/home/one/weekly/models.py`
- Admin view: `/home/one/weekly/app.py` (add to admin in `create_app()`)
- Tests: `/home/one/weekly/tests/test_models.py`

### New Route
- Implementation: `/home/one/weekly/routes.py` inside `register_routes()` function
- Template: `/home/one/weekly/templates/<route_name>.html`
- Tests: `/home/one/weekly/tests/test_routes.py`

### New Utility Function
- Implementation: `/home/one/weekly/utils.py`
- Tests: `/home/one/weekly/tests/test_utils.py`

### New Form
- Implementation: `/home/one/weekly/forms.py`
- Template: `/home/one/weekly/templates/<form_page>.html`

### New Static Asset
- CSS: `/home/one/weekly/static/css/`
- Images: `/home/one/weekly/static/`
- JavaScript: Inline in templates or `/home/one/weekly/static/`

## Special Directories

### instance/
- Purpose: Instance-specific SQLite database
- Generated: No (user data)
- Committed: No (in .gitignore)

### uploads/
- Purpose: User uploaded CKEditor images
- Generated: Yes (at runtime)
- Committed: No (in .gitignore)

### static/ckeditor4/
- Purpose: CKEditor WYSIWYG editor assets
- Generated: No (third-party library)
- Committed: Yes

### .planning/phases/
- Purpose: Phase execution records from GSD workflow
- Generated: Yes (during planning/execution)
- Committed: Yes

### .venv/
- Purpose: Python virtual environment
- Generated: Yes (via `python -m venv`)
- Committed: No (excluded via .gitignore)

## Template Inheritance

```
base.html
├── home.html (extends base)
├── create_records.html (extends base)
├── manage_records.html (extends base)
├── config.html (extends base)
└── security/
    ├── login_user.html (extends base)
    ├── register_user.html (extends base)
    ├── change_password.html (extends base)
    └── forgot_password.html (extends base)
```

**Base Template Blocks:**
- `{% block head %}`: Head content
- `{% block styles %}`: CSS (includes Bootstrap)
- `{% block content %}`: Main page content
- `{% block scripts %}`: JavaScript (includes Bootstrap JS)

---

*Structure analysis: 2026-03-26*