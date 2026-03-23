# Codebase Structure

**Analysis Date:** 2026-03-23

## Directory Layout

```
/home/one/weekly/
├── app.py              # Main application (748 lines) - models, routes, forms
├── utils.py            # Utility classes (236 lines) - DateRange, RecordDownloader
├── requirements.txt    # Python dependencies
├── app.spec            # PyInstaller specification
├── instance/           # Flask instance folder (gitignored)
│   └── app.db          # SQLite database
├── static/             # Static assets
│   ├── ckeditor/       # CKEditor 4 assets (local)
│   ├── ckeditor4/      # CKEditor 4 full distribution
│   ├── css/            # Custom CSS
│   ├── db_table_data.json  # Initial data seed
│   └── favicon-*.png   # Favicon files
├── templates/          # Jinja2 templates
│   ├── base.html       # Base template with layout
│   ├── _macros.html    # Reusable Jinja macros
│   ├── _menu.html      # Security menu partial
│   ├── home.html       # Dashboard page
│   ├── create_records.html  # Record form page
│   ├── manage_records.html  # Record list page
│   ├── config.html     # Theme configuration
│   ├── security/       # Authentication templates
│   └── admin/          # Flask-Admin override
├── uploads/            # User uploaded files (gitignored)
├── wheels/             # Python wheel packages for offline install
├── build/              # PyInstaller build output (gitignored)
├── dist/               # PyInstaller distribution (gitignored)
└── .venv/              # Virtual environment (gitignored)
```

## Directory Purposes

**`instance/`:**
- Purpose: Flask instance folder for database
- Contains: `app.db` SQLite database file
- Gitignored: Yes
- Created: Automatically by SQLAlchemy

**`static/`:**
- Purpose: Static assets served directly
- Contains: CKEditor, CSS, favicons, seed data JSON
- Key files: `static/db_table_data.json` - initial roles/groups/users

**`templates/`:**
- Purpose: Jinja2 HTML templates
- Contains: Page templates and partials
- Key files: `templates/base.html` - defines common layout

**`templates/security/`:**
- Purpose: Override Flask-Security default templates
- Contains: Login, register, password change, password reset forms
- Naming: `*_user.html` pattern

**`uploads/`:**
- Purpose: CKEditor image uploads
- Contains: User-uploaded images
- Gitignored: Yes
- Max size: 5MB (configured in `app.py:55`)

**`wheels/`:**
- Purpose: Offline Python package installation
- Contains: `.whl` files for all dependencies
- Use case: Deploy to air-gapped environments

## Key File Locations

**Entry Points:**
- `app.py:743-747`: Main script execution
- `app.py:28-58`: Flask app initialization and configuration

**Configuration:**
- `app.py:29-55`: App configuration (database, security, upload limits)
- `requirements.txt`: Python dependencies
- `.gitignore`: Version control exclusions

**Core Logic:**
- `app.py:89-183`: Database models (Record, Role, User, Group)
- `app.py:215-310`: WTForms definitions
- `app.py:379-681`: Route handlers
- `utils.py:6-93`: DateRange utility class
- `utils.py:154-233`: RecordDownloader Excel export

**Testing:**
- Not present - no test files detected

**Database:**
- `instance/app.db`: SQLite database file
- `app.py:60-71`: Schema migration helper (`ensure_record_columns`)
- `app.py:683-739`: Data seeding from JSON (`update_db_from_json`)

## Naming Conventions

**Files:**
- Python: `snake_case.py` (e.g., `app.py`, `utils.py`)
- Templates: `snake_case.html` (e.g., `create_records.html`)
- Static: Mixed (CKEditor uses own conventions)

**Directories:**
- Lowercase with underscores: `templates/security/`
- Special Flask directories: `instance/`, `static/`, `templates/`

**Python Identifiers:**
- Functions: `snake_case` (e.g., `create_records`, `build_record_query`)
- Classes: `PascalCase` (e.g., `RecordFilterForm`, `DateRange`)
- Constants: `UPPER_SNAKE_CASE` (not used in this codebase)
- Private methods: Leading underscore (e.g., `_fsdomain` in templates)

## Where to Add New Code

**New Route:**
- Add to `app.py` after existing routes (around line 680)
- Create corresponding template in `templates/`
- Use `@app.route()` decorator and `@login_required` if needed

**New Model:**
- Add class definition in `app.py` after existing models (around line 180)
- Inherit from `db.Model`
- Add to Flask-Admin: `admin.add_view(UserModelView(NewModel, db.session))`

**New Form:**
- Add WTForms class in `app.py` after existing forms (around line 310)
- Inherit from `FlaskForm`
- Add field validators as needed

**New Permission:**
- Add to role definitions in `static/db_table_data.json`
- Check in route handlers via `User.all_permissions(current_user)`

**New Utility:**
- Add to `utils.py` for date/formatting utilities
- Keep as static methods in utility classes

**New Template:**
- Create in `templates/` directory
- Extend `base.html` for consistent layout
- Use Bootstrap-Flask components for UI

**New Static Asset:**
- Add to `static/` directory
- Reference with `url_for('static', filename='...')`

## Special Directories

**`wheels/`:**
- Purpose: Offline package installation
- Contains: Pre-downloaded `.whl` and `.tar.gz` files
- Generated: Manually via `pip download`
- Committed: Yes (for air-gapped deployment)

**`build/` and `dist/`:**
- Purpose: PyInstaller output
- Generated: By PyInstaller build process
- Committed: No (gitignored)

**`.venv/`:**
- Purpose: Python virtual environment
- Generated: By `python -m venv`
- Committed: No (gitignored)

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

*Structure analysis: 2026-03-23*