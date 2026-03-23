# Architecture

**Analysis Date:** 2026-03-23

## Pattern Overview

**Overall:** Flask MVC (Model-View-Controller) with Flask-Security for authentication

**Key Characteristics:**
- Single-file application core (`app.py`) with models, views, and routes
- SQLAlchemy ORM for database abstraction
- Flask-Security for role-based access control
- Flask-Admin for administrative interface
- WTForms for form validation
- CKEditor for rich text editing

## Layers

**Model Layer:**
- Purpose: Data representation and persistence
- Location: `app.py:89-183` (model definitions)
- Contains: SQLAlchemy models (User, Role, Record, Group) and association tables
- Depends on: SQLAlchemy, Flask-Security mixins
- Used by: Route handlers, Flask-Admin views

**View Layer:**
- Purpose: HTTP request handling and response generation
- Location: `app.py:379-681` (route definitions)
- Contains: Route functions with decorators for auth/authorization
- Depends on: Models, Forms, Templates
- Used by: Flask routing system

**Template Layer:**
- Purpose: HTML rendering with Jinja2
- Location: `templates/` directory
- Contains: Base template, page templates, security templates, macros
- Depends on: Bootstrap-Flask for UI components
- Used by: Route handlers via `render_template()`

**Form Layer:**
- Purpose: Input validation and CSRF protection
- Location: `app.py:215-310` (form definitions)
- Contains: WTForms classes for record, filter, authentication, and configuration
- Depends on: WTForms, Flask-WTF
- Used by: Route handlers

## Data Flow

**Record Creation Flow:**

1. User navigates to `/create_records` (GET)
2. `create_records()` renders form with empty RecordForm
3. User fills CKEditor field and submits (POST)
4. Form validation via WTForms
5. Record object created and associated with current_user
6. Database commit and redirect to `/manage_records`

**Record Query Flow:**

1. User accesses `/manage_records` with optional filter params
2. `build_record_query()` constructs SQLAlchemy query with:
   - Permission-based user filtering
   - Time range filtering via `DateRange` utility
   - Group-based filtering
3. Query executed with pagination
4. Results rendered in table with edit/delete buttons

**Authentication Flow:**

1. User submits login form at `/login`
2. `login()` validates credentials via `verify_password()`
3. `login_user()` establishes session
4. Redirect to `next` URL or home
5. `@login_required` decorator protects routes

## Key Abstractions

**Permission System:**
- Purpose: Fine-grained access control
- Examples: `app.py:106-132` (User permission methods)
- Pattern: Role-based with permissions stored as list in Role model
  - `view_self`: User can only see their own records
  - `view_group`: Group leader can see their group's records
  - `view_all`: Admin/teacher can see all records
  - `edit_database`: Admin can access Flask-Admin

**DateRange Utility:**
- Purpose: Calculate date ranges for filtering
- Examples: `utils.py:6-93`
- Pattern: Static methods returning (start_date, end_date) tuples
  - `this_week()`, `last_week()`, `this_month()`, `this_quarter()`, `this_year()`

**RecordDownloader:**
- Purpose: Export records to Excel
- Examples: `utils.py:154-233`
- Pattern: Generates openpyxl Workbook with styled output

## Entry Points

**Main Application Entry:**
- Location: `app.py:743-747`
- Triggers: Direct script execution `python app.py`
- Responsibilities: Create tables, seed data from JSON, start development server

**Route Entry Points:**
- `/` - Home dashboard (`app.py:379-407`)
- `/login` - Authentication (`app.py:431-441`)
- `/register` - User registration (`app.py:409-429`)
- `/create_records` - New record form (`app.py:476-495`)
- `/manage_records` - Record list with filters (`app.py:571-632`)
- `/download_records` - Excel export (`app.py:538-568`)
- `/admin` - Flask-Admin interface (`app.py:209-213`)

**Before Request Hook:**
- Location: `app.py:635-638`
- Triggers: Every HTTP request
- Responsibilities: Apply user's theme preference from session

## Database Models

**User Model** (`app.py:98-161`):
- Inherits from `FsUserMixin` for Flask-Security
- Fields: id, email, username, password, records (relationship)
- Many-to-Many: roles (via roles_users), groups (via users_groups)
- Methods: `is_admin`, `with_role()`, `can_view_group()`, `all_permissions()`, `managed_group()`, `change_user_password()`

**Record Model** (`app.py:89-93`):
- Fields: id, content (Text), date (Date), createtime (DateTime)
- Many-to-Many: users (via user_records)

**Role Model** (`app.py:95-97`):
- Inherits from `FsRoleMixin` for Flask-Security
- Fields: id, name, description, permissions (list)
- Used for RBAC permission checks

**Group Model** (`app.py:164-182`):
- Fields: id, name, description
- Many-to-Many: users (via users_groups)
- Used for organizational grouping and permission scoping

**Association Tables:**
- `user_records` (`app.py:73-76`): User-Record many-to-many
- `roles_users` (`app.py:78-81`): User-Role many-to-many
- `users_groups` (`app.py:83-86`): User-Group many-to-many

## Error Handling

**Strategy:** HTTP status codes with flash messages

**Patterns:**
- `abort(404)` for missing resources (`app.py:504, 532, 660`)
- `abort(403)` for permission denied (`app.py:506, 534`)
- `flash()` for user feedback after actions (`app.py:491, 514, 530, 647`)

## Cross-Cutting Concerns

**Logging:** Not configured - uses Flask defaults

**Validation:**
- WTForms validators: `DataRequired`, `Length`, `EqualTo` (`app.py:14`)
- File upload validation: extension whitelist (`app.py:671`)

**Authentication:**
- Flask-Security with Argon2 password hashing
- Session-based with `remember me` option
- Custom login/register forms extending Flask-Security defaults

**Authorization:**
- Role-based via Flask-Security roles
- Permission checking via `User.all_permissions()` (`app.py:126-132`)
- Request-level permission caching using Flask's `g` object

**Database Connection Pooling:**
- Configured at `app.py:31-36`
- `pool_pre_ping`: Detect stale connections
- `pool_recycle`: 3600 seconds (1 hour)
- `pool_size`: 10 connections
- `max_overflow`: 20 additional connections

---

*Architecture analysis: 2026-03-23*