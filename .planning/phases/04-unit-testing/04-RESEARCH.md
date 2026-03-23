# Phase 4: Unit Testing - Research

**Researched:** 2026-03-23
**Domain:** Python unit testing with pytest, Flask application testing
**Confidence:** HIGH

## Summary

This phase establishes unit test coverage for core functionality in a Flask-based weekly report management system. The project currently has **no test infrastructure** - no test files, no pytest configuration, no test dependencies. The testing scope is well-defined in CONTEXT.md with specific coverage targets for authentication, CRUD operations, utility functions, and permission logic.

**Primary recommendation:** Use pytest 8.x with pytest-cov, organize tests by module (test_utils.py, test_routes.py, test_models.py), and use Flask's test_client with in-memory SQLite for database-dependent tests. Focus on testing the core paths identified in CONTEXT.md rather than pursuing coverage percentages.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- **D-01:** Use pytest as the testing framework
- **D-02:** Configure pytest fixtures for test client and database setup
- **D-03:** Full Coverage - test all routes, all models, all utility functions
- **D-04:** Must cover: user authentication functions (login, register, logout), Record CRUD operations (create, read, update, delete)
- **D-05:** Additional coverage: DateRange utility class, html_to_text function, User permission methods, route authorization functions
- **D-06:** Use in-memory SQLite database (`sqlite:///:memory:`)
- **D-07:** Each test function gets independent database state (create_all/drop_all)
- **D-08:** Use pytest fixture to provide test client and authentication state
- **D-09:** No minimum coverage percentage requirement
- **D-10:** Focus on verifying core paths work correctly, not pursuing numbers

### Claude's Discretion
- Test file organization structure (single file vs. by module)
- Specific test case naming and boundary conditions
- Fixture implementation details

### Deferred Ideas (OUT OF SCOPE)
None - discussion stayed within phase scope
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| TEST-01 | Core functionality has unit test coverage | pytest framework + Flask test_client patterns documented below enable testing of authentication, CRUD, utilities, and permissions |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| pytest | 8.3.x | Test runner and framework | Industry standard for Python testing, powerful fixtures, detailed assertion introspection |
| pytest-cov | 5.0.x | Coverage reporting | Integrates with pytest, generates coverage reports |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| pytest-mock | 3.14.x | Mocking utilities | For mocking datetime, external services |
| unittest.mock | (stdlib) | Built-in mocking | For simple mock needs without extra dependency |

### Already in Project
| Library | Version | Purpose |
|---------|---------|---------|
| Flask | 3.0.3 | Provides test_client() for integration tests |
| Flask-SQLAlchemy | 3.1.1 | Database ORM, works with in-memory SQLite |
| Flask-Security | 5.5.2 | Authentication - requires special test handling |

**Installation:**
```bash
pip install pytest==8.3.5 pytest-cov==5.0.0
```

Or add to requirements.txt:
```
pytest==8.3.5
pytest-cov==5.0.0
```

**Version verification:**
```bash
pip3 index versions pytest 2>/dev/null | head -1
# pytest (9.0.2) - latest, but 8.3.5 is more stable for production use
pip3 index versions pytest-cov 2>/dev/null | head -1
# pytest-cov (7.1.0) - latest
```

## Architecture Patterns

### Recommended Project Structure
```
/home/one/weekly/
├── tests/
│   ├── __init__.py           # Makes tests a package
│   ├── conftest.py           # Shared fixtures (client, db, auth)
│   ├── test_utils.py         # DateRange, html_to_text tests
│   ├── test_models.py        # User, Record, Group, Role tests
│   └── test_routes.py        # Route handler tests (auth, CRUD)
├── app.py                    # Application under test
├── utils.py                  # Utilities under test
├── pytest.ini                # pytest configuration (to be created)
└── requirements.txt          # Add pytest, pytest-cov
```

### Pattern 1: Flask Test Client Fixture
**What:** Provides a test client for making HTTP requests to the Flask app without running a server.
**When to use:** All route/integration tests.
**Example:**
```python
# tests/conftest.py
import pytest
from app import app, db

@pytest.fixture
def client():
    """Create a test client with in-memory database."""
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for tests

    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
            db.drop_all()
```

### Pattern 2: Authenticated Client Fixture
**What:** Provides a client that's already logged in as a test user.
**When to use:** Testing routes protected by @login_required.
**Example:**
```python
# tests/conftest.py
from flask_security.utils import hash_password
from app import user_datastore

@pytest.fixture
def auth_client(client):
    """Create authenticated client with test user."""
    with client.application.app_context():
        # Create test user
        user = user_datastore.create_user(
            email='test@test.com',
            username='testuser',
            password=hash_password('testpass123')
        )
        db.session.commit()

    # Login
    client.post('/login', data={
        'username': 'testuser',
        'password': 'testpass123'
    })
    yield client
```

### Pattern 3: Test Database Isolation
**What:** Each test gets a fresh database state.
**When to use:** All tests that interact with the database.
**Example:**
```python
# Alternative: Function-scoped isolation
@pytest.fixture(autouse=True)
def reset_db():
    """Reset database state before each test."""
    db.session.rollback()
    for table in reversed(db.metadata.sorted_tables):
        db.session.execute(table.delete())
    db.session.commit()
```

### Pattern 4: Pure Unit Tests (No Database)
**What:** Test utility functions without database dependency.
**When to use:** DateRange methods, html_to_text, permission helper functions.
**Example:**
```python
# tests/test_utils.py
from datetime import date
from unittest.mock import patch
from utils import DateRange, html_to_text

class TestDateRange:
    def test_this_week_returns_tuple(self):
        result = DateRange.this_week()
        assert isinstance(result, tuple)
        assert len(result) == 2
        start, end = result
        assert isinstance(start, date)
        assert isinstance(end, date)
        assert start <= end

    @patch('utils.datetime')
    def test_this_week_known_date(self, mock_datetime):
        """Test with mocked date for deterministic results."""
        mock_datetime.today.return_value.date.return_value = date(2026, 3, 23)  # Monday
        start, end = DateRange.this_week()
        assert start == date(2026, 3, 23)  # Monday
        assert end == date(2026, 3, 23)

    def test_get_range_unknown_returns_this_year(self):
        result = DateRange.get_range('unknown')
        expected = DateRange.this_year()
        assert result == expected

class TestHtmlToText:
    def test_empty_input(self):
        assert html_to_text('') == ''
        assert html_to_text(None) == ''

    def test_plain_paragraph(self):
        assert html_to_text('<p>Hello World</p>') == 'Hello World'

    def test_unordered_list(self):
        result = html_to_text('<ul><li>Item 1</li><li>Item 2</li></ul>')
        assert '- Item 1' in result
        assert '- Item 2' in result

    def test_ordered_list(self):
        result = html_to_text('<ol><li>First</li><li>Second</li></ol>')
        assert '1. First' in result
        assert '2. Second' in result
```

### Anti-Patterns to Avoid
- **Using production database for tests:** Always use in-memory SQLite or a separate test database.
- **Not disabling CSRF in tests:** Flask-WTF CSRF tokens will cause form submissions to fail.
- **Sharing database state between tests:** Each test should have clean, predictable state.
- **Testing implementation details:** Test behavior, not internal structure.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Mock datetime | Custom date injection | `unittest.mock.patch` or `pytest-mock` | Standard, well-tested, handles edge cases |
| Test client authentication | Manual session manipulation | Flask-Security's `login_user()` in fixture | Flask-Security has complex session handling |
| Database cleanup | Custom truncation logic | `db.drop_all()` / `db.create_all()` | Handles constraints and relationships correctly |
| Assertion messages | Manual string comparison | pytest's assertion introspection | Better error messages automatically |

**Key insight:** Flask's built-in test_client and pytest's fixtures are sufficient for all testing needs. Flask-Security's authentication can be tested via the login route rather than trying to mock internal state.

## Common Pitfalls

### Pitfall 1: Flask-Security Session Handling
**What goes wrong:** Tests fail because current_user is anonymous even after "logging in".
**Why it happens:** Flask-Security uses complex session management that doesn't work with naive mock approaches.
**How to avoid:** Use the actual login route to authenticate, or use `login_user()` within an app context.
**Warning signs:** `AttributeError: 'AnonymousUser' object has no attribute 'username'`

### Pitfall 2: Database State Leakage
**What goes wrong:** Tests pass in isolation but fail when run together, or fail nondeterministically.
**Why it happens:** Tests share database state without proper cleanup.
**How to avoid:** Use fixture scopes correctly (function scope for db isolation), or use `autouse=True` cleanup fixture.
**Warning signs:** Tests pass with `pytest -x` but fail with `pytest`, or pass/fail randomly.

### Pitfall 3: Time-Dependent Tests
**What goes wrong:** DateRange tests fail on certain days of the week or at year boundaries.
**Why it happens:** Tests use `datetime.today()` which returns different values depending on when tests run.
**How to avoid:** Use `unittest.mock.patch` to mock `datetime.today()` with fixed dates, or use freezegun library.
**Warning signs:** Tests fail on Monday but pass on Tuesday, or fail at year boundaries.

### Pitfall 4: CSRF Token Issues
**What goes wrong:** Form submission tests return 400 Bad Request or fail validation.
**Why it happens:** Flask-WTF requires CSRF tokens that aren't included in test requests.
**How to avoid:** Set `WTF_CSRF_ENABLED = False` in test config, or include token in test requests.
**Warning signs:** POST requests to routes with forms return 400 or redirect without processing.

### Pitfall 5: App Context Issues
**What goes wrong:** `RuntimeError: Working outside of application context` errors.
**Why it happens:** Flask-SQLAlchemy operations require an active application context.
**How to avoid:** Use `with app.app_context():` when performing database operations outside of request context.
**Warning signs:** Errors when creating users or querying database in fixtures.

## Code Examples

### Test Configuration (pytest.ini)
```ini
# pytest.ini
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = -v --tb=short
```

### Complete conftest.py
```python
# tests/conftest.py
import pytest
from app import app, db, user_datastore
from flask_security.utils import hash_password

@pytest.fixture
def client():
    """Create test client with in-memory database."""
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SECURITY_PASSWORD_SALT'] = 'test-salt'

    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
            db.session.remove()
            db.drop_all()

@pytest.fixture
def test_user(client):
    """Create a test user and return user data."""
    with client.application.app_context():
        user = user_datastore.create_user(
            email='test@example.com',
            username='testuser',
            password=hash_password('TestPass123')
        )
        db.session.commit()
        return {'username': 'testuser', 'password': 'TestPass123', 'id': user.id}

@pytest.fixture
def auth_client(client, test_user):
    """Authenticated test client."""
    client.post('/login', data={
        'username': test_user['username'],
        'password': test_user['password']
    })
    yield client

@pytest.fixture
def admin_user(client):
    """Create admin user for admin tests."""
    with client.application.app_context():
        from app import Role
        admin_role = Role(name='admin', description='Admin', permissions=['view_all', 'edit_database'])
        db.session.add(admin_role)
        user = user_datastore.create_user(
            email='admin@example.com',
            username='adminuser',
            password=hash_password('AdminPass123'),
            roles=[admin_role]
        )
        db.session.commit()
        return {'username': 'adminuser', 'password': 'AdminPass123'}
```

### Authentication Tests
```python
# tests/test_routes.py
class TestAuthentication:
    def test_login_page_loads(self, client):
        response = client.get('/login')
        assert response.status_code == 200

    def test_login_success(self, client, test_user):
        response = client.post('/login', data={
            'username': test_user['username'],
            'password': test_user['password']
        }, follow_redirects=True)
        assert response.status_code == 200
        assert b'testuser' in response.data or b'home' in response.data

    def test_login_invalid_password(self, client, test_user):
        response = client.post('/login', data={
            'username': test_user['username'],
            'password': 'wrongpassword'
        }, follow_redirects=True)
        assert b'warning' in response.data or b'\xe4\xb8\x8d\xe6\xad\xa3\xe7\xa1\xae' in response.data  # Chinese "incorrect"

    def test_logout(self, auth_client):
        response = auth_client.get('/logout', follow_redirects=True)
        assert response.status_code == 200

    def test_register_new_user(self, client):
        response = client.post('/register', data={
            'username': 'newuser',
            'password': 'NewPass123',
            'password_confirm': 'NewPass123'
        }, follow_redirects=True)
        assert response.status_code == 200
```

### CRUD Tests
```python
# tests/test_routes.py
class TestRecordCRUD:
    def test_create_record_requires_auth(self, client):
        response = client.get('/create_records')
        assert response.status_code == 302  # Redirect to login

    def test_create_record_success(self, auth_client):
        response = auth_client.post('/create_records', data={
            'date': '2026-03-23',
            'body': '<p>Test content</p>'
        }, follow_redirects=True)
        assert response.status_code == 200

    def test_edit_own_record(self, auth_client, test_user):
        # First create a record
        auth_client.post('/create_records', data={
            'date': '2026-03-23',
            'body': '<p>Original content</p>'
        })
        # Then edit it
        response = auth_client.get('/edit_record/1')
        assert response.status_code == 200

    def test_delete_own_record(self, auth_client):
        auth_client.post('/create_records', data={
            'date': '2026-03-23',
            'body': '<p>To be deleted</p>'
        })
        response = auth_client.post('/delete_record/1', follow_redirects=True)
        assert response.status_code == 200
```

### Permission Tests
```python
# tests/test_models.py
from app import User, Role, Group, db
from flask_security.utils import hash_password
from flask import g

class TestUserPermissions:
    def test_is_admin_property(self, client):
        with client.application.app_context():
            # Create admin role
            admin_role = Role(name='admin', permissions=['view_all', 'edit_database'])
            db.session.add(admin_role)

            # Create admin user
            user = User(username='admin', email='admin@test.com',
                       password=hash_password('pass'), roles=[admin_role])
            db.session.add(user)
            db.session.commit()

            assert user.is_admin == True

    def test_all_permissions_caching(self, client):
        with client.application.app_context():
            role = Role(name='employee', permissions=['view_self'])
            user = User(username='emp', email='emp@test.com',
                       password=hash_password('pass'), roles=[role])
            db.session.add_all([role, user])
            db.session.commit()

            # Clear g to simulate fresh request
            g._user_perms_1 = None if hasattr(g, '_user_perms_1') else None

            perms = User.all_permissions(user)
            assert 'view_self' in perms

class TestCanEditRecord:
    def test_owner_can_edit(self, client):
        # Test that record owner can edit their own record
        pass

    def test_non_owner_cannot_edit(self, client):
        # Test that non-owner cannot edit others' records
        pass

    def test_admin_can_edit_any(self, client):
        # Test that admin can edit any record
        pass
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| unittest.TestCase | pytest free functions | pytest 3.0+ (2016) | Simpler tests, better fixtures |
| Database fixtures per class | Function-scoped fixtures | pytest 2.3+ (2012) | Better isolation, parallel-safe |
| Manual mock objects | unittest.mock/pytest-mock | Python 3.3+ | Cleaner mocking syntax |

**Deprecated/outdated:**
- `nose` test runner: Use pytest instead
- `unittest2` backport: Use built-in unittest in Python 3

## Open Questions

1. **Should we use pytest-mock or unittest.mock?**
   - What we know: unittest.mock is in stdlib, pytest-mock provides pytest-specific conveniences
   - What's unclear: Whether the project needs pytest-mock's additional features
   - Recommendation: Start with unittest.mock, add pytest-mock only if needed for complex mocking

2. **Should we test the RecordDownloader class?**
   - What we know: RecordDownloader uses openpyxl and send_file, returns Excel files
   - What's unclear: Whether to test the Excel generation or just mock send_file
   - Recommendation: Test html_to_text separately, mock RecordDownloader in route tests

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Python 3.10+ | pytest | Yes | 3.10.12 | - |
| pytest | Test runner | No | - | Install required |
| pytest-cov | Coverage | No | - | Install required |
| Flask | test_client | Yes | 3.0.3 | - |
| Flask-SQLAlchemy | Test DB | Yes | 3.1.1 | - |
| Flask-Security | Auth tests | Yes | 5.5.2 | - |

**Missing dependencies with no fallback:**
- pytest and pytest-cov must be installed before running tests

**Missing dependencies with fallback:**
- None (all test dependencies are add-ons)

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | pytest 8.3.x |
| Config file | pytest.ini (to be created) |
| Quick run command | `pytest -x` |
| Full suite command | `pytest --cov=app --cov=utils` |

### Phase Requirements -> Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| TEST-01 | User authentication functions have tests | integration | `pytest tests/test_routes.py::TestAuthentication -x` | Wave 0 |
| TEST-01 | Record CRUD operations have tests | integration | `pytest tests/test_routes.py::TestRecordCRUD -x` | Wave 0 |
| TEST-01 | DateRange utility tests | unit | `pytest tests/test_utils.py::TestDateRange -x` | Wave 0 |
| TEST-01 | html_to_text tests | unit | `pytest tests/test_utils.py::TestHtmlToText -x` | Wave 0 |
| TEST-01 | User permission tests | unit | `pytest tests/test_models.py::TestUserPermissions -x` | Wave 0 |

### Sampling Rate
- **Per task commit:** `pytest -x` (stop on first failure)
- **Per wave merge:** `pytest --cov=app --cov=utils` (full suite with coverage)
- **Phase gate:** All tests pass, coverage report generated

### Wave 0 Gaps
- [ ] `tests/__init__.py` - package marker
- [ ] `tests/conftest.py` - shared fixtures (client, auth_client, test_user)
- [ ] `tests/test_utils.py` - DateRange and html_to_text tests
- [ ] `tests/test_routes.py` - authentication and CRUD tests
- [ ] `tests/test_models.py` - User permission tests
- [ ] `pytest.ini` - pytest configuration
- [ ] Framework install: `pip install pytest==8.3.5 pytest-cov==5.0.0`

## Sources

### Primary (HIGH confidence)
- pytest documentation - https://docs.pytest.org/ (fixture patterns, configuration)
- Flask testing documentation - https://flask.palletsprojects.com/en/stable/testing/ (test_client patterns)
- Flask-SQLAlchemy documentation - in-memory SQLite patterns
- Project code analysis - app.py, utils.py source code reviewed

### Secondary (MEDIUM confidence)
- TESTING.md analysis - existing test infrastructure documentation
- ARCHITECTURE.md analysis - model and route structure
- CONVENTIONS.md analysis - coding patterns and error handling

### Tertiary (LOW confidence)
- None required - primary sources sufficient for this phase

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - pytest is industry standard, Flask test_client is well-documented
- Architecture: HIGH - patterns are well-established for Flask testing
- Pitfalls: HIGH - common Flask/pytest issues are well-documented

**Research date:** 2026-03-23
**Valid until:** 2026-04-23 (pytest 8.x is stable, patterns won't change significantly)