# Testing Patterns

**Analysis Date:** 2026-03-26

## Summary

The project uses pytest as its test framework with pytest-cov for coverage. Tests are organized in a `tests/` directory with separate files for models, routes, and utilities. The test suite includes unit tests for utility functions, integration tests for routes, and model permission tests. Fixtures in `conftest.py` provide test client and authenticated client setup.

## Test Framework

**Runner:**
- pytest 8.3.5
- pytest-cov 5.0.0 for coverage reporting
- Configuration: `/home/one/weekly/pytest.ini`

**Assertion Library:**
- Python's built-in `assert` statements
- pytest assertions for exception testing

**Run Commands:**
```bash
pytest                    # Run all tests
pytest -v                 # Verbose output (configured by default)
pytest --cov=app          # Coverage report for app module
pytest tests/test_utils.py  # Run specific test file
pytest -k "DateRange"     # Run tests matching pattern
```

**pytest.ini Configuration:**
```ini
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = -v --tb=short
```

## Test File Organization

**Location:**
- Tests in `/home/one/weekly/tests/` directory (separate from source)
- Follows pytest conventions

**Naming:**
- Test files: `test_*.py`
- Test classes: `Test*` prefix
- Test functions: `test_*` prefix

**Structure:**
```
/home/one/weekly/tests/
├── __init__.py          # Package marker
├── conftest.py          # Shared fixtures
├── test_models.py       # Model and permission tests
├── test_routes.py       # Route integration tests
└── test_utils.py        # Utility function unit tests
```

## Test Structure

**Suite Organization:**
```python
class TestUserPermissions:
    """Tests for User model permission methods."""

    def test_is_admin_true_for_admin_role(self, client):
        """Admin users should have is_admin property return True."""
        # Test implementation...

    def test_is_admin_false_for_non_admin(self, client):
        """Non-admin users should have is_admin property return False."""
        # Test implementation...
```

**Patterns:**
- Group related tests in classes by functionality
- Descriptive docstrings explaining expected behavior
- Arrange-Act-Assert pattern within test methods

## Fixtures

**Core Fixtures from `/home/one/weekly/tests/conftest.py`:**

```python
@pytest.fixture
def client():
    """Create a test client with in-memory database."""
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
```

**Fixture Usage:**
- `client` - Unauthenticated test client
- `test_user` - Creates and returns user credentials dict
- `auth_client` - Pre-authenticated client for protected routes

## Mocking

**Framework:** `unittest.mock` (standard library)

**Patterns from `/home/one/weekly/tests/test_utils.py`:**
```python
from unittest.mock import patch, MagicMock

@patch('utils.datetime')
def test_this_week_start_is_monday(self, mock_datetime):
    """Test that this_week start is Monday of the current week."""
    mock_datetime.today.return_value.date.return_value = date(2026, 3, 25)

    with patch.object(DateRange, 'get_today', return_value=date(2026, 3, 25)):
        start, end = DateRange.this_week()
        assert start.weekday() == 0  # Monday
```

**What to Mock:**
- `datetime.now()` / `datetime.today()` for time-dependent tests
- External services (none currently in this project)
- File system operations for upload tests

**What NOT to Mock:**
- Database operations in integration tests (use in-memory SQLite)
- Form validation logic (test actual validators)
- Jinja2 filters (test actual filter behavior)

## Test Types

**Unit Tests:**
- Location: `/home/one/weekly/tests/test_utils.py`
- Scope: Pure functions and utility classes
- Examples: `DateRange` methods, `html_to_text()` function, `sanitize_html` filter

**Integration Tests:**
- Location: `/home/one/weekly/tests/test_routes.py`, `/home/one/weekly/tests/test_models.py`
- Scope: Route handlers, database operations, permission system
- Examples: Authentication flows, CRUD operations, permission checks

**E2E Tests:**
- Not used explicitly
- Flask test client simulates full request/response cycle

## Coverage

**Requirements:** No enforced minimum

**Current Coverage:** Coverage data exists in `/home/one/weekly/.coverage`

**View Coverage:**
```bash
pytest --cov=app --cov=models --cov=routes --cov=utils --cov-report=html
# Open htmlcov/index.html for detailed report
```

## Common Patterns

**Authentication Testing:**
```python
def test_login_success(self, client, test_user):
    """Test successful login with valid credentials."""
    response = client.post('/login', data={
        'username': test_user['username'],
        'password': test_user['password']
    }, follow_redirects=True)
    assert response.status_code == 200
    # Verify authenticated by accessing protected route
    protected_response = client.get('/manage_records')
    assert protected_response.status_code == 200
```

**Authorization Testing:**
```python
def test_edit_record_forbidden(self, client, test_user):
    """Test that user cannot edit another user's record."""
    # Create user A and their record
    client.post('/login', data={
        'username': test_user['username'],
        'password': test_user['password']
    })
    client.post('/create_records', data={
        'date': '2026-03-23',
        'body': '<p>User A record</p>'
    }, follow_redirects=True)
    client.get('/logout', follow_redirects=True)

    # Create user B and try to edit user A's record
    create_user_helper(client, 'userb', 'UserBPass123')
    client.post('/login', data={
        'username': 'userb',
        'password': 'UserBPass123'
    })
    response = client.get('/edit_record/1')
    assert response.status_code == 403
```

**Database Testing:**
```python
def test_create_record_success(self, auth_client):
    """Test successful record creation."""
    response = auth_client.post('/create_records', data={
        'date': '2026-03-23',
        'body': '<p>Test content</p>'
    }, follow_redirects=True)
    assert response.status_code == 200
    # Verify record exists in database
    with auth_client.application.app_context():
        record = Record.query.filter_by(content='<p>Test content</p>').first()
        assert record is not None
```

**Permission Testing:**
```python
def test_all_permissions_caches_result(self, client):
    """all_permissions should cache results on the g object."""
    with client.application.app_context():
        role = Role(name='employee', permissions=['view_self'])
        db.session.add(role)
        user = user_datastore.create_user(
            email='emp2@example.com',
            username='emp2user',
            password=hash_password('EmpPass123'),
            roles=[role]
        )
        db.session.commit()

        cache_key = f'_user_perms_{user.id}'
        if hasattr(g, cache_key):
            delattr(g, cache_key)

        result1 = User.all_permissions(user)
        result2 = User.all_permissions(user)

        assert result1 == result2
        assert hasattr(g, cache_key)
```

**XSS Prevention Testing:**
```python
def test_xss_script_filtered_on_home(self, auth_client):
    """Test that script tags are escaped in user content on home page."""
    auth_client.post('/create_records', data={
        'date': '2026-03-26',
        'body': '<script>alert("xss")</script><p>safe content</p>'
    }, follow_redirects=True)

    response = auth_client.get('/')
    assert response.status_code == 200
    assert b'safe content' in response.data
    assert b'&lt;script&gt;' in response.data or b'<script>alert' not in response.data
```

**Helper Functions in Tests:**
```python
def create_user_helper(client, username, password, roles=None):
    """Helper function to create additional users in tests."""
    with client.application.app_context():
        user = user_datastore.create_user(
            email=f'{username}@test.com',
            username=username,
            password=hash_password(password),
            roles=roles or []
        )
        db.session.commit()
        return {'username': username, 'password': password, 'id': user.id}
```

## Test Organization by Module

**test_models.py:** 19 tests
- `TestUserPermissions`: 10 tests for permission methods
- `TestAuthorizationFunctions`: 9 tests for authorization helpers

**test_routes.py:** 34 tests
- `TestAuthentication`: 11 tests for login/register/logout
- `TestRecordCRUD`: 15 tests for record operations
- `TestHomeRendering`: 3 tests for rich text display
- `TestXSSPrevention`: 4 tests for security

**test_utils.py:** 25 tests
- `TestDateRange`: 12 tests for date range calculations
- `TestHtmlToText`: 9 tests for HTML conversion
- `TestSanitizeHtml`: 11 tests for the Jinja2 filter

## CI/CD Testing

**Current State:** No CI/CD configuration detected

**Recommended Addition:**
```yaml
# .github/workflows/test.yml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - run: pip install -r requirements.txt
      - run: pytest --cov=app --cov-report=xml
```

---

*Testing analysis: 2026-03-26*