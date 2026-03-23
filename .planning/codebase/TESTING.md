# Testing Patterns

**Analysis Date:** 2026-03-23

## Test Framework

**Runner:**
- **None configured** - No test framework detected

**Missing Configuration:**
- No `pytest.ini`, `setup.cfg`, or `pyproject.toml` with test settings
- No test runner in `requirements.txt`
- No `tests/` or `test_*.py` files in project root

**Assertion Library:**
- Would use Python's built-in `assert` or test framework assertions

## Test File Organization

**Location:**
- **No test files exist in project directory**
- All test files found are in `.venv/` (third-party package tests)

**Expected Pattern (if tests were added):**
```
/home/one/weekly/
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── test_models.py
│   ├── test_routes.py
│   └── test_utils.py
├── test_app.py          # Alternative: co-located single file
└── ...
```

## Test Structure

**Current State:**
- No test files to analyze

**Recommended Structure (for future implementation):**
```python
# tests/conftest.py - pytest fixtures
import pytest
from app import app, db

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
            db.drop_all()

@pytest.fixture
def auth_client(client):
    # Create test user and authenticate
    ...
```

## Mocking

**Framework:**
- Not applicable (no tests)

**Recommended for Future Tests:**
- Use `unittest.mock` or `pytest-mock`
- Mock external services, file operations, and database for unit tests

**What to Mock:**
- `datetime.now()` / `datetime.today()` for time-dependent tests
- File system operations in upload tests
- External API calls (none currently)

**What NOT to Mock:**
- Database operations in integration tests (use test database)
- Form validation logic (test actual validators)

## Fixtures and Factories

**Current State:**
- No test fixtures exist

**Test Data Source:**
- `static/db_table_data.json` contains seed data for development/initial setup
- Could be adapted for test fixtures

**Location:**
- No fixture directory

## Coverage

**Requirements:**
- **No coverage requirements enforced**

**View Coverage:**
- Not applicable (no tests to measure)

## Test Types

**Unit Tests:**
- **None exist**
- Should test: `DateRange` methods, `html_to_text()` function, permission logic

**Integration Tests:**
- **None exist**
- Should test: route handlers, form submissions, database operations

**E2E Tests:**
- **Not used**
- Could use: Selenium, Playwright, or Flask's test client for full flow tests

## Testable Components

**High Priority for Testing:**

1. **DateRange utility class** (`utils.py` lines 6-93):
   - Time range calculations
   - Edge cases (year boundaries, week transitions)
   - Static method behavior

2. **html_to_text function** (`utils.py` lines 102-141):
   - HTML parsing
   - List conversion (ordered/unordered)
   - Nested element handling
   - Empty input handling

3. **User permission methods** (`app.py` lines 106-161):
   - `is_admin` property
   - `all_permissions()` with caching
   - `can_view_group()`
   - `managed_group()`

4. **Route authorization**:
   - `can_edit_record()` function
   - `get_allowed_usernames()` function
   - `build_record_query()` function

## Testing Recommendations

**Immediate Actions:**

1. Add pytest to requirements.txt:
```
pytest==8.0.0
pytest-cov==4.1.0
```

2. Create test directory structure:
```bash
mkdir tests
touch tests/__init__.py tests/conftest.py
```

3. Create initial tests for critical path:
```python
# tests/test_utils.py
from utils import DateRange, html_to_text
from datetime import date

class TestDateRange:
    def test_this_week_returns_tuple(self):
        result = DateRange.this_week()
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_get_range_default(self):
        result = DateRange.get_range('unknown')
        assert result == DateRange.this_year()

class TestHtmlToText:
    def test_empty_input(self):
        assert html_to_text('') == ''
        assert html_to_text(None) == ''

    def test_plain_text(self):
        assert html_to_text('<p>Hello</p>') == 'Hello'
```

**Run Commands (after setup):**
```bash
pytest                    # Run all tests
pytest -v                 # Verbose output
pytest --cov=app utils    # Coverage report
pytest -x                 # Stop on first failure
```

## Flask Test Client Usage

**Pattern for route testing:**
```python
def test_home_requires_login(client):
    response = client.get('/')
    assert response.status_code == 302  # Redirect to login

def test_home_authenticated(auth_client):
    response = auth_client.get('/')
    assert response.status_code == 200
    assert b'本周' in response.data
```

## Database Testing

**Pattern:**
```python
@pytest.fixture
def test_db():
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    with app.app_context():
        db.create_all()
        yield db
        db.drop_all()
```

---

*Testing analysis: 2026-03-23*