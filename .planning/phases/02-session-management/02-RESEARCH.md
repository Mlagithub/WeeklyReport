# Phase 2: Session Management - Research

**Researched:** 2026-03-23
**Domain:** Flask-SQLAlchemy 3.x Session Management / Error Handling / Transaction Patterns
**Confidence:** HIGH (Well-documented patterns, training knowledge with codebase verification)

## Summary

This phase implements proper database session management and error handling for a Flask application using Flask-SQLAlchemy 3.1.1. Flask-SQLAlchemy 3.x automatically manages session lifecycle (no manual teardown needed), but write operations require explicit error handling with rollback. The solution uses a `@with_db_transaction` decorator pattern applied to write operations only, with rollback and re-raise on exception, user-friendly flash messages, and structured logging via the Phase 1 logging configuration.

**Primary recommendation:** Create a simple `@with_db_transaction` decorator that wraps write operations, catches SQLAlchemy exceptions, logs full stack traces, rolls back the session, flashes a generic user message, and re-raises for Flask's error handler.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- **D-01:** Rely on Flask-SQLAlchemy automatic session lifecycle management
- **D-02:** Do NOT add explicit `teardown_appcontext` cleanup (Flask-SQLAlchemy 3.x handles this)
- **D-03:** Create `@with_db_transaction` decorator for unified database error handling
- **D-04:** Decorator applies to **write operations only** (insert/update/delete), read operations need no handling
- **D-05:** Decorator implements try/except/rollback/re-raise pattern
- **D-06:** On exception, execute `db.session.rollback()` then re-raise the exception
- **D-07:** Do NOT catch the exception - let Flask error handler process it
- **D-08:** User sees simple generic message: "操作失败，请重试"
- **D-09:** Log full exception stack trace using Phase 1 configured logging system
- **D-10:** Use `current_app.logger.error()` for database error logging

### Claude's Discretion
- Specific decorator name and parameter design
- Which route functions need the decorator applied
- Whether to use dedicated error pages or Flask's default 500 handler

### Deferred Ideas (OUT OF SCOPE)
None - discussion stayed within phase scope
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| STAB-02 | Database sessions properly closed after each request (no connection leaks) | Flask-SQLAlchemy 3.x automatic session management via scoped_session |
| STAB-04 | All database operations have error handling and transaction rollback | @with_db_transaction decorator pattern, SQLAlchemy exception hierarchy |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Flask-SQLAlchemy | 3.1.1 | ORM and session management | Already in project, handles session lifecycle automatically |
| SQLAlchemy | 2.x | Database abstraction | Transitive dependency, provides exception classes |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| functools | stdlib | Decorator utilities | Always - @wraps preserves function metadata |
| flask | 3.0.3 | flash(), current_app | Already in project - user feedback and logging |

### Exception Hierarchy
```
SQLAlchemyError (base class)
├── IntegrityError     - Unique constraint, foreign key violations
├── OperationalError   - Connection issues, table doesn't exist
├── DataError          - Data type mismatches
├── InterfaceError     - Database driver errors
└── DatabaseError      - General database errors
```

### Installation
```bash
# No additional packages needed - all dependencies already in requirements.txt
# Flask-SQLAlchemy 3.1.1 is already specified
```

## Architecture Patterns

### Recommended Code Structure
```
app.py
├── Decorator definition (NEW - after imports, before routes)
│   └── def with_db_transaction(func): ...
│
├── Routes with decorator applied (MODIFY)
│   ├── @with_db_transaction
│   │   def create_records(): ...
│   │
│   ├── @with_db_transaction
│   │   def edit_record(): ...
│   │
│   ├── @with_db_transaction
│   │   def delete_record(): ...
│   │
│   ├── @with_db_transaction
│   │   def register(): ...
│   │
│   └── (no decorator)  # Read-only routes
│       def manage_records(): ...
│       def home(): ...
│
└── Helper functions with decorator (MODIFY)
    └── User.change_user_password(): ...
```

### Pattern 1: Transaction Decorator
**What:** Decorator that wraps database write operations with error handling
**When to use:** All routes/functions that perform INSERT, UPDATE, or DELETE operations
**Example:**
```python
from functools import wraps
from flask import flash, current_app
from sqlalchemy.exc import SQLAlchemyError

def with_db_transaction(func):
    """
    Decorator for database write operations.
    Implements D-03, D-05, D-06, D-08, D-09, D-10.

    - Catches SQLAlchemy exceptions
    - Logs full stack trace
    - Rolls back transaction
    - Flashes user-friendly message
    - Re-raises for Flask error handler
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except SQLAlchemyError as e:
            # D-09: Log full exception stack trace
            current_app.logger.error(
                f"Database error in {func.__name__}: {str(e)}",
                exc_info=True
            )
            # D-06: Rollback transaction
            db.session.rollback()
            # D-08: Flash generic user message
            flash('操作失败，请重试', 'warning')
            # D-07: Re-raise for Flask error handler
            raise
    return wrapper
```

### Pattern 2: Decorator Application
**What:** Apply decorator to route functions with write operations
**When to use:** Routes that modify database state
**Example:**
```python
# CREATE operation - app.py line 515-534
@app.route('/create_records', methods=('GET', 'POST'))
@login_required
@with_db_transaction  # Add decorator
def create_records():
    form = RecordForm()
    if form.validate_on_submit():
        record = Record()
        record.date = form.date.data
        record.content = form.body.data
        record.createtime = datetime.now()
        current_user.records.append(record)
        db.session.add(record)
        db.session.commit()  # Decorator handles errors
        flash('已提交')
        return redirect(url_for('manage_records'))
    return render_template('create_records.html', form=form)

# UPDATE operation - app.py line 537-559
@app.route('/edit_record/<int:record_id>', methods=['POST', 'GET'])
@login_required
@with_db_transaction  # Add decorator
def edit_record(record_id):
    # ... existing code ...
    db.session.commit()  # Decorator handles errors
    # ... rest of function ...

# DELETE operation - app.py line 562-574
@app.route('/delete_record/<int:record_id>', methods=['POST', 'GET'])
@login_required
@with_db_transaction  # Add decorator
def delete_record(record_id):
    # ... existing code ...
    db.session.delete(record)
    db.session.commit()  # Decorator handles errors
    # ... rest of function ...
```

### Pattern 3: Logging Integration
**What:** Use Phase 1 logging configuration for database errors
**When to use:** In the exception handler of the decorator
**Example:**
```python
# Phase 1 already configured in app.py lines 62-94:
# - RotatingFileHandler at /var/log/weekly/app.log
# - INFO level
# - Format: '%(asctime)s - %(name)s - %(levelname)s - %(message)s [in %(pathname)s:%(lineno)d]'

# In decorator, use current_app.logger:
current_app.logger.error(
    f"Database error in {func.__name__}",
    exc_info=True  # Includes full stack trace
)

# Log output will appear in /var/log/weekly/app.log
```

### Pattern 4: Static Method Decoration
**What:** Applying decorator to static methods in model classes
**When to use:** Helper methods that perform database writes
**Example:**
```python
# User.change_user_password - app.py line 190-200
@staticmethod
@with_db_transaction
def change_user_password(username, password):
    user = User.query.filter_by(username=username).first()
    if user:
        user.password = hash_password(password)
        db.session.commit()
        flash("密码已更改")
        return True
    else:
        flash(f"用户{username}不存在", 'warning')
        return False
```

### Anti-Patterns to Avoid

- **Catching Exception too broadly:** Use `SQLAlchemyError` not `Exception` to avoid catching non-database errors
- **Not re-raising:** Swallowing exceptions hides issues and prevents Flask error handling
- **Decorating read operations:** Read-only operations don't need rollback; decorator adds unnecessary overhead
- **Using db.session.remove():** Flask-SQLAlchemy 3.x handles this automatically; manual calls cause issues
- **Multiple flash messages:** Decorator handles the error flash; don't add another in the route

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Session cleanup | Manual teardown_appcontext | Flask-SQLAlchemy built-in | Automatic, tested, handles edge cases |
| Transaction management | Manual try/except in every route | @with_db_transaction decorator | DRY, consistent error handling |
| Exception hierarchy | Custom error classes | SQLAlchemyError and subclasses | Standard, well-documented |
| Logging setup | Custom logger configuration | Phase 1 setup (RotatingFileHandler) | Already configured, consistent format |

**Key insight:** Flask-SQLAlchemy 3.x removes the need for manual session cleanup. Focus on error handling, not lifecycle management.

## Common Pitfalls

### Pitfall 1: Decorator Order Matters
**What goes wrong:** Decorator doesn't work because @app.route processes the function first
**Why it happens:** Flask route decorator must be the outermost decorator
**How to avoid:**
```python
# CORRECT: @app.route is outermost
@app.route('/create_records')
@login_required
@with_db_transaction
def create_records():
    pass

# INCORRECT: @with_db_transaction outermost
@with_db_transaction
@app.route('/create_records')  # This breaks routing
def create_records():
    pass
```
**Warning signs:** Route returns 404, decorator never executes

### Pitfall 2: Flash Message Duplication
**What goes wrong:** User sees multiple error messages
**Why it happens:** Both decorator and route handler flash messages on error
**How to avoid:** Decorator handles error flash; route should only flash on success
```python
# CORRECT: Only success flash in route
@with_db_transaction
def create_records():
    # ... db operations ...
    db.session.commit()
    flash('已提交')  # Success message only
    return redirect(...)

# INCORRECT: Error flash in route
@with_db_transaction
def create_records():
    try:
        db.session.commit()
        flash('已提交')
    except:
        flash('操作失败')  # DUPLICATE - decorator already flashes
```
**Warning signs:** Two "操作失败" messages on error

### Pitfall 3: Forgetting db.session.commit()
**What goes wrong:** Changes not persisted to database
**Why it happens:** Decorator catches exceptions but doesn't auto-commit
**How to avoid:** Always call `db.session.commit()` at end of write operations
```python
# CORRECT: Explicit commit
@with_db_transaction
def create_records():
    db.session.add(record)
    db.session.commit()  # REQUIRED

# INCORRECT: Missing commit
@with_db_transaction
def create_records():
    db.session.add(record)
    # No commit - data not saved
```
**Warning signs:** No error, but data not in database

### Pitfall 4: Using @login_required Inside Decorator
**What goes wrong:** Authentication bypassed or errors
**Why it happens:** Decorator execution order issues
**How to avoid:** Keep @login_required between @app.route and @with_db_transaction
```python
# CORRECT order (inside to outside execution):
# 1. @with_db_transaction executes first (innermost)
# 2. @login_required executes second
# 3. @app.route executes last (outermost)

@app.route('/create_records')
@login_required
@with_db_transaction
def create_records():
    pass
```

### Pitfall 5: Static Method Decoration Syntax
**What goes wrong:** Decorator doesn't apply correctly to static methods
**Why it happens:** @staticmethod must be the outermost decorator for static methods
**How to avoid:**
```python
# CORRECT: @staticmethod outermost
class User:
    @staticmethod
    @with_db_transaction
    def change_user_password(username, password):
        pass

# INCORRECT: @with_db_transaction outermost
class User:
    @with_db_transaction
    @staticmethod  # This breaks the decorator
    def change_user_password(username, password):
        pass
```

### Pitfall 6: Rollback Before Logging
**What goes wrong:** Logging loses transaction context
**Why it happens:** Order of operations in exception handler
**How to avoid:** Log first, then rollback
```python
# CORRECT: Log before rollback
except SQLAlchemyError as e:
    current_app.logger.error(...)  # Log first
    db.session.rollback()           # Then rollback

# INCORRECT: Rollback before logging (minor issue)
except SQLAlchemyError as e:
    db.session.rollback()
    current_app.logger.error(...)  # Session already rolled back
```

## Code Examples

### Complete Decorator Implementation
```python
# Add to app.py after imports (around line 60)
from functools import wraps
from flask import flash, current_app
from sqlalchemy.exc import SQLAlchemyError

def with_db_transaction(func):
    """
    Decorator for database write operations.

    Per D-03: Unified error handling
    Per D-05: try/except/rollback/re-raise pattern
    Per D-06: Rollback on exception
    Per D-07: Re-raise after rollback
    Per D-08: Flash generic user message
    Per D-09: Log full stack trace
    Per D-10: Use current_app.logger.error()
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except SQLAlchemyError as e:
            # Log full exception with stack trace
            current_app.logger.error(
                f"Database error in {func.__name__}: {str(e)}",
                exc_info=True
            )
            # Rollback the transaction
            db.session.rollback()
            # Flash user-friendly message
            flash('操作失败，请重试', 'warning')
            # Re-raise for Flask error handler
            raise
    return wrapper
```

### Modified Route: create_records()
```python
# app.py line 515-534 (MODIFIED)
@app.route('/create_records', methods=('GET', 'POST'))
@login_required
@with_db_transaction  # NEW: Add decorator
def create_records():
    form = RecordForm()
    if form.validate_on_submit():
        record_date = form.date.data
        body = form.body.data
        record = Record()
        record.createtime = datetime.now()
        record.date = record_date
        record.content = body
        current_user.records.append(record)
        db.session.add(record)
        db.session.commit()

        flash('已提交')
        return redirect(url_for('manage_records'))

    return render_template('create_records.html', form=form)
```

### Modified Route: edit_record()
```python
# app.py line 537-559 (MODIFIED)
@app.route('/edit_record/<int:record_id>', methods=['POST', 'GET'])
@login_required
@with_db_transaction  # NEW: Add decorator
def edit_record(record_id):
    form = RecordForm()
    record = db.session.get(Record, record_id)
    if not record:
        abort(404)
    if not can_edit_record(record, current_user):
        abort(403)
    if form.validate_on_submit():
        record.date = form.date.data
        record.content = form.body.data
        record.createtime = datetime.now()
        db.session.commit()
        flash('已提交')
        return redirect(url_for('manage_records'))
    else:
        form.date.data = record.date
        form.body.data = record.content

    return render_template('create_records.html', form=form)
```

### Modified Route: delete_record()
```python
# app.py line 562-574 (MODIFIED)
@app.route('/delete_record/<int:record_id>', methods=['POST', 'GET'])
@login_required
@with_db_transaction  # NEW: Add decorator
def delete_record(record_id):
    record = db.session.get(Record, record_id)
    if record and can_edit_record(record, current_user):
        db.session.delete(record)
        db.session.commit()
        flash('数据已删除')
    elif not record:
        abort(404)
    else:
        abort(403)
    return redirect(url_for('manage_records'))
```

### Modified Route: register()
```python
# app.py line 448-468 (MODIFIED)
@app.route('/register', methods=['GET', 'POST'])
@with_db_transaction  # NEW: Add decorator
def register():
    form = MyRegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        if User.query.filter_by(username=username).first():
            flash('用户名已存在', 'warning')
            return render_template('security/register_user.html', register_user_form=form)
        email = f"{username}_{uuid.uuid4().hex[:8]}@local"
        user = user_datastore.create_user(
            email=email,
            username=username,
            password=hash_password(form.password.data)
        )
        db.session.commit()
        flash('注册成功，请登录')
        return redirect(url_for('login'))
    return render_template('security/register_user.html', register_user_form=form)
```

### Modified Static Method: User.change_user_password()
```python
# app.py line 190-200 (MODIFIED)
@staticmethod
@with_db_transaction  # NEW: Add decorator
def change_user_password(username, password):
    user = User.query.filter_by(username=username).first()
    if user:
        user.password = hash_password(password)
        db.session.commit()
        flash("密码已更改")
        return True
    else:
        flash(f"用户{username}不存在", 'warning')
        return False
```

## Write Operations Inventory

| Route/Function | Line | Operation | Commit Line | Needs Decorator |
|----------------|------|-----------|-------------|-----------------|
| `create_records()` | 515-534 | INSERT Record | 528 | YES |
| `edit_record()` | 537-559 | UPDATE Record | 552 | YES |
| `delete_record()` | 562-574 | DELETE Record | 568 | YES |
| `register()` | 448-468 | INSERT User | 465 | YES |
| `User.change_user_password()` | 190-200 | UPDATE User | 195 | YES |
| `ensure_record_columns()` | 96-104 | ALTER TABLE | 104 | NO (startup only) |
| `update_db_from_json()` | 722-778 | INSERT Role/Group/User | 738, 751, 778 | NO (startup only) |

**Note:** `ensure_record_columns()` and `update_db_from_json()` are startup functions that run before the application serves requests. They don't need the decorator because:
1. They run in `app.app_context()` context, not request context
2. `current_app.logger` may not be available
3. No user to flash messages to
4. Errors during startup should crash the application (fail-fast)

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Manual session.remove() | Flask-SQLAlchemy automatic cleanup | Flask-SQLAlchemy 3.0 | Simplified code, no connection leaks |
| try/except in every route | @with_db_transaction decorator | This phase | DRY, consistent error handling |
| print() or basic logging | Structured logging with RotatingFileHandler | Phase 1 | Production-ready logs, rotation |
| Generic exception handling | SQLAlchemyError specific | SQLAlchemy 2.0 | Better error categorization |

**Deprecated/outdated:**
- **Manual teardown_appcontext:** Not needed in Flask-SQLAlchemy 3.x
- **db.session.remove() in routes:** Handled automatically
- **Global try/except in routes:** Use decorator pattern instead

## Open Questions

1. **Should the decorator also catch IntegrityError specifically?**
   - What we know: IntegrityError is a subclass of SQLAlchemyError
   - What's unclear: Whether to handle unique constraint violations differently (e.g., "用户名已存在")
   - Recommendation: No - current design catches SQLAlchemyError which includes IntegrityError. Specific messages are handled in route logic (e.g., register() checks if username exists before insert).

2. **Should update_db_from_json() have error handling?**
   - What we know: Runs at startup, seeds database from JSON
   - What's unclear: Whether errors should crash startup or be logged
   - Recommendation: Keep without decorator. Startup errors should be visible (fail-fast). The function already has idempotent checks (existing_role, existing_group, existing_user).

3. **Should the decorator return a specific value on error?**
   - What we know: D-07 says re-raise the exception
   - What's unclear: Whether routes expect a return value after error
   - Recommendation: No return value - re-raise ensures Flask error handler processes the exception. Routes that redirect after success won't reach the redirect on error anyway.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Flask-SQLAlchemy | ORM | Yes | 3.1.1 | - |
| SQLAlchemy | Exception classes | Yes | 2.x (transitive) | - |
| Flask | flash, current_app | Yes | 3.0.3 | - |
| functools | @wraps | Yes | stdlib | - |
| RotatingFileHandler | Logging | Yes | stdlib | - |

**Missing dependencies with no fallback:**
- None - all dependencies already in project

**Missing dependencies with fallback:**
- None

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | pytest (not yet installed) |
| Config file | None - needs pytest.ini |
| Quick run command | `pytest tests/ -x` (after setup) |
| Full suite command | `pytest tests/ -v` (after setup) |

### Phase Requirements -> Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| STAB-02 | Sessions closed after request | integration | `pytest tests/test_session.py -x` | Wave 0 |
| STAB-04 | Rollback on database error | unit | `pytest tests/test_transaction.py -x` | Wave 0 |
| STAB-04 | Flash message shown on error | unit | `pytest tests/test_flash.py -x` | Wave 0 |
| STAB-04 | Error logged with stack trace | unit | `pytest tests/test_logging.py -x` | Wave 0 |

### Sampling Rate
- **Per task commit:** `pytest tests/ -x` (quick, stops on first failure)
- **Per wave merge:** `pytest tests/ -v` (full suite)
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `tests/` directory - Create test structure
- [ ] `tests/conftest.py` - Flask test client fixture, database setup
- [ ] `tests/test_session.py` - STAB-02 tests
- [ ] `tests/test_transaction.py` - STAB-04 rollback tests
- [ ] `pytest.ini` - Test configuration
- [ ] `pytest` in requirements.txt - Add test dependency

**Note:** Test infrastructure is created in Phase 4 (Unit Testing). This phase focuses on implementation. Manual verification steps:
1. Trigger a database error (e.g., duplicate username)
2. Verify flash message appears
3. Check `/var/log/weekly/app.log` for error entry
4. Verify application continues to function

## Sources

### Primary (HIGH confidence)
- Flask-SQLAlchemy 3.x documentation (training knowledge) - scoped_session automatic management
- SQLAlchemy 2.x documentation (training knowledge) - exception hierarchy
- Python functools documentation (training knowledge) - @wraps decorator

### Secondary (MEDIUM confidence)
- Flask best practices for error handling (community patterns)
- Flask flash message patterns (standard Flask functionality)

### Tertiary (LOW confidence)
- None - patterns are well-established

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - Flask-SQLAlchemy 3.1.1 already in project
- Architecture: HIGH - Decorator pattern is standard Python, Flask-SQLAlchemy 3.x session handling is well-documented
- Pitfalls: HIGH - Common issues with decorator ordering and Flask routes are well-known

**Research date:** 2026-03-23
**Valid until:** 2026-09-23 (6 months - stable patterns, Flask-SQLAlchemy 3.x API stable)