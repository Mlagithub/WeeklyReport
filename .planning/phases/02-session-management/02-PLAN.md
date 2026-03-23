---
phase: 02-session-management
plan: 01
type: execute
wave: 1
depends_on: []
files_modified: [app.py]
autonomous: true
requirements: [STAB-02, STAB-04]
user_setup: []

must_haves:
  truths:
    - "Database write operations have error handling with rollback"
    - "User sees flash message on database error"
    - "Full exception stack trace is logged"
    - "Application continues to function after database errors"
  artifacts:
    - path: "app.py"
      provides: "@with_db_transaction decorator and decorated routes"
      contains: "def with_db_transaction"
      contains: "@with_db_transaction"
  key_links:
    - from: "@with_db_transaction decorator"
      to: "create_records, edit_record, delete_record, register, User.change_user_password"
      via: "decorator application"
      pattern: "@with_db_transaction"
---

<objective>
Implement database session error handling with @with_db_transaction decorator.

Purpose: Prevent connection leaks and ensure proper transaction rollback on errors (STAB-02, STAB-04)
Output: Working decorator applied to all write operations
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/PROJECT.md
@.planning/ROADMAP.md
@.planning/STATE.md
@.planning/phases/02-session-management/02-CONTEXT.md
@.planning/phases/02-session-management/02-RESEARCH.md
</context>

<interfaces>
<!-- Key imports the executor needs -->
```python
from functools import wraps
from flask import flash, current_app
from sqlalchemy.exc import SQLAlchemyError
```

<!-- Existing logging configuration (Phase 1) -->
```python
# app.py lines 62-94: RotatingFileHandler at /var/log/weekly/app.log
# Use: current_app.logger.error(message, exc_info=True)
```

<!-- Routes to decorate (write operations only) -->
| Route | Line | Operation |
|-------|------|-----------|
| create_records() | 515-534 | INSERT Record |
| edit_record() | 537-559 | UPDATE Record |
| delete_record() | 562-574 | DELETE Record |
| register() | 448-468 | INSERT User |
| User.change_user_password() | 190-200 | UPDATE User |
</interfaces>

<tasks>

<task type="auto">
  <name>Task 1: Create @with_db_transaction decorator</name>
  <files>app.py</files>
  <read_first>
    - app.py lines 1-60 (imports and configuration)
    - app.py lines 62-94 (logging setup from Phase 1)
  </read_first>
  <behavior>
    - Decorator catches SQLAlchemyError exceptions
    - Logs full stack trace with current_app.logger.error(exc_info=True)
    - Rolls back transaction with db.session.rollback()
    - Flashes generic message "操作失败，请重试" with category 'warning'
    - Re-raises exception for Flask error handler
  </behavior>
  <action>
    Add the following decorator after imports (around line 60, after `db = SQLAlchemy(app)`):

    ```python
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
                # Log full exception with stack trace (D-09, D-10)
                current_app.logger.error(
                    f"Database error in {func.__name__}: {str(e)}",
                    exc_info=True
                )
                # Rollback the transaction (D-06)
                db.session.rollback()
                # Flash user-friendly message (D-08)
                flash('操作失败，请重试', 'warning')
                # Re-raise for Flask error handler (D-07)
                raise
        return wrapper
    ```

    Note: `functools` import may already exist. Check line 1-26 imports and add `wraps` if needed.
    Note: `flash` and `current_app` are already imported from flask at line 1.
    Note: `SQLAlchemyError` needs to be added to the sqlalchemy import at line 9.

    Update line 9 from:
    ```python
    from sqlalchemy import inspect, text, func, case, and_
    ```
    to:
    ```python
    from sqlalchemy import inspect, text, func, case, and_
    from sqlalchemy.exc import SQLAlchemyError
    ```

    Add `wraps` to imports - add near line 1 with functools import if not present.
  </action>
  <verify>
    <automated>grep -q "def with_db_transaction" app.py && grep -q "from sqlalchemy.exc import SQLAlchemyError" app.py && grep -q "@wraps(func)" app.py</automated>
  </verify>
  <done>
    - Decorator function `with_db_transaction` exists in app.py
    - Import for SQLAlchemyError added
    - Import for wraps added (if not present)
    - Decorator implements D-03 through D-10 requirements
  </done>
</task>

<task type="auto">
  <name>Task 2: Apply decorator to 5 write operation routes</name>
  <files>app.py</files>
  <read_first>
    - app.py lines 448-468 (register route)
    - app.py lines 515-534 (create_records route)
    - app.py lines 537-559 (edit_record route)
    - app.py lines 562-574 (delete_record route)
    - app.py lines 190-200 (User.change_user_password static method)
  </read_first>
  <behavior>
    - Decorator is applied to 5 write operations
    - Decorator order is correct: @app.route -> @login_required -> @with_db_transaction
    - For static methods: @staticmethod is outermost, then @with_db_transaction
  </behavior>
  <action>
    Apply @with_db_transaction decorator to the following routes/functions:

    1. **register()** (line 448-468):
       ```python
       @app.route('/register', methods=['GET', 'POST'])
       @with_db_transaction  # ADD THIS LINE
       def register():
       ```

    2. **create_records()** (line 515-534):
       ```python
       @app.route('/create_records', methods=('GET', 'POST'))
       @login_required
       @with_db_transaction  # ADD THIS LINE
       def create_records():
       ```

    3. **edit_record()** (line 537-559):
       ```python
       @app.route('/edit_record/<int:record_id>', methods=['POST', 'GET'])
       @login_required
       @with_db_transaction  # ADD THIS LINE
       def edit_record(record_id):
       ```

    4. **delete_record()** (line 562-574):
       ```python
       @app.route('/delete_record/<int:record_id>', methods=['POST', 'GET'])
       @login_required
       @with_db_transaction  # ADD THIS LINE
       def delete_record(record_id):
       ```

    5. **User.change_user_password()** (line 190-200):
       ```python
       @staticmethod
       @with_db_transaction  # ADD THIS LINE
       def change_user_password(username, password):
       ```

    **IMPORTANT: Decorator order matters (per RESEARCH.md Pitfall 1 and 5)**
    - For routes: @app.route is outermost, then @login_required, then @with_db_transaction
    - For static methods: @staticmethod is outermost, then @with_db_transaction
  </action>
  <verify>
    <automated>grep -c "@with_db_transaction" app.py | grep -q "5"</automated>
  </verify>
  <done>
    - All 5 write operations have @with_db_transaction decorator
    - Decorator order is correct for routes (@app.route outermost)
    - Decorator order is correct for static methods (@staticmethod outermost)
    - No read operations have the decorator (manage_records, home, etc.)
  </done>
</task>

<task type="checkpoint:human-verify" gate="blocking">
  <what-built>
    Complete database error handling system:
    - @with_db_transaction decorator with rollback, logging, flash message
    - Decorator applied to 5 write operations (register, create_records, edit_record, delete_record, change_user_password)
  </what-built>
  <how-to-verify>
    1. Start the application: `python app.py` or `gunicorn app:app`
    2. Test successful write: Login and create a new record - should see "已提交" flash
    3. Test error handling: Try to register with an existing username - should see "用户名已存在" then "操作失败，请重试"
    4. Check logs: `tail -20 /var/log/weekly/app.log` - should see error entries with stack traces if errors occurred
    5. Verify app continues: After error, try another operation - app should still work
  </how-to-verify>
  <resume-signal>Type "approved" or describe issues found</resume-signal>
</task>

</tasks>

<verification>
**Automated checks:**
- Decorator exists: `grep -q "def with_db_transaction" app.py`
- SQLAlchemyError imported: `grep -q "from sqlalchemy.exc import SQLAlchemyError" app.py`
- Decorator applied to 5 functions: `grep -c "@with_db_transaction" app.py` returns 5

**Manual verification:**
- Create record successfully - flash message appears
- Trigger database error - flash "操作失败，请重试" appears
- Check log file for error stack trace
- App continues to respond after error
</verification>

<success_criteria>
1. Database sessions are properly closed after each request (Flask-SQLAlchemy 3.x automatic - D-01, D-02)
2. Database errors are caught and logged with meaningful messages (D-09, D-10)
3. Failed transactions are properly rolled back (D-05, D-06)
4. Application continues to function after database errors (D-07 - re-raise allows Flask error handling)
5. User sees generic error message "操作失败，请重试" (D-08)
</success_criteria>

<output>
After completion, create `.planning/phases/02-session-management/02-01-SUMMARY.md`
</output>