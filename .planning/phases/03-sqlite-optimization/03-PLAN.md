---
phase: 03-sqlite-optimization
plan: 01
type: execute
wave: 1
depends_on: []
files_modified: [app.py]
autonomous: true
requirements: [STAB-03]
must_haves:
  truths:
    - "PRAGMA journal_mode query returns 'wal'"
    - "SQLite WAL mode is enabled on database connections"
    - "Application logs confirm WAL mode activation"
  artifacts:
    - path: "app.py"
      provides: "WAL mode enablement via SQLAlchemy event listener"
      contains: "PRAGMA journal_mode=WAL"
  key_links:
    - from: "SQLAlchemy engine"
      to: "SQLite database"
      via: "connect event listener"
      pattern: "event\\.listens_for.*connect"
---

<objective>
Enable SQLite WAL mode to optimize concurrent read/write performance and prevent database locking issues.

Purpose: SQLite WAL (Write-Ahead Logging) allows concurrent readers during writes, eliminating the "database is locked" errors common with the default rollback journal mode.

Output: Modified app.py with WAL enablement and verification logging.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/PROJECT.md
@.planning/ROADMAP.md
@.planning/STATE.md

## User Decisions (from CONTEXT.md)

- **D-01:** Execute `PRAGMA journal_mode=WAL` on database connection
- **D-02:** Use SQLAlchemy event listener for connection hook
- **D-03:** Use SQLite default auto-checkpoint (no manual configuration)
- **D-04:** Use default wal_autocheckpoint threshold (1000 pages)
- **D-05:** Verify WAL mode by querying `PRAGMA journal_mode` at startup
- **D-06:** Log WAL mode activation status

## Existing Code Context

From app.py:
- Line 33: `app.config['SQLALCHEMY_DATABASE_URI']` - database URI configuration
- Lines 35-40: `SQLALCHEMY_ENGINE_OPTIONS` - existing pool configuration
- Line 62: `db = SQLAlchemy(app)` - database initialization
- Lines 93-125: `setup_logging(app)` - logging configuration

</context>

<tasks>

<task type="auto">
  <name>Task 1: Add SQLAlchemy event listener to enable WAL mode</name>
  <files>app.py</files>
  <read_first>
    - app.py lines 1-20 (imports section)
    - app.py lines 31-62 (database configuration)
  </read_first>
  <action>
    Add a SQLAlchemy event listener that enables WAL mode on each new database connection.

    **Implementation (per D-01, D-02):**
    1. Add the `event` import from sqlalchemy at the top of app.py (line ~9):
       ```python
       from sqlalchemy import event
       ```

    2. After `db = SQLAlchemy(app)` (after line 62), add the WAL enablement listener:
       ```python
       # Enable SQLite WAL mode for better concurrent performance
       @event.listens_for(db.engine, "connect")
       def set_sqlite_pragma(dbapi_connection, connection_record):
           """Enable WAL mode on SQLite connections per D-01, D-02."""
           cursor = dbapi_connection.cursor()
           cursor.execute("PRAGMA journal_mode=WAL")
           cursor.close()
       ```

    **Why this approach:**
    - SQLAlchemy event listener is the standard way to execute PRAGMA statements on new connections
    - Using `connect` event ensures WAL mode is set for every new connection in the pool
    - WAL mode persists for the database file, so subsequent connections inherit it

    **Note:** Only applies to SQLite databases. The listener will silently work for SQLite and do nothing for other database backends.
  </action>
  <verify>
    <automated>grep -n "PRAGMA journal_mode=WAL" /home/one/weekly/app.py</automated>
  </verify>
  <done>
    - SQLAlchemy event listener added to app.py
    - WAL mode PRAGMA executes on each new database connection
  </done>
</task>

<task type="auto">
  <name>Task 2: Add startup verification for WAL mode</name>
  <files>app.py</files>
  <read_first>
    - app.py lines 137-141 (existing app_context block)
  </read_first>
  <action>
    Add verification logic that confirms WAL mode is enabled and logs the status.

    **Implementation (per D-05, D-06):**
    Add a verification function and call it during app startup. Insert after the `ensure_record_columns()` call in the existing `with app.app_context():` block (around line 137-138):

    ```python
    def verify_wal_mode():
        """Verify SQLite WAL mode is enabled per D-05, D-06."""
        try:
            result = db.session.execute(text("PRAGMA journal_mode")).scalar()
            if result and result.lower() == 'wal':
                current_app.logger.info(f"SQLite WAL mode verified: {result}")
            else:
                current_app.logger.warning(f"SQLite WAL mode not active: {result}")
        except Exception as e:
            current_app.logger.warning(f"Could not verify WAL mode: {e}")
    ```

    Then call it in the existing app_context block:
    ```python
    with app.app_context():
        ensure_record_columns()
        verify_wal_mode()  # Add this line
    ```

    **Existing context (from app.py lines 137-138):**
    ```python
    with app.app_context():
        ensure_record_columns()
    ```

    **After modification:**
    ```python
    with app.app_context():
        ensure_record_columns()
        verify_wal_mode()
    ```
  </action>
  <verify>
    <automated>grep -n "verify_wal_mode" /home/one/weekly/app.py</automated>
  </verify>
  <done>
    - verify_wal_mode() function defined in app.py
    - Function called during app startup
    - WAL mode status logged at INFO level
  </done>
</task>

</tasks>

<verification>
1. Start the application and verify logs contain "SQLite WAL mode verified: wal"
2. Query the database directly: `sqlite3 app.db "PRAGMA journal_mode;"` returns "wal"
3. Verify WAL files exist after writes: `app.db-wal` and `app.db-shm`
</verification>

<success_criteria>
1. SQLite WAL mode is enabled and verified
2. Concurrent read/write operations no longer cause database locks
3. Database performance remains stable under normal usage (10-50 users)
</success_criteria>

<output>
After completion, create `.planning/phases/03-sqlite-optimization/03-01-SUMMARY.md`
</output>