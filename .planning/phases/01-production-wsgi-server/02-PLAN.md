---
phase: 01-production-wsgi-server
plan: 02
type: execute
wave: 1
depends_on: []
files_modified:
  - app.py
  - logrotate.weekly
autonomous: true
requirements: [STAB-01]
user_setup:
  - service: logrotate
    why: "Logrotate config requires sudo to deploy"
    env_vars: []
    dashboard_config:
      - task: "Copy logrotate config"
        location: "Requires sudo: sudo cp logrotate.weekly /etc/logrotate.d/weekly"

must_haves:
  truths:
    - "Application logs are written to /var/log/weekly/app.log"
    - "Logs are at INFO level"
    - "Log files are automatically rotated"
    - "Log rotation includes compression"
  artifacts:
    - path: "app.py"
      provides: "Flask logging configuration"
      contains: "RotatingFileHandler"
      min_lines: 750
    - path: "logrotate.weekly"
      provides: "Log rotation configuration"
      contains: "/var/log/weekly/*.log"
      min_lines: 10
  key_links:
    - from: "app.py"
      to: "/var/log/weekly/app.log"
      via: "RotatingFileHandler"
      pattern: "RotatingFileHandler.*app\\.log"
    - from: "logrotate.weekly"
      to: "/var/log/weekly/*.log"
      via: "logrotate daemon"
      pattern: "/var/log/weekly/\\*\\.log"
---

<objective>
Configure application logging and log rotation for production deployment.

Purpose: Implement file-based logging per D-08 and D-09.
Output: Flask logging configuration in app.py and logrotate config.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/PROJECT.md
@.planning/ROADMAP.md
@.planning/STATE.md
@.planning/phases/01-production-wsgi-server/01-CONTEXT.md
@.planning/phases/01-production-wsgi-server/01-RESEARCH.md

<interfaces>
<!-- Key types and contracts from existing codebase -->

From app.py (current imports at lines 1-25):
```python
import os
from datetime import date, datetime
# NOTE: logging and RotatingFileHandler NOT imported yet
```

From app.py:27-28 (app initialization):
```python
basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
```

From app.py:58 (db initialization):
```python
db = SQLAlchemy(app)
```

From app.py:743-747 (current main block):
```python
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        update_db_from_json()
    app.run(host='0.0.0.0', debug=True)
```

From 01-RESEARCH.md Pattern 3 (logging implementation):
```python
import logging
from logging.handlers import RotatingFileHandler

def setup_logging(app):
    if not app.debug:
        file_handler = RotatingFileHandler(
            '/var/log/weekly/app.log',
            maxBytes=10485760,  # 10MB
            backupCount=10
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
```
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Add Flask logging configuration to app.py</name>
  <files>app.py</files>
  <read_first>
    - app.py (full file, to understand structure and find insertion points)
    - .planning/phases/01-production-wsgi-server/01-CONTEXT.md (for D-08, D-09)
    - .planning/phases/01-production-wsgi-server/01-RESEARCH.md (Pattern 3 for logging implementation)
  </read_first>
  <action>
    Modify app.py to add production logging. Make the following specific changes:

    1. Add imports at the top of the file (after line 25, before other imports):
    ```python
    import logging
    from logging.handlers import RotatingFileHandler
    ```

    2. Add logging setup function after line 58 (after `db = SQLAlchemy(app)`):
    ```python
    def setup_logging(app):
        """Configure production logging for Flask application.
        Per D-08: File logging, INFO level
        Per D-09: Logs at /var/log/weekly/
        """
        # Skip logging setup in debug mode
        if app.debug:
            return

        log_dir = '/var/log/weekly'

        # Create log directory if it doesn't exist (with error handling)
        try:
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)
        except PermissionError:
            app.logger.warning(f"Cannot create log directory {log_dir}")
            return

        # Application log handler - per D-08 (INFO level)
        file_handler = RotatingFileHandler(
            os.path.join(log_dir, 'app.log'),
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=10
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)

        app.logger.info('Weekly Report Management System starting up')
    ```

    3. Call setup_logging after db initialization (after line 71, after `ensure_record_columns()` call):
    ```python
    # Setup production logging - per D-08, D-09
    setup_logging(app)
    ```

    4. Modify the main block (lines 743-747) to remove debug=True and make it environment-aware:
    ```python
    if __name__ == '__main__':
        with app.app_context():
            db.create_all()
            update_db_from_json()

        # Production: Gunicorn calls app directly, this block is skipped
        # Development: Run with FLASK_DEBUG=true python app.py
        debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
        port = int(os.environ.get('PORT', 5000))
        app.run(host='0.0.0.0', debug=debug_mode, port=port)
    ```

    Key changes:
    - Import logging and RotatingFileHandler
    - Add setup_logging() function with 10MB rotation, INFO level
    - Call setup_logging(app) during initialization
    - Replace hardcoded debug=True with environment variable check
    - Default FLASK_DEBUG to 'false' for production safety
  </action>
  <verify>
    <automated>grep -q "from logging.handlers import RotatingFileHandler" app.py && grep -q "def setup_logging(app):" app.py && grep -q "/var/log/weekly" app.py && grep -q "file_handler.setLevel(logging.INFO)" app.py && grep -q "setup_logging(app)" app.py && grep -q "debug_mode = os.environ.get" app.py && echo "PASS" || echo "FAIL"</automated>
  </verify>
  <acceptance_criteria>
    - app.py contains `from logging.handlers import RotatingFileHandler`
    - app.py contains `def setup_logging(app):` function
    - app.py contains `/var/log/weekly` path (per D-09)
    - app.py contains `setLevel(logging.INFO)` (per D-08)
    - app.py calls `setup_logging(app)` during initialization
    - app.py no longer has hardcoded `debug=True`
    - app.py uses `os.environ.get('FLASK_DEBUG', 'false')` for debug mode
  </acceptance_criteria>
  <done>
    Flask logging configured with RotatingFileHandler at INFO level (D-08, D-09). Debug mode now controlled by environment variable.
  </done>
</task>

<task type="auto">
  <name>Task 2: Create logrotate configuration</name>
  <files>logrotate.weekly</files>
  <read_first>
    - .planning/phases/01-production-wsgi-server/01-CONTEXT.md (for D-09 log location)
    - .planning/phases/01-production-wsgi-server/01-RESEARCH.md (Pattern 4 for logrotate syntax)
  </read_first>
  <action>
    Create logrotate.weekly in project root with the following exact content:

    ```bash
    # logrotate.weekly
    # Log rotation configuration for Weekly Report Management System
    # Deploy with: sudo cp logrotate.weekly /etc/logrotate.d/weekly

    /var/log/weekly/*.log {
        daily
        missingok
        rotate 14
        compress
        delaycompress
        notifempty
        create 0640 one one
        sharedscripts
        postrotate
            # Signal Gunicorn to reopen log files after rotation
            systemctl reload weekly > /dev/null 2>&1 || true
        endscript
    }
    ```

    Configuration details:
    - `daily`: Rotate logs daily
    - `rotate 14`: Keep 14 days of logs
    - `compress`: Compress rotated logs with gzip
    - `delaycompress`: Don't compress yesterday's log (still being written)
    - `create 0640 one one`: New log files owned by user 'one'
    - `postrotate`: Reload Gunicorn to reopen log files after rotation
  </action>
  <verify>
    <automated>test -f logrotate.weekly && grep -q "/var/log/weekly/\*\.log" logrotate.weekly && grep -q "rotate 14" logrotate.weekly && grep -q "compress" logrotate.weekly && grep -q "systemctl reload weekly" logrotate.weekly && echo "PASS" || echo "FAIL"</automated>
  </verify>
  <acceptance_criteria>
    - logrotate.weekly exists in project root
    - Contains `/var/log/weekly/*.log` pattern (per D-09)
    - Contains `rotate 14` for 14-day retention
    - Contains `compress` for log compression
    - Contains `create 0640 one one` for correct file permissions
    - Contains `systemctl reload weekly` in postrotate script
  </acceptance_criteria>
  <done>
    Logrotate configuration created for automatic log rotation.
  </done>
</task>

</tasks>

<verification>
After both tasks complete:
1. Verify logging imports: `grep -c "RotatingFileHandler" app.py`
2. Verify no hardcoded debug=True: `grep "debug=True" app.py` should return nothing
3. Verify logrotate syntax: `logrotate -d logrotate.weekly 2>&1 | head -5`
4. Test Python syntax: `python -m py_compile app.py`
</verification>

<success_criteria>
- app.py has RotatingFileHandler logging to /var/log/weekly/app.log at INFO level
- app.py no longer has hardcoded debug=True
- logrotate.weekly exists with proper rotation configuration
- All locked decisions (D-08, D-09) are implemented
</success_criteria>

<output>
After completion, create `.planning/phases/01-production-wsgi-server/01-02-SUMMARY.md`
</output>