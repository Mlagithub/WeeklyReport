---
phase: 01-production-wsgi-server
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - requirements.txt
  - gunicorn.conf.py
  - weekly.service
autonomous: true
requirements: [STAB-01]
user_setup:
  - service: systemd
    why: "Service deployment requires sudo access"
    env_vars: []
    dashboard_config:
      - task: "Copy service file to /etc/systemd/system/"
        location: "Requires sudo: sudo cp weekly.service /etc/systemd/system/"
      - task: "Create log directory"
        location: "Requires sudo: sudo mkdir -p /var/log/weekly && sudo chown $USER:$USER /var/log/weekly"

must_haves:
  truths:
    - "Gunicorn is installed and can be invoked"
    - "Application is served by Gunicorn on 0.0.0.0:5000"
    - "systemd service manages the application process"
    - "Service auto-restarts on failure"
  artifacts:
    - path: "requirements.txt"
      provides: "Gunicorn dependency"
      contains: "gunicorn"
    - path: "gunicorn.conf.py"
      provides: "Gunicorn configuration"
      contains: "bind = \"0.0.0.0:5000\""
      min_lines: 20
    - path: "weekly.service"
      provides: "systemd service definition"
      contains: "ExecStart=.*gunicorn"
      min_lines: 15
  key_links:
    - from: "weekly.service"
      to: "gunicorn.conf.py"
      via: "--config gunicorn.conf.py"
      pattern: "--config gunicorn\\.conf\\.py"
    - from: "weekly.service"
      to: "app:app"
      via: "WSGI entry point"
      pattern: "app:app"
---

<objective>
Install Gunicorn WSGI server and configure systemd service management.

Purpose: Replace Flask development server with production-grade Gunicorn (per D-01, D-06).
Output: Gunicorn configuration and systemd service file.
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

From app.py (current entry point):
```python
# Line 28: Flask app object (the WSGI entry point)
app = Flask(__name__)

# Line 743-747: Current development server (TO BE REPLACED)
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        update_db_from_json()
    app.run(host='0.0.0.0', debug=True)
```

From requirements.txt (current dependencies):
```
Flask==3.0.3
flask_sqlalchemy==3.1.1
# ... other dependencies
# NOTE: gunicorn NOT present - needs to be added
```

From app.py:29-36 (database connection pool - already configured):
```python
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 3600,
    'pool_size': 10,
    'max_overflow': 20,
}
```
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Install Gunicorn and create configuration file</name>
  <files>requirements.txt, gunicorn.conf.py</files>
  <read_first>
    - requirements.txt (to append gunicorn dependency)
    - .planning/phases/01-production-wsgi-server/01-CONTEXT.md (for locked decisions D-01 to D-05)
  </read_first>
  <action>
    1. Add gunicorn to requirements.txt:
       - Append line: `gunicorn==25.1.0`
       - Install with: `pip install gunicorn==25.1.0`

    2. Create gunicorn.conf.py in project root with the following exact content:

    ```python
    # gunicorn.conf.py
    # Gunicorn configuration for Weekly Report Management System
    # Per user decisions: D-01 (Gunicorn), D-02 (Sync), D-03 (2-4 workers), D-04 (0.0.0.0:5000), D-05 (30s timeout)

    import multiprocessing
    import os

    # Server socket - per D-04
    bind = "0.0.0.0:5000"
    backlog = 2048

    # Worker processes - per D-02 and D-03
    # Formula: (2 x CPU cores) + 1, capped at 4 for SQLite compatibility
    workers = min(multiprocessing.cpu_count() * 2 + 1, 4)
    worker_class = "sync"  # D-02: Sync mode for simplicity

    # Timeouts - per D-05
    timeout = 30
    keepalive = 2
    graceful_timeout = 30

    # Logging (paths will be created by systemd service setup)
    accesslog = "/var/log/weekly/gunicorn-access.log"
    errorlog = "/var/log/weekly/gunicorn-error.log"
    loglevel = "info"

    # Process naming
    proc_name = "weekly"

    # Security limits
    limit_request_line = 4094
    limit_request_fields = 100
    limit_request_field_size = 8190
    ```

    Do NOT modify app.py in this task. Do NOT set debug=True anywhere.
  </action>
  <verify>
    <automated>grep -q "gunicorn==25.1.0" requirements.txt && test -f gunicorn.conf.py && grep -q 'bind = "0.0.0.0:5000"' gunicorn.conf.py && grep -q "worker_class = \"sync\"" gunicorn.conf.py && grep -q "timeout = 30" gunicorn.conf.py && echo "PASS" || echo "FAIL"</automated>
  </verify>
  <acceptance_criteria>
    - requirements.txt contains exact line `gunicorn==25.1.0`
    - gunicorn.conf.py exists in project root
    - gunicorn.conf.py contains `bind = "0.0.0.0:5000"` (per D-04)
    - gunicorn.conf.py contains `worker_class = "sync"` (per D-02)
    - gunicorn.conf.py contains `timeout = 30` (per D-05)
    - gunicorn.conf.py contains `workers = min(multiprocessing.cpu_count() * 2 + 1, 4)` (per D-03)
  </acceptance_criteria>
  <done>
    Gunicorn is in requirements.txt and gunicorn.conf.py is created with user-specified configuration (D-01 to D-05).
  </done>
</task>

<task type="auto">
  <name>Task 2: Create systemd service unit file</name>
  <files>weekly.service</files>
  <read_first>
    - gunicorn.conf.py (created by Task 1, referenced in ExecStart)
    - .planning/phases/01-production-wsgi-server/01-CONTEXT.md (for locked decisions D-06, D-07)
  </read_first>
  <action>
    Create weekly.service in project root with the following exact content:

    ```ini
    # weekly.service
    # systemd service unit for Weekly Report Management System
    # Per user decisions: D-06 (systemd), D-07 (auto-restart)
    # Deploy with: sudo cp weekly.service /etc/systemd/system/ && sudo systemctl daemon-reload

    [Unit]
    Description=Weekly Report Management System
    After=network.target

    [Service]
    Type=exec
    User=one
    Group=one
    WorkingDirectory=/home/one/weekly

    # Environment setup
    Environment="PATH=/home/one/weekly/.venv/bin:/usr/local/bin:/usr/bin:/bin"
    Environment="FLASK_DEBUG=0"

    # ExecStart references gunicorn.conf.py from Task 1
    ExecStart=/home/one/weekly/.venv/bin/gunicorn \
        --config gunicorn.conf.py \
        app:app

    ExecReload=/bin/kill -s HUP $MAINPID
    KillMode=mixed
    TimeoutStopSec=30
    PrivateTmp=true

    # Restart policy - per D-07
    Restart=on-failure
    RestartSec=5

    # Security hardening
    NoNewPrivileges=true
    ProtectSystem=strict
    ProtectHome=true
    ReadWritePaths=/home/one/weekly /var/log/weekly

    [Install]
    WantedBy=multi-user.target
    ```

    Key points:
    - ExecStart uses `/home/one/weekly/.venv/bin/gunicorn` (full path to venv)
    - WSGI entry point is `app:app` (module:object format)
    - Restart=on-failure implements D-07 auto-restart policy
    - ReadWritePaths includes /var/log/weekly for logging (D-09)
  </action>
  <verify>
    <automated>test -f weekly.service && grep -q "ExecStart=.*gunicorn.*--config gunicorn.conf.py.*app:app" weekly.service && grep -q "Restart=on-failure" weekly.service && grep -q "User=one" weekly.service && echo "PASS" || echo "FAIL"</automated>
  </verify>
  <acceptance_criteria>
    - weekly.service exists in project root
    - Contains `ExecStart=/home/one/weekly/.venv/bin/gunicorn` with correct path
    - Contains `--config gunicorn.conf.py` referencing Task 1's config
    - Contains `app:app` as WSGI entry point
    - Contains `Restart=on-failure` (per D-07)
    - Contains `User=one` matching system user
    - Contains `WorkingDirectory=/home/one/weekly`
  </acceptance_criteria>
  <done>
    systemd service unit file created with auto-restart policy (D-06, D-07). Ready for deployment.
  </done>
</task>

</tasks>

<verification>
After both tasks complete:
1. Verify files exist: `ls -la requirements.txt gunicorn.conf.py weekly.service`
2. Verify Gunicorn installed: `.venv/bin/gunicorn --version`
3. Verify configuration syntax: `python -c "import gunicorn.conf; print('Config OK')"`
4. Verify service file syntax: `systemd-analyze verify weekly.service` (may show warnings for non-root paths, this is expected)
</verification>

<success_criteria>
- Gunicorn 25.1.0 is in requirements.txt and installed
- gunicorn.conf.py exists with bind="0.0.0.0:5000", sync workers, 30s timeout
- weekly.service exists with Restart=on-failure and correct ExecStart
- All locked decisions (D-01 to D-07) are implemented in configuration
</success_criteria>

<output>
After completion, create `.planning/phases/01-production-wsgi-server/01-01-SUMMARY.md`
</output>