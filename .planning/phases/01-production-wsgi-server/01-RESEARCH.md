# Phase 1: Production WSGI Server - Research

**Researched:** 2026-03-23
**Domain:** Python WSGI Server Deployment / systemd Service Management
**Confidence:** MEDIUM (Training knowledge with environment verification; official docs not fetchable due to network restrictions)

## Summary

This phase replaces the Flask development server (`app.run(debug=True)`) with Gunicorn, a production-grade WSGI server. The application will be managed as a systemd service on Ubuntu 22.04, with file-based logging and log rotation. The current application uses Flask 3.0.3 with SQLite and serves 10-50 users.

**Primary recommendation:** Use gunicorn.conf.py for configuration (cleaner, version-controlled), systemd service with EnvironmentFile for secrets, and Python logging module with file handlers for application logs.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- **D-01:** Use Gunicorn as WSGI server
- **D-02:** Worker type uses Sync (synchronous) mode - simple and reliable
- **D-03:** Worker count auto-configured (2-4 workers, following Gunicorn formula)
- **D-04:** Port binding 0.0.0.0:5000, maintain current accessibility
- **D-05:** Request timeout 30 seconds (Gunicorn default)
- **D-06:** Use systemd service for process management
- **D-07:** Configure auto-restart policy, automatic recovery after crash
- **D-08:** Add file logging, log level INFO
- **D-09:** Log files stored in standard location (e.g., /var/log/weekly/)

### Claude's Discretion
- Log file rotation configuration (can use logrotate)
- Specific systemd service file path and naming
- Gunicorn configuration file format (gunicorn.conf.py or command line arguments)

### Deferred Ideas (OUT OF SCOPE)
None - discussion stayed within phase scope
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| STAB-01 | Application runs on production-grade WSGI server (not Flask dev server with debug=True) | Gunicorn 25.1.0 with sync workers, systemd service, file logging |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| gunicorn | 25.1.0 | WSGI HTTP Server | Industry standard for Python WSGI, mature, well-documented, simple configuration |
| systemd | 249 (Ubuntu 22.04) | Process manager | Native to Ubuntu, automatic restart, logging integration, dependency management |
| logrotate | 3.19.0 | Log rotation | Standard on Ubuntu, handles compression and rotation automatically |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| python-dotenv | 1.0.1 | Environment variable management | Optional - if .env file approach preferred over EnvironmentFile |

### Installation
```bash
pip install gunicorn
# Or add to requirements.txt:
# gunicorn==25.1.0
```

### Environment Verification
- **Python:** 3.10.12 (installed)
- **systemd:** 249 (installed)
- **logrotate:** 3.19.0 (installed)
- **Gunicorn:** NOT installed (needs `pip install gunicorn`)

## Architecture Patterns

### Recommended Project Structure
```
/home/one/weekly/
├── app.py                    # Flask application (entry point: 'app' object)
├── gunicorn.conf.py          # Gunicorn configuration (NEW)
├── requirements.txt          # Dependencies (UPDATE: add gunicorn)
├── .env                      # Environment variables (NEW, optional)
└── instance/
    └── app.db               # SQLite database

/etc/systemd/system/
└── weekly.service           # systemd service unit file (NEW)

/var/log/weekly/
├── app.log                  # Application log (NEW)
├── gunicorn-access.log     # Gunicorn access log (NEW)
└── gunicorn-error.log      # Gunicorn error log (NEW)

/etc/logrotate.d/
└── weekly                   # Log rotation config (NEW)
```

### Pattern 1: Gunicorn Configuration File
**What:** Python-based configuration file for Gunicorn settings
**When to use:** Recommended for production - version-controlled, readable, maintainable
**Example:**
```python
# gunicorn.conf.py
# Source: Gunicorn documentation, training knowledge

import multiprocessing
import os

# Server socket
bind = "0.0.0.0:5000"
backlog = 2048

# Worker processes
# Formula: (2 x CPU cores) + 1
workers = multiprocessing.cpu_count() * 2 + 1
# Cap at 4 workers for this application (10-50 users)
workers = min(workers, 4)
worker_class = "sync"  # Simple, reliable for I/O-bound apps

# Timeouts
timeout = 30  # D-05: 30 seconds
keepalive = 2
graceful_timeout = 30

# Logging
accesslog = "/var/log/weekly/gunicorn-access.log"
errorlog = "/var/log/weekly/gunicorn-error.log"
loglevel = "info"

# Process naming
proc_name = "weekly"

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190
```

### Pattern 2: systemd Service Unit
**What:** systemd service definition for process management
**When to use:** Production deployment on Ubuntu/Debian
**Example:**
```ini
# /etc/systemd/system/weekly.service
# Source: systemd documentation, training knowledge

[Unit]
Description=Weekly Report Management System
After=network.target

[Service]
Type=exec
User=one
Group=one
WorkingDirectory=/home/one/weekly
Environment="PATH=/home/one/weekly/.venv/bin"
Environment="DATABASE_URL=sqlite:///instance/app.db"
EnvironmentFile=/home/one/weekly/.env  # Optional: for secrets

ExecStart=/home/one/weekly/.venv/bin/gunicorn \
    --config gunicorn.conf.py \
    app:app

ExecReload=/bin/kill -s HUP $MAINPID
KillMode=mixed
TimeoutStopSec=30
PrivateTmp=true

# Restart policy (D-07)
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

### Pattern 3: Flask Application Logging
**What:** Python logging configuration for Flask application
**When to use:** All production Flask deployments
**Example:**
```python
# In app.py, after app initialization
# Source: Python logging documentation, Flask best practices

import logging
from logging.handlers import RotatingFileHandler
import os

def setup_logging(app):
    """Configure application logging."""
    if not app.debug:
        # Create log directory if it doesn't exist
        log_dir = '/var/log/weekly'
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        # File handler with rotation
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

        # Set app log level
        app.logger.setLevel(logging.INFO)
        app.logger.info('Weekly Report startup')
```

### Pattern 4: logrotate Configuration
**What:** Automatic log rotation for application logs
**When to use:** Production systems with file-based logging
**Example:**
```bash
# /etc/logrotate.d/weekly
# Source: logrotate documentation

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
        # Signal Gunicorn to reopen log files
        systemctl reload weekly > /dev/null 2>&1 || true
    endscript
}
```

### Anti-Patterns to Avoid

- **Running as root:** Gunicorn workers should never run as root. Use a dedicated user with minimal permissions.
- **Debug mode in production:** Never set `debug=True` or `FLASK_DEBUG=1` in production. This enables the Werkzeug debugger which allows arbitrary code execution.
- **Ignoring SIGTERM:** Gunicorn handles graceful shutdown. Do not override signal handlers without understanding implications.
- **Sync workers for CPU-bound tasks:** Sync workers block on each request. For CPU-intensive workloads, use gevent or eventlet workers instead.
- **Missing log directory:** Ensure `/var/log/weekly/` exists with correct permissions before starting the service.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Process supervision | Custom watchdog script | systemd | Handles restart, logging, dependencies, cgroups |
| Log rotation | Cron job + mv | logrotate | Atomic rotation, compression, date extension built-in |
| Worker management | Manual process spawning | Gunicorn arbiter | Pre-fork model, graceful reload, worker timeout handling |
| Environment variables | Hardcoded values | EnvironmentFile / .env | Security, environment separation, easy rotation |

**Key insight:** systemd and logrotate are battle-tested system tools. Custom solutions introduce unnecessary complexity and bugs.

## Common Pitfalls

### Pitfall 1: Incorrect WSGI Entry Point
**What goes wrong:** Gunicorn cannot find the Flask application object
**Why it happens:** The entry point format is `module:variable`, not a file path
**How to avoid:**
```bash
# CORRECT: module:app_object
gunicorn app:app

# INCORRECT: treating as file path
gunicorn app.py  # This fails

# INCORRECT: wrong object name
gunicorn app:application  # When the object is named 'app'
```
**Warning signs:** ImportError, "Failed to find application object"

### Pitfall 2: Virtual Environment PATH Issues
**What goes wrong:** systemd cannot find gunicorn or Python packages
**Why it happens:** systemd does not inherit shell environment by default
**How to avoid:**
```ini
# In systemd service file, explicitly set PATH
Environment="PATH=/home/one/weekly/.venv/bin"
# OR use full path to gunicorn
ExecStart=/home/one/weekly/.venv/bin/gunicorn ...
```
**Warning signs:** "command not found", ImportError for installed packages

### Pitfall 3: Log Directory Permissions
**What goes wrong:** Application cannot write logs
**Why it happens:** Log directory created by root, application runs as non-root user
**How to avoid:**
```bash
# Create log directory with correct ownership
sudo mkdir -p /var/log/weekly
sudo chown one:one /var/log/weekly
sudo chmod 755 /var/log/weekly
```
**Warning signs:** PermissionError, "No such file or directory" for log files

### Pitfall 4: Worker Count Too High for SQLite
**What goes wrong:** Database locked errors under concurrent writes
**Why it happens:** SQLite has limited write concurrency; multiple workers = multiple connections = lock contention
**How to avoid:**
- Limit workers to 2-4 for SQLite (user decided: 2-4 workers)
- Consider connection pooling (already configured in app.py:31-36)
- Phase 3 will enable WAL mode for better concurrency
**Warning signs:** "database is locked" errors, intermittent 500 errors

### Pitfall 5: Graceful Reload Failure
**What goes wrong:** Gunicorn workers don't pick up code changes after `systemctl reload`
**Why it happens:** Only HUP signal triggers graceful worker restart
**How to avoid:**
```bash
# For code updates, restart (not reload)
sudo systemctl restart weekly

# Reload only reopens log files
sudo systemctl reload weekly
```
**Warning signs:** Old code still running after `git pull`

### Pitfall 6: Missing SECRET_KEY in Production
**What goes wrong:** Session errors, CSRF failures
**Why it happens:** Hardcoded SECRET_KEY in code, but environment variable expected in production
**How to avoid:**
```ini
# In systemd EnvironmentFile or Environment
Environment="SECRET_KEY=your-production-secret-key"
```
**Note:** Per CONCERNS.md, SECRET_KEY is currently hardcoded at app.py:37. This is a security issue but changing it requires a migration strategy.

## Code Examples

### Gunicorn Entry Point Modification
```python
# app.py - Current (line 743-747)
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        update_db_from_json()
    app.run(host='0.0.0.0', debug=True)  # REMOVE debug=True

# app.py - Recommended production setup
if __name__ == '__main__':
    # Production: Gunicorn calls app directly, this block is skipped
    # Development: Run with flask run or python app.py
    import os
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'

    with app.app_context():
        db.create_all()
        update_db_from_json()

    app.run(host='0.0.0.0', debug=debug_mode, port=int(os.environ.get('PORT', 5000)))
```

### Flask Logging Setup
```python
# Add to app.py, after Flask app initialization
# Source: Flask documentation, Python logging best practices

import logging
from logging.handlers import RotatingFileHandler
import os

def configure_logging(app):
    """Configure production logging for Flask application."""
    # Skip if in debug mode
    if app.debug:
        return

    log_dir = os.environ.get('LOG_DIR', '/var/log/weekly')

    # Ensure log directory exists
    try:
        os.makedirs(log_dir, exist_ok=True)
    except PermissionError:
        app.logger.warning(f"Cannot create log directory {log_dir}, using current directory")
        log_dir = '.'

    # Application log handler
    app_handler = RotatingFileHandler(
        os.path.join(log_dir, 'app.log'),
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=10
    )
    app_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    app_handler.setLevel(logging.INFO)
    app.logger.addHandler(app_handler)
    app.logger.setLevel(logging.INFO)

    # Also configure root logger for unhandled exceptions
    logging.basicConfig(
        level=logging.INFO,
        handlers=[app_handler]
    )

# Call after app creation
configure_logging(app)
```

### Quick Service Management Commands
```bash
# Install Gunicorn
pip install gunicorn

# Create log directory
sudo mkdir -p /var/log/weekly
sudo chown $USER:$USER /var/log/weekly

# Deploy service
sudo cp weekly.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable weekly
sudo systemctl start weekly

# Check status
sudo systemctl status weekly
sudo journalctl -u weekly -f

# Reload after config changes
sudo systemctl restart weekly
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Flask dev server (`app.run()`) | Gunicorn with workers | Standard practice | Production-ready, handles concurrency |
| Supervisor + Gunicorn | systemd + Gunicorn | Ubuntu 15.04+ | Native integration, fewer dependencies |
| Manual log management | logrotate | Long standard | Automatic rotation, compression |
| Start scripts in /etc/init.d | systemd unit files | Ubuntu 15.04+ | Declarative, dependency-aware |

**Deprecated/outdated:**
- **Supervisor:** Still used but systemd is preferred on modern Ubuntu
- **Upstart:** Replaced by systemd in Ubuntu 15.04+
- **mod_wsgi:** Still valid but Gunicorn + nginx reverse proxy is more common for microservices

## Open Questions

1. **Should we use nginx as reverse proxy?**
   - What we know: Gunicorn can serve directly on port 5000; nginx adds SSL termination, static file serving, load balancing
   - What's unclear: User hasn't specified if SSL/reverse proxy needed
   - Recommendation: Start without nginx. Add in future if SSL termination or static file caching needed.

2. **Environment variable management approach?**
   - What we know: systemd supports EnvironmentFile for .env files
   - What's unclear: Whether to use .env file or direct Environment directives
   - Recommendation: Use EnvironmentFile=/home/one/weekly/.env for secrets (SECRET_KEY, DATABASE_URL), with file not in git.

3. **Database migration during startup?**
   - What we know: Current code runs `db.create_all()` and `update_db_from_json()` on startup
   - What's unclear: Whether this should happen on every service start
   - Recommendation: Keep for now (idempotent), but consider migration scripts in future phases.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Python 3.10+ | Gunicorn | Yes | 3.10.12 | - |
| systemd | Process management | Yes | 249 | - |
| logrotate | Log rotation | Yes | 3.19.0 | - |
| Gunicorn | WSGI server | No | - | pip install required |
| pip | Package management | Yes | 22.0.2 | - |
| Virtual environment | Isolation | Yes | .venv | - |

**Missing dependencies with no fallback:**
- Gunicorn: Must be installed via `pip install gunicorn`

**Missing dependencies with fallback:**
- None

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | pytest (not yet installed) |
| Config file | None - needs pytest.ini or pyproject.toml |
| Quick run command | `pytest -x` (after setup) |
| Full suite command | `pytest -v` (after setup) |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| STAB-01 | Gunicorn serves app on port 5000 | smoke | Manual: `curl localhost:5000` | N/A - infrastructure test |
| STAB-01 | Service restarts on failure | integration | Manual: `systemctl status weekly` | N/A - system test |
| STAB-01 | Logs written to /var/log/weekly | smoke | Manual: `tail /var/log/weekly/app.log` | N/A - file check |

### Sampling Rate
- **Per task commit:** Not applicable - infrastructure deployment
- **Per wave merge:** Manual verification of service status
- **Phase gate:** Service running, logs accessible, curl returns 200

### Wave 0 Gaps
- [ ] `tests/` directory - No test files exist in project
- [ ] `pytest` - Not in requirements.txt, needs installation
- [ ] `conftest.py` - No shared fixtures

**Note:** This phase is primarily infrastructure deployment. Testing is manual/operational (service starts, responds to requests, logs written). Automated tests for application functionality come in Phase 4.

## Sources

### Primary (HIGH confidence)
- Training knowledge: Gunicorn documentation patterns, systemd unit file syntax, Python logging module
- Environment verification: systemd 249, logrotate 3.19.0, Python 3.10.12 available
- pip registry: Gunicorn 25.1.0 is current stable release

### Secondary (MEDIUM confidence)
- Flask deployment patterns (standard practice in Flask community)
- Ubuntu 22.04 systemd conventions

### Tertiary (LOW confidence)
- Specific gunicorn.conf.py configuration values (unverified against current docs)
- systemd security hardening options (recommend testing before production)

**Limitation:** Official documentation (docs.gunicorn.org, flask.palletsprojects.com) was not fetchable due to network restrictions. Confidence is MEDIUM; recommend verifying configuration against official docs before deployment.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - Gunicorn/systemd/logrotate are stable, well-documented tools
- Architecture: HIGH - Patterns are industry standard
- Pitfalls: HIGH - Common issues well-known in community
- Configuration details: MEDIUM - Specific values should be verified against docs

**Research date:** 2026-03-23
**Valid until:** 2026-06-23 (3 months - stable technologies, low drift)

---

*Research complete. Ready for planning.*