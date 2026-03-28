# gunicorn.conf.py
# Gunicorn configuration for Weekly Report Management System
# Per user decisions: D-01 (Gunicorn), D-02 (Sync), D-03 (2-4 workers), D-04 (0.0.0.0:5000), D-05 (30s timeout)

import multiprocessing

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
