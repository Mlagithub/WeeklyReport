---
phase: 01-production-wsgi-server
plan: 03
type: execute
wave: 2
depends_on: [01-PLAN, 02-PLAN]
files_modified: []
autonomous: false
requirements: [STAB-01]
user_setup:
  - service: systemd
    why: "Service deployment requires sudo commands"
    env_vars: []
    dashboard_config:
      - task: "Deploy systemd service"
        location: "Run: sudo cp weekly.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable weekly && sudo systemctl start weekly"
      - task: "Deploy logrotate config"
        location: "Run: sudo cp logrotate.weekly /etc/logrotate.d/weekly"
      - task: "Create log directory"
        location: "Run: sudo mkdir -p /var/log/weekly && sudo chown one:one /var/log/weekly"

must_haves:
  truths:
    - "Service is running and accessible"
    - "Application responds to HTTP requests on port 5000"
    - "Logs are being written"
    - "Service auto-restarts on failure"
  artifacts:
    - path: "/etc/systemd/system/weekly.service"
      provides: "Deployed systemd service"
      contains: "ExecStart=.*gunicorn"
    - path: "/var/log/weekly/app.log"
      provides: "Application log file"
      min_lines: 1
    - path: "/var/log/weekly/gunicorn-access.log"
      provides: "Gunicorn access log"
    - path: "/var/log/weekly/gunicorn-error.log"
      provides: "Gunicorn error log"
  key_links:
    - from: "systemctl status weekly"
      to: "running state"
      via: "systemd"
      pattern: "Active: active \\(running\\)"
    - from: "curl localhost:5000"
      to: "application response"
      via: "HTTP"
      pattern: "HTTP/1\\.1 200"
---

<objective>
Deploy and verify the production WSGI server setup.

Purpose: Execute deployment commands and verify all components work together.
Output: Running service with verified functionality.
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
<!-- Files created by previous plans -->

From Plan 01:
- gunicorn.conf.py - Gunicorn configuration
- weekly.service - systemd service unit
- requirements.txt updated with gunicorn

From Plan 02:
- app.py - Updated with logging configuration
- logrotate.weekly - Log rotation configuration

<!-- Expected system state after deployment -->
- Service: weekly.service enabled and running
- Logs: /var/log/weekly/*.log files being written
- Process: Gunicorn workers serving app:app on 0.0.0.0:5000
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Execute deployment commands</name>
  <files></files>
  <read_first>
    - gunicorn.conf.py (verify exists from Plan 01)
    - weekly.service (verify exists from Plan 01)
    - logrotate.weekly (verify exists from Plan 02)
    - app.py (verify logging changes from Plan 02)
  </read_first>
  <action>
    Execute the following deployment commands in sequence. These require sudo access.

    1. Create log directory with correct permissions:
    ```bash
    sudo mkdir -p /var/log/weekly
    sudo chown one:one /var/log/weekly
    sudo chmod 755 /var/log/weekly
    ```

    2. Install gunicorn if not already installed:
    ```bash
    /home/one/weekly/.venv/bin/pip install gunicorn==25.1.0
    ```

    3. Deploy systemd service:
    ```bash
    sudo cp /home/one/weekly/weekly.service /etc/systemd/system/weekly.service
    sudo systemctl daemon-reload
    sudo systemctl enable weekly
    sudo systemctl start weekly
    ```

    4. Deploy logrotate configuration:
    ```bash
    sudo cp /home/one/weekly/logrotate.weekly /etc/logrotate.d/weekly
    ```

    5. Verify service is running:
    ```bash
    sudo systemctl status weekly
    ```

    6. Check logs are being written:
    ```bash
    ls -la /var/log/weekly/
    tail -5 /var/log/weekly/app.log
    ```

    7. Test application responds:
    ```bash
    curl -s -o /dev/null -w "%{http_code}" http://localhost:5000/
    ```

    If any command fails, stop and report the error. Do not proceed to verification.
  </action>
  <verify>
    <automated>sudo systemctl is-active weekly && test -f /var/log/weekly/app.log && curl -s -o /dev/null -w "%{http_code}" http://localhost:5000/ | grep -q "200\|302" && echo "PASS" || echo "FAIL"</automated>
  </verify>
  <acceptance_criteria>
    - `systemctl is-active weekly` returns "active"
    - /var/log/weekly/app.log exists and has content
    - /var/log/weekly/gunicorn-access.log exists
    - /var/log/weekly/gunicorn-error.log exists
    - `curl http://localhost:5000/` returns HTTP 200 or 302
  </acceptance_criteria>
  <done>
    Service deployed and running. Application accessible on port 5000.
  </done>
</task>

<task type="checkpoint:human-verify" gate="blocking">
  <what-built>
    Production WSGI server deployment:
    - Gunicorn 25.1.0 installed and configured
    - systemd service 'weekly' created with auto-restart
    - Flask logging configured at INFO level to /var/log/weekly/app.log
    - Log rotation configured via logrotate
  </what-built>
  <how-to-verify>
    1. Check service status:
       `sudo systemctl status weekly`
       Expected: "Active: active (running)" with Gunicorn master process

    2. Verify web access:
       Open browser to http://localhost:5000 (or http://SERVER_IP:5000)
       Expected: Login page or dashboard loads

    3. Check logs are being written:
       `tail -20 /var/log/weekly/app.log`
       Expected: Startup messages, INFO level logs

    4. Test auto-restart (optional):
       `sudo kill -9 $(pgrep -f "gunicorn.*weekly")`
       Wait 5 seconds, then:
       `sudo systemctl status weekly`
       Expected: Service auto-restarted (Restart=on-failure working)

    5. Verify no Flask dev server:
       `ps aux | grep -E "(flask|werkzeug)" | grep -v grep`
       Expected: No output (only Gunicorn processes, no Flask dev server)
  </how-to-verify>
  <resume-signal>Type "approved" if all verifications pass, or describe any issues found</resume-signal>
</task>

</tasks>

<verification>
After checkpoint approval:
1. Document final service status
2. Record any issues encountered during deployment
3. Update STATE.md with phase completion
</verification>

<success_criteria>
- Service 'weekly' is active and running
- Application responds on http://localhost:5000
- Logs are being written to /var/log/weekly/
- Auto-restart verified working
- No Flask development server running
- All Phase 1 requirements (STAB-01) satisfied
</success_criteria>

<output>
After completion, create `.planning/phases/01-production-wsgi-server/01-03-SUMMARY.md`

Then update ROADMAP.md to mark Phase 1 as complete.
</output>