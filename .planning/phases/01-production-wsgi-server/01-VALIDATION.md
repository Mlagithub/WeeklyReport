---
phase: 1
slug: production-wsgi-server
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-23
---

# Phase 1 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | manual / system-level verification |
| **Config file** | none — infrastructure phase |
| **Quick run command** | `sudo systemctl status weekly` |
| **Full suite command** | `sudo systemctl restart weekly && curl -s http://localhost:5000` |
| **Estimated runtime** | ~5 seconds |

---

## Sampling Rate

- **After every task commit:** Verify file exists and syntax is valid
- **After every plan wave:** Full system verification (service status + app response)
- **Before `/gsd:verify-work`:** Service running, logs captured, app responds
- **Max feedback latency:** 10 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 01-01-01 | 01 | 1 | STAB-01 | file | `test -f gunicorn.conf.py` | ❌ W0 | ⬜ pending |
| 01-01-02 | 01 | 1 | STAB-01 | file | `test -f /etc/systemd/system/weekly.service` | ❌ W0 | ⬜ pending |
| 01-02-01 | 02 | 1 | STAB-01 | file | `grep -q 'RotatingFileHandler' app.py` | ✅ exists | ⬜ pending |
| 01-03-01 | 03 | 1 | STAB-01 | file | `test -f /etc/logrotate.d/weekly` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `gunicorn` in requirements.txt — dependency for WSGI server
- [ ] `sudo` access — required for systemd and logrotate configuration
- [ ] `/var/log/weekly/` directory — created with proper permissions

*Note: This is an infrastructure phase — verification is primarily system-level, not unit tests.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Service auto-restart on crash | STAB-01 | Requires killing process | `sudo kill -9 $(pidof gunicorn) && sleep 2 && sudo systemctl status weekly` |
| Log rotation | STAB-01 | Requires time/filesystem manipulation | `sudo logrotate -f /etc/logrotate.d/weekly && ls /var/log/weekly/` |
| Concurrent request handling | STAB-01 | Needs load testing tool | `ab -n 100 -c 10 http://localhost:5000/` |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 10s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending