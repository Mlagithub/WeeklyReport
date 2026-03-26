---
phase: 2
slug: session-management
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-23
---

# Phase 2 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest (to be added in Phase 4) |
| **Config file** | none — manual verification for this phase |
| **Quick run command** | `curl -X POST http://localhost:5000/login` |
| **Full suite command** | Manual verification of error handling |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Verify decorator exists and syntax is valid
- **After every plan wave:** Verify application starts and routes work
- **Before `/gsd:verify-work`:** All routes respond correctly, errors logged
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 02-01-01 | 01 | 1 | STAB-04 | file | `grep -q 'def with_db_transaction' app.py` | ✅ exists | ⬜ pending |
| 02-01-02 | 01 | 1 | STAB-04 | file | `grep -q '@with_db_transaction' app.py` | ✅ exists | ⬜ pending |
| 02-02-01 | 02 | 1 | STAB-02 | manual | Check logs for error messages | N/A | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] Application running on Gunicorn (Phase 1 complete)
- [ ] Log directory `/var/log/weekly/` writable
- [ ] No additional dependencies needed

*Note: This phase modifies existing code only, no new test framework yet.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Error logging with stack trace | STAB-04 | Requires forcing database error | Temporarily modify DB path, trigger error, check log |
| User sees flash message | STAB-04 | Requires UI interaction | Force error, verify flash message appears |
| App continues after error | STAB-02 | Requires error recovery | Force error, verify app still responds |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending