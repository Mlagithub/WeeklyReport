---
phase: 04
slug: unit-testing
status: ready
nyquist_compliant: true
wave_0_complete: false
created: 2026-03-23
---

# Phase 4 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 8.3.x |
| **Config file** | pytest.ini (Plan 01 Task 1 creates) |
| **Quick run command** | `pytest -x` |
| **Full suite command** | `pytest --cov=app --cov=utils` |
| **Estimated runtime** | ~5 seconds |

---

## Sampling Rate

- **After every task commit:** Run `pytest -x`
- **After every plan wave:** Run `pytest --cov=app --cov=utils`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 10 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 04-01-01 | 01 | 1 | TEST-01 | infra | `pytest --collect-only` | Plan 01 creates | ⬜ pending |
| 04-01-02 | 01 | 1 | TEST-01 | unit | `pytest tests/test_utils.py -x` | Plan 01 creates | ⬜ pending |
| 04-02-01 | 02 | 2 | TEST-01 | unit | `pytest tests/test_models.py::TestUserPermissions -x` | Plan 02 creates | ⬜ pending |
| 04-02-02 | 02 | 2 | TEST-01 | unit | `pytest tests/test_models.py::TestAuthorizationFunctions -x` | Plan 02 creates | ⬜ pending |
| 04-03-01 | 03 | 2 | TEST-01 | integration | `pytest tests/test_routes.py::TestAuthentication -x` | Plan 03 creates | ⬜ pending |
| 04-03-02 | 03 | 2 | TEST-01 | integration | `pytest tests/test_routes.py::TestRecordCRUD -x` | Plan 03 creates | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Wave 0 infrastructure is created by Plan 01 Task 1:

- [ ] `tests/__init__.py` — package marker (Plan 01 Task 1)
- [ ] `tests/conftest.py` — shared fixtures (Plan 01 Task 1)
- [ ] `pytest.ini` — pytest configuration (Plan 01 Task 1)
- [ ] `pytest==8.3.5` in requirements.txt (Plan 01 Task 1)
- [ ] `pytest-cov==5.0.0` in requirements.txt (Plan 01 Task 1)

*Existing infrastructure covers: Flask test_client, Flask-SQLAlchemy in-memory DB support*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| None | - | - | All phase behaviors have automated verification |

*All phase behaviors have automated verification.*

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (Plan 01 Task 1)
- [x] No watch-mode flags
- [x] Feedback latency < 10s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** ready