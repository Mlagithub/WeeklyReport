---
phase: 6
slug: find-page-filtering
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-25
---

# Phase 6 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 8.3.5 |
| **Config file** | pytest.ini |
| **Quick run command** | `pytest tests/test_routes.py -x -v` |
| **Full suite command** | `pytest --tb=short` |
| **Estimated runtime** | ~5 seconds |

---

## Sampling Rate

- **After every task commit:** Run `pytest tests/test_routes.py -x`
- **After every plan wave:** Run `pytest --tb=short`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 5 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 6-01-01 | 01 | 1 | FIND-02 | unit | `pytest tests/test_utils.py -x` | ✅ | ⬜ pending |
| 6-02-01 | 02 | 1 | FIND-01, FIND-02 | integration | `pytest tests/test_routes.py -x` | ✅ | ⬜ pending |
| 6-02-02 | 02 | 1 | FIND-01 | integration | `pytest tests/test_routes.py::TestRecordCRUD::test_manage_records_default_user_filter -x` | ❌ W0 | ⬜ pending |
| 6-02-03 | 02 | 1 | FIND-02 | integration | `pytest tests/test_routes.py::TestRecordCRUD::test_manage_records_default_time_filter -x` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `tests/test_routes.py` — add `test_manage_records_default_user_filter` test
- [ ] `tests/test_routes.py` — add `test_manage_records_default_time_filter` test
- [ ] `tests/test_utils.py` — add `test_last_7_days_in_time_ranges` test

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| None | - | All behaviors have automated verification | - |

*All phase behaviors have automated verification.*

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 5s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending