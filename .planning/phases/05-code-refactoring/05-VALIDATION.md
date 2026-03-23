---
phase: 05
slug: code-refactoring
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-23
---

# Phase 05 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 8.3.5 |
| **Config file** | tests/conftest.py |
| **Quick run command** | `python -m pytest tests/ -x -q` |
| **Full suite command** | `python -m pytest tests/ -v` |
| **Estimated runtime** | ~15 seconds |

---

## Sampling Rate

- **After every task commit:** Run `python -m pytest tests/ -x -q`
- **After every plan wave:** Run `python -m pytest tests/ -v`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 15 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 05-01-01 | 01 | 1 | REFAC-01 | structure | `ls config.py extensions.py models.py forms.py routes.py` | ✅ W0 | ⬜ pending |
| 05-01-02 | 01 | 1 | REFAC-01 | unit | `python -m pytest tests/ -x -q` | ✅ W0 | ⬜ pending |
| 05-02-01 | 02 | 2 | REFAC-01 | integration | `python -m pytest tests/ -v` | ✅ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements.

- [x] `tests/test_routes.py` — 31 tests (authentication + CRUD)
- [x] `tests/test_models.py` — 19 tests (permissions + authorization)
- [x] `tests/test_utils.py` — 12 tests (DateRange + html_to_text)
- [x] `tests/conftest.py` — shared fixtures

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Code organized into logical modules | REFAC-01 | Structure verification | `ls -la config.py extensions.py models.py forms.py routes.py` |
| Configuration centralized | REFAC-01 | Inspection required | `grep -l "SECRET_KEY" config.py && grep -l "class.*Config" config.py` |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 15s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending