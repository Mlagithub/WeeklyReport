---
phase: 13
slug: comprehensive-code-review-covering-syntax-style-and-redundancy-implement-fixes
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-28
---

# Phase 13 — Validation Strategy

> Per-phase validation contract for code review and quality improvements.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 7.x |
| **Config file** | pytest.ini (existing) |
| **Quick run command** | `pytest tests/ -q --tb=short` |
| **Full suite command** | `pytest tests/ -v --cov=app --cov-report=term-missing` |
| **Estimated runtime** | ~15 seconds |

---

## Sampling Rate

- **After every task commit:** Run `pytest tests/ -q --tb=short`
- **After every plan wave:** Run `pytest tests/ -v --cov=app --cov-report=term-missing`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 15 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 13-01-01 | 01 | 1 | Linter Config | unit | `ruff check . --statistics` | ❌ W0 | ⬜ pending |
| 13-01-02 | 01 | 1 | Auto-fixes | unit | `pytest tests/ -q` | ✅ | ⬜ pending |
| 13-02-01 | 02 | 2 | Manual fixes | unit | `pytest tests/ -q && ruff check .` | ✅ | ⬜ pending |
| 13-03-01 | 03 | 3 | Complexity refactor | unit | `pytest tests/ -q && radon cc app/ -a` | ✅ | ⬜ pending |
| 13-04-01 | 04 | 4 | Dead code removal | unit | `pytest tests/ -q` | ✅ | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] No new test files needed - existing test suite covers all modules
- [ ] `tests/conftest.py` — existing fixtures cover app initialization
- [ ] Linter runs pass without breaking existing tests

*Existing infrastructure covers all phase requirements.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Code style consistency | STYLE-01 | Visual inspection needed | Review diff output from ruff/black |
| Complexity reduction impact | COMPLEX-01 | Requires domain judgment | Compare before/after CC metrics |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 15s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending