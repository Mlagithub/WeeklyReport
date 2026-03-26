---
phase: 8
slug: export-foundation
status: in-progress
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-26
---

# Phase 8 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 8.3.5 |
| **Config file** | pytest.ini |
| **Quick run command** | `pytest tests/ -v -x` |
| **Full suite command** | `pytest tests/ -v --cov=. --cov-report=term-missing` |
| **Estimated runtime** | ~5 seconds |

---

## Sampling Rate

- **After every task commit:** Run `pytest tests/ -v -x`
- **After every plan wave:** Run `pytest tests/ -v --cov=.`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 10 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 08-01-01 | 01 | 1 | INFRA-04 | integration | `pip list \| grep python-docx` | N/A | ⬜ pending |
| 08-01-02 | 01 | 1 | INFRA-04 | integration | `pip list \| grep weasyprint` | N/A | ⬜ pending |
| 08-02-01 | 02 | 1 | INFRA-01 | unit | `pytest tests/test_exporters.py::TestExporterBase -v` | ✅ W0 | ⬜ pending |
| 08-03-01 | 03 | 1 | INFRA-02 | unit | `pytest tests/test_exporters.py::TestExporterFactory -v` | ✅ W0 | ⬜ pending |
| 08-04-01 | 04 | 1 | INFRA-03 | unit | `pytest tests/test_exporters.py::TestImageResolver -v` | ✅ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [x] `tests/test_exporters.py` — stubs for ExporterBase, ExporterFactory, ImageResolver tests
- [x] No shared fixtures needed beyond existing conftest.py
- [x] Framework installed: pytest 8.3.5

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| None | N/A | All behaviors have automated verification | N/A |

*All phase behaviors have automated verification.*

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 10s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending