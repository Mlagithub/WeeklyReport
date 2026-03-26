---
phase: 12
slug: batch-export
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-26
---

# Phase 12 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 8.3.5 |
| **Config file** | pytest.ini |
| **Quick run command** | `pytest tests/ -v -x` |
| **Full suite command** | `pytest tests/ -v --cov=.` |
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
| 12-00-01 | 00 | 0 | BATCH-01 | unit | `pytest tests/test_exporters.py::TestBatchExport -v` | ⬜ W0 | ⬜ pending |
| 12-01-01 | 01 | 1 | BATCH-01 | unit | `pytest tests/test_exporters.py::TestBatchExport::test_create_zip_with_files -v` | ✅ W0 | ⬜ pending |
| 12-01-02 | 01 | 1 | BATCH-01 | unit | `pytest tests/test_exporters.py::TestBatchExport::test_batch_export_returns_bytesio -v` | ✅ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `tests/test_exporters.py` — TestBatchExport stubs added to existing file
- [x] Framework installed: pytest 8.3.5
- [x] zipfile module: Python stdlib

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| ZIP downloads with correct filenames | BATCH-01 | Visual verification | Download ZIP, extract, verify filenames include username + date |
| Batch button visible only for team leads | BATCH-01 | UI verification | Login as team lead vs regular user, check button visibility |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 10s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending