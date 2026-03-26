---
phase: 11
slug: excel-enhancement
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-26
---

# Phase 11 — Validation Strategy

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
| 11-00-01 | 00 | 0 | XLSX-01 | unit | `pytest tests/test_exporters.py::TestExcelExporter -v` | ⬜ W0 | ⬜ pending |
| 11-01-01 | 01 | 1 | XLSX-01 | unit | `pytest tests/test_exporters.py::TestExcelExporter::test_file_extension -v` | ✅ W0 | ⬜ pending |
| 11-01-02 | 01 | 1 | XLSX-01 | unit | `pytest tests/test_exporters.py::TestExcelExporter::test_rich_text_conversion -v` | ✅ W0 | ⬜ pending |
| 11-02-01 | 02 | 1 | XLSX-01 | unit | `pytest tests/test_exporters.py::TestExporterFactory::test_supported_formats -v` | ✅ | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `tests/test_exporters.py` — TestExcelExporter stubs added to existing file
- [x] Framework installed: pytest 8.3.5
- [x] openpyxl 3.1.5 installed (verified in research)

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Excel opens with formatted text | XLSX-01 | Visual verification | Download Excel, open in Excel/LibreOffice, verify bold/italic visible |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 10s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending