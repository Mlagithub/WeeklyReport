---
phase: 13-comprehensive-code-review-covering-syntax-style-and-redundancy-implement-fixes
plan: 02
subsystem: linting
tags: [ruff, auto-fix, imports, eof-newline, style-fixes]
requires: [13-01]
provides:
  - 149 auto-fixed linting issues
  - Clean Python files with EOF newlines
  - Sorted imports across all modules
affects: [all-python-files]
tech-stack:
  added: []
  patterns:
    - Ruff auto-fix workflow for batch linting fixes
    - Import sorting with known-first-party modules
key-files:
  created: []
  modified:
    - app.py
    - routes.py
    - utils.py
    - config.py
    - extensions.py
    - forms.py
    - models.py
    - gunicorn.conf.py
    - exporters/__init__.py
    - exporters/base.py
    - exporters/docx.py
    - exporters/excel.py
    - exporters/pdf.py
    - exporters/image_resolver.py
    - tests/__init__.py
    - tests/conftest.py
    - tests/test_exporters.py
    - tests/test_models.py
    - tests/test_routes.py
    - tests/test_utils.py
decisions:
  - D-01: Auto-fix with ruff check . --fix resolves trivial issues efficiently
  - D-02: Remaining 21 issues require manual intervention or are intentional patterns
metrics:
  duration: 126s
  tasks: 2
  files: 20
  completed: 2026-03-28
---

# Phase 13 Plan 02: Auto-fix Linting Issues Summary

**One-liner:** Auto-fixed 149 linting issues using ruff --fix, reducing codebase issues from 170 to 21 remaining manual-fix items.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Run ruff auto-fix on all Python files | 3b22af1 | 20 files (app.py, routes.py, utils.py, exporters/*, tests/*) |
| 2 | Verify auto-fix results and document remaining issues | N/A | Verification only |

## Key Changes

### Auto-fixed Issues (149 total)

| Category | Count | Description |
|----------|-------|-------------|
| I001 | 40 | Import sorting fixed |
| F401 | 24 | Unused imports removed |
| W292 | 11 | EOF newlines added |
| W293 | 9 | Blank line whitespace removed |
| E303 | 6 | Excessive blank lines reduced |
| E128 | 12 | Continuation indentation fixed |
| F541 | 1 | F-string without placeholder converted to regular string (routes.py:285) |
| UP006 | 20 | Non-PEP585 annotations updated (Dict -> dict, List -> list) |
| UP009 | 5 | UTF-8 encoding declarations removed |
| Other | ~21 | Various minor fixes |

### Specific Fixes Verified

1. **EOF newlines**: All 12+ Python files now have trailing newline character
2. **routes.py:285**: `flash(f'数据己删除')` converted to `flash('数据己删除')`
3. **Unused imports**: Removed from app.py, utils.py, exporters/docx.py, and other files

## Verification Results

### Test Suite

- 122 tests passed (all existing tests work)
- 41 warnings (pre-existing, not related to this plan)

### Remaining Linting Issues (21 manual-fix required)

| Category | Count | Files Affected |
|----------|-------|----------------|
| E402 | 8 | app.py (1), exporters/__init__.py (3), utils.py (4) |
| UP035 | 4 | exporters/__init__.py (3), tests/test_exporters.py (1) |
| F401 | 3 | exporters/__init__.py (typing imports unused) |
| F841 | 3 | routes.py (1), tests/test_models.py (2) |
| UP031 | 3 | models.py (1), routes.py (2) |

### Complexity Metrics (unchanged)

High-complexity functions remain at same CC values:
- RecordDownloader.download: CC=12
- html_to_text: CC=8
- User.managed_group: CC=6

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Documentation] Plan expected 14 remaining issues, actual is 21**
- **Found during:** Task 2 verification
- **Issue:** Plan was written before actual ruff analysis; estimated 14 issues (E402, F811, W605) but actual remaining is 21 (different categories)
- **Resolution:** Documented actual remaining issues; W605 issues in exporters/pdf.py were valid byte string escapes, not flagged
- **Files:** N/A (documentation difference)

## Known Stubs

None - this plan addresses linting issues only, no data stubs created.

## Next Steps

The following plans in Phase 13 will address remaining issues:
- Plan 03: Fix style issues (W605 if applicable, W293 remaining)
- Plan 04: Fix modernization issues (UP035, UP031)
- Plan 05: Fix remaining issues (E402 intentional patterns, F841 unused variables)

## Self-Check: PASSED

- All 20 modified files: FOUND (git log 3b22af1)
- Commit 3b22af1: FOUND
- EOF newlines in all files: VERIFIED (tail -c 1 shows newline)
- Test suite: PASSED (122 tests)
- Remaining issues: 21 (documented above)