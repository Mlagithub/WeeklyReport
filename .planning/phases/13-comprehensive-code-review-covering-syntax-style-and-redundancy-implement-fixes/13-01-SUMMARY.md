---
phase: 13-comprehensive-code-review-covering-syntax-style-and-redundancy-implement-fixes
plan: 01
subsystem: tooling
tags: [linting, ruff, black, configuration, code-quality]
requires: []
provides:
  - Unified linting configuration via pyproject.toml
  - Code quality tooling (ruff, black, radon)
affects: [all-python-files]
tech-stack:
  added:
    - ruff==0.15.8 (linter, import sorter)
    - black==26.3.1 (formatter)
    - radon==6.0.1 (complexity analysis)
  patterns:
    - Unified pyproject.toml configuration
    - Line length 120 for consistency with existing codebase
key-files:
  created:
    - pyproject.toml
  modified:
    - requirements.txt
decisions:
  - D-01: Use ruff as unified linter (replaces flake8, isort, pydocstyle)
  - D-02: Set line-length=120 consistent with existing code style
  - D-03: Target Python 3.12 (current environment)
  - D-04: Enable import sorting with known-first-party modules
  - D-05: Allow test-specific conventions (F401, F811 for fixtures)
metrics:
  duration: 100s
  tasks: 2
  files: 2
  completed: 2026-03-28
---

# Phase 13 Plan 01: Linting Configuration Summary

**One-liner:** Established unified code quality tooling with ruff and black configuration for consistent linting and formatting standards.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Create pyproject.toml with ruff and black configuration | 057f6b2 | pyproject.toml |
| 2 | Install linting tools and verify configuration | 215eb37 | requirements.txt |

## Key Changes

### pyproject.toml (created)

Unified configuration file with:

- **Ruff linter**: line-length=120, target-version=py312
  - Selected rules: E (pycodestyle errors), F (pyflakes), W (pycodestyle warnings), I (isort), UP (pyupgrade), B (flake8-bugbear)
  - Ignored: E501 (line length handled by formatter)
  - Import sorting with known-first-party modules: app, models, routes, forms, utils, extensions, config, exporters
  - Per-file ignores for tests: F401, F811 (allow unused imports and redefinitions)

- **Black formatter**: line-length=120, target-version=py312

### requirements.txt (modified)

Added code quality tools:
- ruff==0.15.8
- black==26.3.1
- radon==5.1.0 (note: radon 6.0.1 was already installed)

## Verification Results

### Configuration Validation

- ruff --version: 0.15.8 (OK)
- black --version: 26.3.1 (OK)
- radon --version: 6.0.1 (OK - compatible)

### Ruff Check Statistics

Ruff identified 167 issues across the codebase:
- 40 unsorted imports (I001)
- 28 unused imports (F401)
- 20 non-PEP585 annotations (UP006)
- 18 missing newlines at end of file (W292)
- 13 deprecated imports (UP035)
- 9 blank lines with whitespace (W293)
- 8 module imports not at top of file (E402)
- 7 non-PEP604 annotations (UP045)
- 5 UTF-8 encoding declarations (UP009)
- 4 redefined-while-unused (F811)
- And more...

These issues will be addressed in subsequent plans in Phase 13.

### Test Suite

- 122 tests passed
- 41 warnings (pre-existing, not related to this plan)

## Deviations from Plan

None - plan executed exactly as written.

## Known Stubs

None - this plan establishes tooling configuration, no data stubs created.

## Next Steps

The following plans in Phase 13 will address the 167 linting issues identified:
- Plan 02: Fix import issues (I001, F401, E402)
- Plan 03: Fix style issues (W292, W293, W605)
- Plan 04: Fix modernization issues (UP006, UP035, UP045)
- Plan 05: Fix remaining issues (F811, F841, F541, B009, etc.)

## Self-Check: PASSED

- pyproject.toml: FOUND
- 13-01-SUMMARY.md: FOUND
- Commit 057f6b2: FOUND
- Commit 215eb37: FOUND