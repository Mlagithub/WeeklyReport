# Linting Report - Phase 19 Code Review

**Generated:** 2026-03-29
**Tool:** ruff check (from .venv)
**Configuration:** pyproject.toml (select: E, F, W, I, UP, B)

---

## Summary Statistics

| Metric | Count |
|--------|-------|
| **Total Issues** | 21 |
| **Errors** | 21 |
| **Warnings** | 0 |

### Issues by Code Type

| Code | Description | Count |
|------|-------------|-------|
| F821 | Undefined name | 1 |
| F401 | Unused import | 2 |
| I001 | Import block unsorted | 9 |
| W292 | Missing newline at end of file | 9 |

---

## Critical Issues (F821 - Undefined Names)

**CRITICAL BUG - Will cause runtime error**

| File | Line | Code | Issue | Fix |
|------|------|------|-------|-----|
| routes.py | 483 | F821 | `decrypt_api_key` used but not imported | Add `from ai_utils import decrypt_api_key` |

**Analysis:**
- Line 483: `api_key = decrypt_api_key(config.api_key_encrypted)`
- Current imports from ai_utils: `encrypt_api_key, test_ai_connection`
- Missing: `decrypt_api_key`
- Impact: Test connection button will crash when trying to decrypt stored API key

---

## Unused Imports (F401)

| File | Line | Code | Issue | Fix |
|------|------|------|-------|-----|
| routes.py | 22 | F401 | `SummaryGenerationForm` imported but unused | Remove import |
| summary_utils.py | 14 | F401 | `Group` imported but unused | Remove import |

**Analysis:**
- `SummaryGenerationForm` was imported but never used in any route handler
- `Group` in summary_utils.py:14 appears unused - no direct Group queries in the file

---

## Import Sorting Issues (I001)

| File | Line | Code | Issue | Fix |
|------|------|------|-------|-----|
| ai_utils.py | 13 | I001 | Import block unsorted | Run `ruff check --fix` |
| forms.py | 8 | I001 | Import block unsorted | Run `ruff check --fix` |
| routes.py | 9 | I001 | Import block unsorted | Run `ruff check --fix` |
| routes.py | 704 | I001 | Import block unsorted (in-file import) | Run `ruff check --fix` |
| summary_utils.py | 12 | I001 | Import block unsorted | Run `ruff check --fix` |
| utils/template_defaults.py | 7 | I001 | Import block unsorted | Run `ruff check --fix` |
| tests/test_ai_api.py | 12 | I001 | Import block unsorted | Run `ruff check --fix` |
| tests/test_summary_generation.py | 13 | I001 | Import block unsorted | Run `ruff check --fix` |
| tests/test_summary_utils.py | 9 | I001 | Import block unsorted | Run `ruff check --fix` |

**Fix Recommendation:**
All I001 issues can be auto-fixed with: `ruff check --fix .`

---

## Missing Trailing Newlines (W292)

| File | Line | Code | Issue | Fix |
|------|------|------|-------|-----|
| ai_utils.py | 313 | W292 | No newline at end of file | Add newline |
| summary_utils.py | 357 | W292 | No newline at end of file | Add newline |
| utils/__init__.py | 25 | W292 | No newline at end of file | Add newline |
| utils/template_defaults.py | 56 | W292 | No newline at end of file | Add newline |
| tests/test_ai_api.py | 361 | W292 | No newline at end of file | Add newline |
| tests/test_ai_config.py | 115 | W292 | No newline at end of file | Add newline |
| tests/test_ai_templates.py | 106 | W292 | No newline at end of file | Add newline |
| tests/test_summary_generation.py | 372 | W292 | No newline at end of file | Add newline |
| tests/test_summary_utils.py | 202 | W292 | No newline at end of file | Add newline |

**Fix Recommendation:**
All W292 issues can be auto-fixed with: `ruff check --fix .`

---

## Priority Order for Fixes

1. **F821 (routes.py:483)** - CRITICAL - Must fix first, will cause runtime crash
2. **F401 (routes.py:22, summary_utils.py:14)** - Medium - Cleanup unused imports
3. **I001 (9 issues)** - Low - Auto-fixable style issue
4. **W292 (9 files)** - Low - Auto-fixable style issue

---

## Recommended Fix Commands

```bash
# Auto-fix all I001 and W292 issues (safe)
.venv/bin/ruff check --fix .

# Manual fixes required for:
# 1. Add decrypt_api_key import to routes.py
# 2. Remove SummaryGenerationForm from routes.py imports
# 3. Remove Group from summary_utils.py imports
```

---

## Verification

After fixes, run: `.venv/bin/ruff check .` to verify 0 issues remain.