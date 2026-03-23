---
phase: 05-code-refactoring
plan: 03
subsystem: code-refactoring
tags: [refactoring, modularization, forms, routes, uuid]
requires: [05-01, 05-02]
provides: [forms.py, routes.py, refactored app.py]
affects: [app.py, tests/]
tech-stack:
  added:
    - forms.py with WTForms classes
    - routes.py with register_routes pattern
    - UUID for upload filenames
  patterns:
    - Application factory pattern
    - register_routes() for route registration
    - Backward-compatible imports for tests
key-files:
  created:
    - forms.py
    - routes.py
  modified:
    - app.py
    - templates/security/login_user.html
decisions:
  - D-11: UUID for upload filenames to prevent collisions
  - D-01: register_routes pattern without Blueprints
metrics:
  duration: 18min
  tasks: 3
  files: 7
  tests_passed: 62
---

# Phase 05 Plan 03: Forms, Routes, and App Refactoring Summary

## One-liner
Created forms.py and routes.py modules, refactored app.py to use modular imports, added UUID for upload filenames, with all 62 tests passing.

## Changes Made

### Task 1: Create forms.py with all WTForms classes
- Extracted all form classes from app.py into dedicated forms.py module
- MyLoginForm, MyRegisterForm, MyChangePasswordForm, MyForgotPasswordForm for authentication
- RecordFilterForm, RecordDownloadForm, RecordForm, ThemeForm for application features
- RecordForm.body is patched to CKEditorField in routes.py when used with the app

### Task 2: Create routes.py with register_routes function
- Implemented register_routes(app) pattern per D-01 (no Blueprints)
- All helper functions: get_allowed_groups, get_allowed_usernames, can_edit_record, build_record_query
- All route handlers for authentication (login, logout, register, forgot_password, change_password)
- All route handlers for records (create, edit, delete, manage, download)
- Configuration route for theme selection
- Per D-11: Upload filenames now use UUID prefix (e.g., `a1b2c3d4e5f6_original.jpg`)

### Task 3: Refactor app.py to use new modules
- app.py now imports from config, extensions, models, forms, routes modules
- create_app() factory function for application initialization
- Backward-compatible exports for tests: app, db, user_datastore, User, Record, Role, Group
- Helper functions re-exported from routes: can_edit_record, get_allowed_usernames, get_allowed_groups
- Fixed login template to not require csrf_token field when CSRF is disabled in tests

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] models.py missing from worktree**
- **Found during:** Task 1 execution
- **Issue:** models.py was created in another worktree but not present in current worktree
- **Fix:** Created models.py with all database models, association tables, and with_db_transaction decorator
- **Files modified:** models.py
- **Commit:** b0079e3

**2. [Rule 1 - Bug] CSRF token field missing in login form when CSRF disabled**
- **Found during:** Task 3 verification (test failures)
- **Issue:** Login template referenced csrf_token field which doesn't exist when WTF_CSRF_ENABLED=False in tests
- **Fix:** Removed explicit csrf_token render from login_user.html template; hidden_tag() already handles CSRF when enabled
- **Files modified:** templates/security/login_user.html
- **Commit:** e9e83e6

### Prerequisite Files Created
- config.py (copied from main repo)
- extensions.py (copied from main repo)

## Verification

- [x] forms.py exists with all WTForms classes
- [x] routes.py exists with register_routes function
- [x] app.py refactored to use new modules
- [x] Upload filenames use UUID prefix (per D-11)
- [x] All 62 tests pass

## Test Results

```
======================== 62 passed, 9 warnings in 9.76s ========================
```

## Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Route registration | register_routes(app) | Per D-01, simple pattern without Blueprints complexity |
| UUID for uploads | f"{uuid.uuid4().hex}_{filename}" | Per D-11, prevents file collision overwrites |
| Test compatibility | Re-export from app.py | Maintains backward compatibility with existing test imports |
| CSRF in tests | Remove from template | hidden_tag() already handles CSRF when enabled |

## Files Modified

| File | Changes |
|------|---------|
| app.py | Complete rewrite to use modular imports, create_app factory |
| forms.py | NEW - All WTForms form classes |
| routes.py | NEW - All route handlers with register_routes pattern |
| models.py | NEW - All database models (created as prerequisite) |
| config.py | NEW - Configuration classes (copied from main repo) |
| extensions.py | NEW - Flask extension initialization (copied from main repo) |
| templates/security/login_user.html | Removed explicit csrf_token render |

## Commits

1. `b0079e3` - feat(05-02): create models.py with database models
2. `1ae3f63` - feat(05-03): create forms.py with WTForms classes
3. `9620328` - feat(05-03): create routes.py with all route handlers
4. `e9e83e6` - feat(05-03): refactor app.py to use modular structure

## Duration

- Start: 2026-03-23T08:48:07Z
- End: 2026-03-23T09:06:25Z
- Total: ~18 minutes

## Self-Check: PASSED

- [x] SUMMARY.md exists at .planning/phases/05-code-refactoring/05-03-SUMMARY.md
- [x] All task commits exist: b0079e3, 1ae3f63, 9620328, e9e83e6
- [x] Final documentation commit exists: b4c59d9
- [x] All 62 tests passed