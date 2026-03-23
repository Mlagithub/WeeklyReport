# Phase 5: Code Refactoring - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-03-23
**Phase:** 05-code-refactoring
**Areas discussed:** Module Split, Configuration, Refactor Scope, Minor Improvements

---

## Module Split

| Option | Description | Selected |
|--------|-------------|----------|
| Simple split (Recommended) | Split app.py into: models.py, routes.py, forms.py, config.py, extensions.py. Keep simple, no Flask Blueprints. | ✓ |
| Blueprint-based | Use Flask Blueprints with routes/ directory for better organization. More structure, slightly more complex. | |
| Minimal | Just extract config and models. Keep routes in app.py for now. | |

**User's choice:** Simple split
**Notes:** Standard Flask modular structure

---

## Configuration

| Option | Description | Selected |
|--------|-------------|----------|
| Config class (Recommended) | Create config.py with class-based config (Development, Production). Read all secrets from env vars. Keep existing defaults for local dev. | ✓ |
| Inline env vars | Keep config in app.py but replace hardcoded values with os.environ.get() calls. Simpler, less structure. | |
| .env file | Use .env file with python-dotenv. Good for local dev, but adds dependency. | |

**User's choice:** Config class
**Notes:** Class-based configuration pattern from Flask docs

---

## Refactor Scope

| Option | Description | Selected |
|--------|-------------|----------|
| Minimal (Recommended) | Split files, centralize config, ensure tests pass. No major logic changes. Low risk, quick to complete. | ✓ |
| Moderate | Above + fix minor issues from CONCERNS.md (add database index, enable CSRF for uploads). More improvements, slightly more risk. | |
| Comprehensive | Full restructure + all improvements from CONCERNS.md. Most thorough, highest effort. | |

**User's choice:** Minimal
**Notes:** Low risk approach, focus on structure only

---

## Minor Improvements

| Option | Description | Selected |
|--------|-------------|----------|
| Database index | Add index=True to Record.date column. Improves query performance for date filtering. | ✓ |
| CKEditor CSRF | Enable CSRF protection for CKEditor file uploads. Security improvement. | |
| Fix XSS risk | Replace build_edit_buttons() HTML string with Jinja2 template. Security improvement. | |
| Unique upload names | Generate unique filenames for uploads. Prevents file overwrites. | ✓ |

**User's choice:** Database index, Unique upload names
**Notes:** Two targeted improvements included

---

## Claude's Discretion

- Specific file splitting order
- Import statement organization
- Exact configuration items in config class

## Deferred Ideas

- Flask Blueprints restructuring — more complex
- CSRF for CKEditor — needs extra config
- XSS fix for build_edit_buttons — needs template changes
- PostgreSQL migration — out of scope
- Flask-Migrate/Alembic — needs more planning