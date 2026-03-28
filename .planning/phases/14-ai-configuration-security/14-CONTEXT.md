# Phase 14: AI Configuration & Security - Context

**Gathered:** 2026-03-28
**Status:** Ready for planning

<domain>
## Phase Boundary

Implement AI service configuration storage, testing, and security. Admins can securely configure API URL, API Key, and model name through the UI. Configuration persists in the database with encrypted API Key. Permission checks ensure only admins can view/edit AI settings.

</domain>

<decisions>
## Implementation Decisions

### Configuration Storage Location
- Store AI config (API URL/Key/Model) in database (new `ai_config` table) — allows admin UI updates without code changes
- Single record — one AI config for the whole system (defer multiple providers to future)
- Show config form with empty fields if missing — admin must configure before AI works

### API Key Encryption
- Use Fernet symmetric encryption (cryptography library) — standard, secure, Python-native
- Store encryption key in environment variable (AI_ENCRYPTION_KEY) — consistent with existing SECRET_KEY pattern
- Show masked value in UI (last 4 chars visible) — admin can verify key is set without exposing full key

### UI Location
- Extend existing config.html — add new card section for AI config (matches existing pattern)
- Single form with URL/Key/Model fields + Test Connection button — simple, intuitive
- Show success/failure with friendly Chinese message for test connection — user-friendly feedback

### Permission Model
- Admin only can view AI config — consistent with existing pattern
- Admin only can edit AI config — matches SEC-03 requirement
- Redirect to home with flash "需要管理员权限" if non-admin tries to access — matches existing pattern

### Claude's Discretion
- Exact form field labels and validation messages
- Specific encryption key derivation details
- Test connection API call implementation details

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `config.html` — existing configuration page with Bootstrap cards, can extend with AI config section
- `models.py` — database model patterns (db.Model, db.Column, db.Table)
- `User.is_admin` — property for permission checks
- `forms.py` — WTForms patterns for form handling
- `routes.py` — route patterns with permission checks

### Established Patterns
- Config stored in database for admin-editable settings (User, Group models)
- Environment variables for secrets (SECRET_KEY from os.environ in config.py)
- Bootstrap 5 UI with card layouts (config.html pattern)
- Flask-Security for authentication/roles (current_user.is_authenticated, current_user.is_admin)
- `with_db_transaction` decorator for DB operations

### Integration Points
- `config.html` — add AI config card after existing theme config
- `models.py` — add AIConfig model
- `forms.py` — add AIConfigForm
- `routes.py` — add `/ai-config` route with admin check
- `.env` or environment — AI_ENCRYPTION_KEY

</code_context>

<specifics>
## Specific Ideas

- Test Connection button should send a minimal API request (e.g., list models or simple completion)
- Form should show current masked key value when config exists
- Validation: API URL must be valid URL format, Model name cannot be empty

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>