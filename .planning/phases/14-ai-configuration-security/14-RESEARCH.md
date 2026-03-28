# Phase 14: AI Configuration & Security - Research

**Researched:** 2026-03-28
**Domain:** Flask database models, WTForms validation, Fernet symmetric encryption, admin permission patterns
**Confidence:** HIGH

## Summary

Phase 14 implements AI service configuration storage with encrypted API key management. The system will store API URL, API Key, and Model name in a new `ai_config` database table. API Key encryption uses Fernet symmetric encryption from the cryptography library (v46.0.6). The encryption key is sourced from the `AI_ENCRYPTION_KEY` environment variable, following the existing pattern for `SECRET_KEY` in config.py. Admin-only access is enforced through the existing `User.is_admin` property and redirect pattern.

**Primary recommendation:** Follow existing project patterns closely - extend models.py with AIConfig model, extend forms.py with AIConfigForm using URLField + Regexp validator, extend config.html with a new Bootstrap card, and add encryption utility in a new ai_utils.py module.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- Store AI config (API URL/Key/Model) in database (new `ai_config` table) — allows admin UI updates without code changes
- Single record — one AI config for the whole system (defer multiple providers to future)
- Show config form with empty fields if missing — admin must configure before AI works
- Use Fernet symmetric encryption (cryptography library) — standard, secure, Python-native
- Store encryption key in environment variable (AI_ENCRYPTION_KEY) — consistent with existing SECRET_KEY pattern
- Show masked value in UI (last 4 chars visible) — admin can verify key is set without exposing full key
- Extend existing config.html — add new card section for AI config (matches existing pattern)
- Single form with URL/Key/Model fields + Test Connection button — simple, intuitive
- Show success/failure with friendly Chinese message for test connection — user-friendly feedback
- Admin only can view AI config — consistent with existing pattern
- Admin only can edit AI config — matches SEC-03 requirement
- Redirect to home with flash "需要管理员权限" if non-admin tries to access — matches existing pattern

### Claude's Discretion
- Exact form field labels and validation messages
- Specific encryption key derivation details
- Test connection API call implementation details

### Deferred Ideas (OUT OF SCOPE)
None — discussion stayed within phase scope.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| CONFIG-01 | AI service configuration storage (API URL, API Key, Model Name) | AIConfig model in models.py, AIConfigForm in forms.py |
| CONFIG-02 | Test connection functionality | Test button in form, minimal API request in routes.py |
| CONFIG-03 | Configuration persistence | Database storage with encrypted API Key |
| SEC-01 | API Key encryption storage | Fernet encryption in ai_utils.py, AI_ENCRYPTION_KEY env var |
| SEC-03 | Permission control (admin only) | User.is_admin property check, redirect pattern from routes.py |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| cryptography | 46.0.6 | Fernet symmetric encryption for API Key | Industry standard, actively maintained, pure Python |
| WTForms | 3.2.1 | Form validation (URLField, Regexp) | Already in project, familiar pattern |
| Flask-Security | 5.5.2 | Permission checks (current_user.is_admin) | Already integrated, consistent pattern |
| SQLAlchemy | 3.1.1 | AIConfig model storage | Already in project, db.Model pattern |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| requests | (add if needed) | Test connection API call | Phase 15 may use openai library instead |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| cryptography Fernet | passlib / bcrypt | Fernet is designed for symmetric encryption of arbitrary data, passlib/bcrypt are for password hashing |
| database storage | config file | Database allows admin UI updates without redeployment |
| env var for key | hardcoded key | Environment variables are standard for secrets, consistent with SECRET_KEY pattern |

**Installation:**
```bash
pip install cryptography==46.0.6
# Add to requirements.txt
```

**Version verification:** cryptography v46.0.6 verified from PyPI (2026-03-28). WTForms 3.2.1 already in requirements.txt.

## Architecture Patterns

### Recommended Project Structure
```
/
├── models.py          # Add AIConfig model (extend existing)
├── forms.py           # Add AIConfigForm (extend existing)
├── routes.py          # Add /ai-config route (extend existing)
├── ai_utils.py        # NEW - Encryption helpers, test connection
├── config.py          # Add AI_ENCRYPTION_KEY env var (extend existing)
├── templates/
│   └── config.html    # Extend with AI config card
└── tests/
    └── test_ai_config.py  # NEW - Unit tests for AI config
```

### Pattern 1: AIConfig Model (extends models.py)
**What:** Single-record database model for AI configuration
**When to use:** For system-wide AI settings that admins can modify via UI
**Example:**
```python
# Source: Existing models.py pattern (db.Model, db.Column)
from extensions import db

class AIConfig(db.Model):
    """AI service configuration model."""
    __tablename__ = "ai_config"

    id = db.Column(db.Integer, primary_key=True)
    api_url = db.Column(db.String(255), nullable=False)
    api_key_encrypted = db.Column(db.Text, nullable=False)  # Encrypted storage
    model_name = db.Column(db.String(100), nullable=False)

    @staticmethod
    def get_config():
        """Get the single AI config record or None."""
        return AIConfig.query.first()
```

### Pattern 2: AIConfigForm (extends forms.py)
**What:** WTForms form with URL validation and masked API Key display
**When to use:** For admin configuration UI
**Example:**
```python
# Source: Existing forms.py pattern (FlaskForm, StringField, validators)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Regexp

class AIConfigForm(FlaskForm):
    """Form for AI service configuration."""
    api_url = StringField(
        "API URL",
        validators=[
            DataRequired(message="API URL不能为空"),
            Regexp(r'^https?://', message="API URL必须以http://或https://开头")
        ],
        render_kw={"placeholder": "https://api.openai.com/v1"}
    )
    api_key = PasswordField(
        "API Key",
        validators=[DataRequired(message="API Key不能为空")],
        description="保存后仅显示最后4位字符"
    )
    model_name = StringField(
        "模型名称",
        validators=[DataRequired(message="模型名称不能为空")],
        render_kw={"placeholder": "gpt-4o-mini"}
    )
    test_submit = SubmitField("测试连接")
    save_submit = SubmitField("保存配置")
```

### Pattern 3: Fernet Encryption Helper (new ai_utils.py)
**What:** Encryption/decryption utilities for API Key
**When to use:** Whenever storing or retrieving API Key
**Example:**
```python
# Source: cryptography library Fernet documentation
import os
from cryptography.fernet import Fernet

def get_fernet_key():
    """Get Fernet key from environment variable."""
    key = os.environ.get("AI_ENCRYPTION_KEY")
    if not key:
        raise ValueError("AI_ENCRYPTION_KEY environment variable not set")
    return key.encode()  # Fernet expects bytes

def get_fernet():
    """Get Fernet instance for encryption/decryption."""
    return Fernet(get_fernet_key())

def encrypt_api_key(api_key: str) -> str:
    """Encrypt API key for storage."""
    f = get_fernet()
    return f.encrypt(api_key.encode()).decode()

def decrypt_api_key(encrypted_key: str) -> str:
    """Decrypt API key for use."""
    f = get_fernet()
    return f.decrypt(encrypted_key.encode()).decode()

def mask_api_key(api_key: str) -> str:
    """Mask API key showing only last 4 characters."""
    if len(api_key) <= 4:
        return "****"
    return "*" * (len(api_key) - 4) + api_key[-4:]
```

### Pattern 4: Admin Permission Check (routes.py)
**What:** Admin-only route protection
**When to use:** For AI config routes that should only be accessible by admins
**Example:**
```python
# Source: Existing routes.py pattern (current_user.is_admin, redirect, flash)
@app.route("/ai-config", methods=["GET", "POST"])
@login_required
@with_db_transaction
def ai_config():
    # Admin permission check
    if not current_user.is_admin:
        flash("需要管理员权限", "warning")
        return redirect(url_for("home"))

    form = AIConfigForm()
    config = AIConfig.get_config()

    if form.validate_on_submit():
        # Handle save or test
        ...

    return render_template("config.html", ai_form=form, ai_config=config)
```

### Anti-Patterns to Avoid
- **Storing API Key plaintext:** Never store API Key unencrypted in database — use Fernet
- **Hardcoding encryption key:** Never hardcode AI_ENCRYPTION_KEY in code — use environment variable
- **Missing admin check:** Never allow non-admin users to access AI config routes — check `current_user.is_admin`
- **Missing CSRF protection:** WTForms with Flask-WTF handles CSRF automatically, but ensure `WTF_CSRF_ENABLED` is not disabled

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| URL validation | Custom regex validation | WTForms Regexp validator with `^https?://` pattern | WTForms integrates with Flask-WTF CSRF protection |
| Encryption | Custom AES implementation | cryptography.fernet.Fernet | Fernet handles key derivation, IV, authentication - don't reinvent |
| Permission check | Custom role checking | current_user.is_admin property | Already exists in User model, consistent with project |
| Form rendering | Manual HTML form | render_form from bootstrap5 | Already used in config.html, consistent styling |

**Key insight:** The project has established patterns for all the components needed. Extending existing modules is safer than creating new parallel implementations.

## Runtime State Inventory

> This phase involves database schema changes but no renaming/migration of existing data.

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | None — new `ai_config` table, no migration of existing records | Database migration: create table |
| Live service config | None — AI config will be stored in database, not external services | None |
| OS-registered state | None — no systemd/launchd changes needed | None |
| Secrets/env vars | AI_ENCRYPTION_KEY — new env var, no existing keys to migrate | Add to deployment documentation |
| Build artifacts | None — no compiled artifacts affected | None |

**Nothing found in category:** Verified explicitly — this is a new feature with no existing state to migrate.

## Common Pitfalls

### Pitfall 1: Missing AI_ENCRYPTION_KEY on startup
**What goes wrong:** Application crashes when trying to encrypt/decrypt API Key if env var not set
**Why it happens:** Fernet requires a valid key; missing key causes ValueError
**How to avoid:** Graceful handling - check key availability on startup, log warning if missing, disable AI features until configured
**Warning signs:** `ValueError: AI_ENCRYPTION_KEY environment variable not set`

### Pitfall 2: Invalid Fernet Key Format
**What goes wrong:** Fernet key must be 32 URL-safe base64-encoded bytes
**Why it happens:** Admin might set AI_ENCRYPTION_KEY to arbitrary string
**How to avoid:** Document key format, provide key generation script: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
**Warning signs:** `cryptography.fernet.InvalidToken` or key validation errors

### Pitfall 3: API Key Decryption Failure After Key Change
**What goes wrong:** Changing AI_ENCRYPTION_KEY makes previously encrypted keys unreadable
**Why it happens:** Fernet is symmetric encryption; different key cannot decrypt
**How to avoid:** Document that key change requires re-entering API Key; consider key rotation procedure for production
**Warning signs:** `cryptography.fernet.InvalidToken` when decrypting

### Pitfall 4: Test Connection Exposing API Key in Logs
**What goes wrong:** Logging API request details might expose API Key
**Why it happens:** Debug logging captures full request including Authorization header
**How to avoid:** Filter Authorization headers from logs, use minimal test request
**Warning signs:** API Key appearing in `/var/log/weekly/app.log`

## Code Examples

Verified patterns from project files:

### AIConfig Model Extension (models.py)
```python
# Pattern from existing models.py (db.Model, db.Column, static methods)
class AIConfig(db.Model):
    """AI service configuration model - single system-wide config."""
    __tablename__ = "ai_config"

    id = db.Column(db.Integer, primary_key=True)
    api_url = db.Column(db.String(255), nullable=False)
    api_key_encrypted = db.Column(db.Text, nullable=False)
    model_name = db.Column(db.String(100), nullable=False)

    @staticmethod
    def get_config():
        """Get the single AI config record or None if not configured."""
        return AIConfig.query.first()

    @staticmethod
    @with_db_transaction
    def save_config(api_url: str, api_key_encrypted: str, model_name: str):
        """Save or update AI configuration."""
        config = AIConfig.get_config()
        if config:
            config.api_url = api_url
            config.api_key_encrypted = api_key_encrypted
            config.model_name = model_name
        else:
            config = AIConfig(
                api_url=api_url,
                api_key_encrypted=api_key_encrypted,
                model_name=model_name
            )
            db.session.add(config)
        db.session.commit()
        return config
```

### Form Validation (forms.py pattern)
```python
# Pattern from existing forms.py (FlaskForm, validators)
from wtforms.validators import Regexp

class AIConfigForm(FlaskForm):
    api_url = StringField(
        "API URL",
        validators=[
            DataRequired(message="API URL不能为空"),
            Regexp(r'^https?://.+', message="API URL格式无效，必须以http://或https://开头")
        ]
    )
    api_key = PasswordField("API Key", validators=[DataRequired(message="API Key不能为空")])
    model_name = StringField("模型名称", validators=[DataRequired(message="模型名称不能为空")])
    test_submit = SubmitField("测试连接")
    submit = SubmitField("保存配置")
```

### Bootstrap Card Extension (config.html pattern)
```html
<!-- Pattern from existing config.html (card, render_form) -->
<div class="card shadow-sm mb-4">
    <div class="card-header bg-light">
        <h5 class="mb-0">{{ render_icon('robot') }} AI 配置</h5>
    </div>
    <div class="card-body">
        <p class="text-muted mb-4">配置AI服务参数，支持OpenAI兼容API。</p>
        {% if ai_config %}
        <p class="text-muted">当前API Key: <code>{{ ai_config.masked_key }}</code></p>
        {% endif %}
        {{ render_form(ai_form) }}
    </div>
</div>
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Config in files | Config in database | v1.0 (existing) | Admin can modify without redeployment |
| Plaintext secrets | Encrypted secrets | Phase 14 | API Key secured in database |

**Deprecated/outdated:**
- plaintext API Key storage: Use Fernet encryption instead

## Open Questions

1. **Test Connection Implementation Detail**
   - What we know: Need to send minimal API request to verify connectivity
   - What's unclear: Exact endpoint (list models vs. simple completion) and error handling granularity
   - Recommendation: Use `GET /models` endpoint (lightweight, no token consumption) or minimal chat completion with timeout

2. **Encryption Key Rotation Strategy**
   - What we know: Fernet key must be consistent to decrypt stored values
   - What's unclear: Whether to support key rotation for production deployments
   - Recommendation: Document that key change requires re-entering API Key; defer rotation automation to future

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| cryptography | API Key encryption | ✗ (needs install) | 46.0.6 | No fallback |
| WTForms | Form validation | ✓ | 3.2.1 | — |
| Flask-Security | Permission checks | ✓ | 5.5.2 | — |
| pytest | Testing | ✓ | 8.3.5 | — |

**Missing dependencies with no fallback:**
- cryptography — must be installed before implementation

**Installation command:**
```bash
pip install cryptography==46.0.6
# Add to requirements.txt
```

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | pytest 8.3.5 |
| Config file | pytest.ini |
| Quick run command | `pytest tests/test_ai_config.py -v` |
| Full suite command | `pytest tests/ -v` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| CONFIG-01 | AI config model stores URL/Key/Model | unit | `pytest tests/test_ai_config.py::TestAIConfigModel -v` | ❌ Wave 0 |
| CONFIG-02 | Test connection button works | integration | `pytest tests/test_ai_config.py::TestConnection -v` | ❌ Wave 0 |
| CONFIG-03 | Config persists after restart | unit | `pytest tests/test_ai_config.py::TestPersistence -v` | ❌ Wave 0 |
| SEC-01 | API Key encrypted in database | unit | `pytest tests/test_ai_config.py::TestEncryption -v` | ❌ Wave 0 |
| SEC-03 | Admin-only access enforced | integration | `pytest tests/test_ai_config.py::TestPermissions -v` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `pytest tests/test_ai_config.py -v`
- **Per wave merge:** `pytest tests/ -v`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `tests/test_ai_config.py` — covers CONFIG-01, CONFIG-02, CONFIG-03, SEC-01, SEC-03
- [ ] `tests/conftest.py` — add admin_user fixture (extend existing)
- [ ] `ai_utils.py` — module to create for encryption helpers

*(If no gaps: "None — existing test infrastructure covers all phase requirements")*

### Test Fixture Patterns (from conftest.py)
```python
# Extend existing conftest.py with admin fixture
@pytest.fixture
def admin_user(client):
    """Create an admin user for testing admin-only features."""
    with client.application.app_context():
        admin_role = Role(name="admin", permissions=["view_all", "edit_database"])
        db.session.add(admin_role)
        user = user_datastore.create_user(
            email="admin@example.com",
            username="adminuser",
            password=hash_password("AdminPass123"),
            roles=[admin_role]
        )
        db.session.commit()
        return {"username": "adminuser", "password": "AdminPass123", "id": user.id}

@pytest.fixture
def admin_client(client, admin_user):
    """Authenticated admin client."""
    client.post("/login", data={
        "username": admin_user["username"],
        "password": admin_user["password"]
    })
    yield client
```

## Sources

### Primary (HIGH confidence)
- Project source files: models.py, forms.py, routes.py, config.py, templates/config.html
- PyPI: cryptography 46.0.6 (verified 2026-03-28)
- pytest.ini, tests/conftest.py - test infrastructure patterns

### Secondary (MEDIUM confidence)
- WTForms documentation (URL validation patterns)
- cryptography Fernet documentation (encryption patterns)

### Tertiary (LOW confidence)
- None — all patterns verified from project files

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — cryptography and WTForms are well-established; versions verified
- Architecture: HIGH — patterns derived from existing project files
- Pitfalls: HIGH — common encryption pitfalls are well-documented

**Research date:** 2026-03-28
**Valid until:** 30 days (stable libraries, project patterns are internal)