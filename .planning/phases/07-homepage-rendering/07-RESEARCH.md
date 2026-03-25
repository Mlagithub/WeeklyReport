# Phase 7: Homepage Rendering - Research

**Researched:** 2026-03-25
**Domain:** Flask/Jinja2 HTML sanitization, XSS prevention with bleach
**Confidence:** HIGH

## Summary

This phase addresses the rendering of rich text content on the homepage's "Recent Submissions" list. Currently, the home template uses `striptags | truncate(80, True, '...')` which removes ALL HTML tags, causing loss of formatting (bold, italic, lists) from CKEditor-generated content.

The solution involves creating a Jinja2 custom filter using the existing `bleach` library (v6.2.0, already installed) to sanitize HTML while preserving safe formatting tags. The filter will be registered in `app.py` and used in the `home.html` template with the `|safe` filter after sanitization.

**Primary recommendation:** Create a `sanitize_html` custom filter using bleach with a whitelist of CKEditor's common output tags, then modify the home template to use `{{ record.content | sanitize_html | truncate(80) | safe }}`.

<phase_requirements>

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| RENDER-01 | 主页最近提交列表正确渲染富文本格式 | Standard Stack: bleach.clean() with tag whitelist; Jinja2 custom filter pattern |
| RENDER-02 | 渲染时保持 XSS 防护（使用 bleach 或白名单） | bleach default behavior escapes dangerous content; configure allowed_tags/attributes |

</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| bleach | 6.2.0 | HTML sanitization | Already installed; Python standard for XSS prevention |
| Jinja2 | 3.x (Flask 3.0.3) | Template custom filters | Native Flask/Jinja2 feature |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| beautifulsoup4 | 4.12.3 | HTML parsing | Already installed; optional for complex truncation |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| bleach | nh3 (Rust-based) | Faster but newer; bleach is battle-tested and already installed |
| Custom filter | Mark as `|safe` directly | Dangerous - bypasses ALL XSS protection |
| bleach | DOMPurify (JS) | Client-side only; bleach is server-side protection |

**Installation:**
No new packages needed. bleach 6.2.0 is already installed per requirements.txt.

**Version verification:**
```
bleach==6.2.0 (verified in requirements.txt and .venv)
```

## Architecture Patterns

### Recommended Implementation

**1. Custom Filter Registration (app.py)**
```python
import bleach

# CKEditor commonly produces these tags
ALLOWED_TAGS = {
    'p', 'br', 'b', 'i', 'strong', 'em', 'u',
    'ul', 'ol', 'li', 'a', 'img',
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'blockquote', 'pre', 'code',
    'table', 'thead', 'tbody', 'tr', 'td', 'th',
    'span', 'div'
}

ALLOWED_ATTRIBUTES = {
    '*': ['class', 'style'],  # Allow class/style on all tags
    'a': ['href', 'title', 'target', 'rel'],
    'img': ['src', 'alt', 'title', 'width', 'height'],
}

ALLOWED_PROTOCOLS = {'http', 'https', 'mailto'}

@app.template_filter('sanitize_html')
def sanitize_html(text):
    """Sanitize HTML content for safe rendering.

    Allows common CKEditor formatting tags while blocking XSS.
    Returns Markup object marked safe for Jinja2 rendering.
    """
    if not text:
        return ''
    return bleach.clean(
        text,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=ALLOWED_PROTOCOLS,
        strip=False
    )
```

**2. Template Usage (home.html)**
```jinja
{# Line 71 replacement #}
<span class="text-muted">{{ record.content | sanitize_html | truncate(80) | safe }}</span>
```

**Important:** The order matters: `sanitize_html` first, then `truncate`, then `safe`.

### Pattern 1: Jinja2 Custom Filter in Flask
**What:** Flask provides `@app.template_filter()` decorator to register custom filters.
**When to use:** When you need custom text processing in templates.
**Example:**
```python
# Source: https://flask.palletsprojects.com/en/3.0.x/templating/#registering-filters
@app.template_filter('reverse')
def reverse_filter(s):
    return s[::-1]

# In template: {{ text | reverse }}
```

### Anti-Patterns to Avoid

- **Never use `|safe` without sanitization:** `{{ record.content | safe }}` is XSS vulnerability
- **Don't striptags then expect formatting:** Current code loses all formatting
- **Don't trust CKEditor output directly:** Client-side editors can be bypassed
- **Don't forget to test XSS vectors:** `<script>`, `onclick`, `javascript:` URLs

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| XSS filtering | Custom regex | bleach.clean() | Regex can't handle all edge cases; bleach is OWASP-tested |
| HTML tag removal | Manual string operations | bleach.clean(tags=set()) | Handles malformed HTML, nested tags, encoding attacks |
| Truncation with HTML | Custom slice | Jinja2 truncate filter | After sanitization, text is safe to truncate |

**Key insight:** XSS prevention is security-critical. Always use proven libraries, never write custom sanitization.

## Common Pitfalls

### Pitfall 1: Double Escaping
**What goes wrong:** Content shows as `&lt;b&gt;text&lt;/b&gt;` instead of rendered HTML.
**Why it happens:** Using `|sanitize_html` without `|safe` causes Jinja2 to escape the already-safe HTML.
**How to avoid:** Always apply `|safe` AFTER sanitization: `{{ content | sanitize_html | safe }}`
**Warning signs:** Seeing HTML entities instead of formatted text in browser.

### Pitfall 2: Truncate Breaking HTML
**What goes wrong:** Truncating in the middle of an HTML tag creates broken markup.
**Why it happens:** `truncate(80)` counts characters, not tag boundaries.
**How to avoid:** Either:
1. Truncate first (striptags), then sanitize - loses formatting
2. Accept that truncation may break tags - minor display issue
3. Use bleach.clean(strip=True) to strip disallowed tags before truncate
**Warning signs:** Unclosed tags, missing closing brackets in output.

### Pitfall 3: Missing Tags in Whitelist
**What goes wrong:** Valid CKEditor formatting is stripped.
**Why it happens:** ALLOWED_TAGS doesn't include all tags CKEditor produces.
**How to avoid:** Test with actual CKEditor output; add missing tags to whitelist.
**Warning signs:** Formatting works in editor but not on homepage.

### Pitfall 4: XSS via Attributes
**What goes wrong:** `<a onclick="evil()">` executes malicious code.
**Why it happens:** Allowing dangerous attributes like `onclick`, `onerror`.
**How to avoid:** Use bleach's default ALLOWED_ATTRIBUTES or explicitly whitelist safe ones only.
**Warning signs:** JavaScript execution from user input.

## Code Examples

### Basic bleach.clean() Usage
```python
# Source: https://bleach.readthedocs.io/en/latest/clean.html
import bleach

# Default behavior - very restrictive
bleach.clean('<script>evil()</script><b>safe</b>')
# Output: '&lt;script&gt;evil()&lt;/script&gt;<b>safe</b>'

# With custom tags
bleach.clean(
    '<p class="intro"><b>Hello</b></p>',
    tags={'p', 'b'},
    attributes={'p': ['class']}
)
# Output: '<p class="intro"><b>Hello</b></p>'
```

### Flask Filter Registration
```python
# Source: https://flask.palletsprojects.com/en/3.0.x/templating/
from flask import Flask
import bleach
from markupsafe import Markup

app = Flask(__name__)

@app.template_filter('sanitize_html')
def sanitize_html(text):
    if not text:
        return ''
    clean = bleach.clean(text, tags={'b', 'i', 'p', 'a'}, attributes={'a': ['href']})
    return Markup(clean)
```

### Template Integration
```jinja
{# Without sanitization (DANGEROUS) #}
{{ content | safe }}  {# XSS vulnerability! #}

{# Current approach (loses formatting) #}
{{ content | striptags | truncate(80) }}

{# Correct approach (safe + formatted) #}
{{ content | sanitize_html | truncate(80) | safe }}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| striptags filter | bleach.clean() with whitelist | This phase | Preserves formatting while blocking XSS |
| Trust CKEditor output | Server-side sanitization | This phase | Defense in depth against bypass |

**Deprecated/outdated:**
- bleach 6.x is deprecated as of January 2023, but still maintained and widely used. For new projects, consider `nh3` (Rust-based, faster), but bleach remains the standard for Python XSS prevention.

## Open Questions

1. **Should we truncate before or after sanitization?**
   - What we know: Truncating after sanitization may break HTML tags mid-string.
   - What's unclear: Whether this causes significant display issues in practice.
   - Recommendation: Apply truncation after sanitization. If broken tags cause issues, add CSS `overflow: hidden` or use a different approach.

2. **Should we allow `style` attribute?**
   - What we know: CKEditor can produce inline styles. Allowing `style` has minor XSS risk (CSS expressions in old IE).
   - What's unclear: Whether users actually use style features.
   - Recommendation: Include `style` in ALLOWED_ATTRIBUTES initially. Modern browsers don't execute CSS expressions.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| bleach | HTML sanitization | Yes | 6.2.0 | - |
| Flask | Template filters | Yes | 3.0.3 | - |
| Jinja2 | Template rendering | Yes | 3.x (bundled) | - |
| beautifulsoup4 | Optional truncation | Yes | 4.12.3 | Not needed for basic implementation |

**Missing dependencies with no fallback:**
None - all required dependencies are already installed.

**Missing dependencies with fallback:**
None.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | pytest 8.3.5 |
| Config file | pytest.ini |
| Quick run command | `pytest tests/test_routes.py -x -v` |
| Full suite command | `pytest tests/ -v --cov=app` |

### Phase Requirements -> Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| RENDER-01 | Rich text formatting preserved in homepage list | unit | `pytest tests/test_routes.py::TestHomeRendering -v` | Wave 0 |
| RENDER-02 | XSS attacks are filtered/sanitized | unit | `pytest tests/test_routes.py::TestXSSPrevention -v` | Wave 0 |

### Sampling Rate
- **Per task commit:** `pytest tests/test_routes.py -x -v`
- **Per wave merge:** `pytest tests/ -v`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `tests/test_routes.py::TestHomeRendering` - tests for RENDER-01 (rich text rendering)
- [ ] `tests/test_routes.py::TestXSSPrevention` - tests for RENDER-02 (XSS filtering)
- [ ] Filter function unit tests in `tests/test_utils.py` or new file

### Recommended Test Cases

**For RENDER-01 (Formatting Preservation):**
```python
def test_home_shows_bold_text(auth_client):
    """Test that <b> tags are rendered, not escaped."""
    # Create record with bold content
    # Fetch home page
    # Assert <b> appears in output (not &lt;b&gt;)

def test_home_shows_list_items(auth_client):
    """Test that <ul><li> tags are rendered correctly."""
    # Create record with list
    # Fetch home page
    # Assert <ul> and <li> appear in output
```

**For RENDER-02 (XSS Prevention):**
```python
def test_xss_script_filtered(auth_client):
    """Test that <script> tags are escaped/removed."""
    # Create record with <script>alert('xss')</script>
    # Fetch home page
    # Assert <script> does NOT appear in output
    # Assert alert('xss') is escaped or removed

def test_xss_onclick_filtered(auth_client):
    """Test that onclick attributes are removed."""
    # Create record with <a onclick="evil()">
    # Fetch home page
    # Assert onclick does NOT appear in output

def test_xss_javascript_url_filtered(auth_client):
    """Test that javascript: URLs are removed."""
    # Create record with <a href="javascript:evil()">
    # Fetch home page
    # Assert javascript: does NOT appear in href
```

## Sources

### Primary (HIGH confidence)
- bleach documentation - https://bleach.readthedocs.io/en/latest/clean.html
- Flask template filters - https://flask.palletsprojects.com/en/3.0.x/templating/#registering-filters
- Project requirements.txt - bleach 6.2.0 verified

### Secondary (MEDIUM confidence)
- Jinja2 custom filters - https://jinja.palletsprojects.com/en/3.1.x/api/#custom-filters

### Tertiary (LOW confidence)
- None - all critical information verified from official documentation

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - bleach already installed, Flask filter pattern is well-documented
- Architecture: HIGH - straightforward filter registration, minimal code changes
- Pitfalls: HIGH - XSS patterns are well-documented, bleach handles edge cases

**Research date:** 2026-03-25
**Valid until:** 30 days (bleach API stable)