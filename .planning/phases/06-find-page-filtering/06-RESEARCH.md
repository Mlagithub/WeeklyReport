# Phase 6: Find Page Filtering - Research

**Researched:** 2026-03-25
**Domain:** Flask web application filter defaults, WTForms, Jinja2 templates
**Confidence:** HIGH

## Summary

This phase implements default filter values for the find page (`/manage_records`) to reduce information overload. The current implementation shows all records by default; the requirement is to default to showing the current user's records from the last 7 days.

**Primary recommendation:** Modify the template to set default selected values when URL parameters are absent, and add a 'last_7_days' option to the DateRange.TIME_RANGES dictionary.

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| FIND-01 | Default select current user for "按用户" filter | Template conditional: check `request.args.get('user')` is empty, then select current_user.username |
| FIND-02 | Default select last 7 days for "按日期" filter | Add 'last_7_days' to TIME_RANGES; template conditional for default selection |
| FIND-03 | Preserve existing filter functionality | No changes to query logic; only modify default selection in template |

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Flask | 3.0.3 | Web framework | Project standard |
| WTForms | 3.2.1 | Form handling | Used by RecordFilterForm |
| Jinja2 | (Flask bundled) | Template rendering | Template conditionals for defaults |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| Bootstrap-Flask | 2.4.1 | UI components | Template rendering (already used) |
| python-dateutil | 2.9.0.post0 | Date calculations | Already used by DateRange class |

## Architecture Patterns

### Current Implementation

**Route:** `/manage_records` in `routes.py` (lines 321-382)
- Uses `RecordFilterForm` to define filter fields
- Calls `build_record_query(request.args)` to construct database query
- Renders `manage_records.html` template

**Form:** `RecordFilterForm` in `forms.py` (lines 58-63)
```python
class RecordFilterForm(FlaskForm):
    user = SelectField("按用户", choices=[], default='')
    groups = SelectMultipleField("按小组", choices=[])
    time_range = SelectField("按日期", choices=[(key, value) for key, value in DateRange.TIME_RANGES.items()])
    submit = SubmitField("确定")
```

**Template:** `manage_records.html` (lines 24-56)
- User dropdown: `<option value="">不限</option>` followed by user choices
- Time range dropdown: `<option value="">不限</option>` followed by time range choices
- Selection state determined by: `{% if request.args.get('user') == value %}selected{% endif %}`

### DateRange Class

**Location:** `utils.py` (lines 6-93)

**Current TIME_RANGES:**
```python
TIME_RANGES = {
    'this_week': '本周',
    'last_week': '上周',
    'this_month': '本月',
    'this_quarter': '本季度',
    'this_year': '本年',
}
```

**Available method:** `last_n_days(n)` exists but is NOT in TIME_RANGES
```python
@staticmethod
def last_n_days(n):
    today = DateRange.get_today()
    start_date = today - timedelta(days=n)
    end_date = today
    return start_date, end_date
```

### Recommended Changes

1. **Add 'last_7_days' to TIME_RANGES** (utils.py):
```python
TIME_RANGES = {
    'last_7_days': '最近 7 天',  # NEW - default for FIND-02
    'this_week': '本周',
    'last_week': '上周',
    'this_month': '本月',
    'this_quarter': '本季度',
    'this_year': '本年',
}
```

2. **Update get_range() method** (utils.py):
```python
@staticmethod
def get_range(time_range):
    time_range_methods = {
        'last_7_days': lambda: DateRange.last_n_days(7),  # NEW
        'this_week': DateRange.this_week,
        # ... rest unchanged
    }
```

3. **Update template selection logic** (manage_records.html):
```html
<!-- User dropdown: default to current user if no param -->
{% set user_selected = request.args.get('user', current_user.username) %}
<option value="">不限</option>
{% for value, label in record_form.user.choices %}
<option value="{{ value }}" {% if user_selected == value %}selected{% endif %}>{{ label }}</option>
{% endfor %}

<!-- Time range dropdown: default to last_7_days if no param -->
{% set time_selected = request.args.get('time_range', 'last_7_days') %}
<option value="">不限</option>
{% for value, label in record_form.time_range.choices %}
<option value="{{ value }}" {% if time_selected == value %}selected{% endif %}>{{ label }}</option>
{% endfor %}
```

### Anti-Patterns to Avoid

- **Do NOT change the "不限" option logic** - users must still be able to clear filters
- **Do NOT modify build_record_query** - current query logic is correct
- **Do NOT set form defaults in Python** - Jinja2 template approach is cleaner and preserves "clear filter" functionality

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Date range calculation | Custom timedelta logic | DateRange.last_n_days(7) | Already exists, tested |
| Form field rendering | Custom HTML | Jinja2 conditionals with request.args.get() | Standard Flask pattern |

## Common Pitfalls

### Pitfall 1: Breaking "Clear Filter" Functionality
**What goes wrong:** If defaults are set in Python code (form.default), users cannot clear the filter to see all records.
**Why it happens:** Form defaults apply on every render, overriding user's intent to clear.
**How to avoid:** Use template-level defaults via `request.args.get('param', default_value)` which only applies when URL param is absent.
**Warning signs:** User clicks "不限" but filter still applies.

### Pitfall 2: Inconsistent Default Between Initial Load and Filter Submit
**What goes wrong:** Initial page load shows filtered results, but form submission with empty fields shows all records.
**Why it happens:** Default only applied in template, not in query building.
**How to avoid:** The query builder already handles this correctly - empty params return allowed records. Template defaults ensure the UI reflects the actual query parameters.

### Pitfall 3: Time Range Not in TIME_RANGES Dictionary
**What goes wrong:** Adding 'last_7_days' to get_range() but not to TIME_RANGES means it won't appear in dropdown.
**Why it happens:** Form choices are populated from TIME_RANGES.items().
**How to avoid:** Add to both TIME_RANGES dict and get_range() method.

## Code Examples

### Pattern: Default Selection in Jinja2 Template

```html
<!-- Standard pattern for dropdown with default -->
<select name="filter_field" class="form-select">
    <option value="">All</option>
    {% for value, label in choices %}
    {% set selected_val = request.args.get('filter_field', 'default_value') %}
    <option value="{{ value }}" {% if selected_val == value %}selected{% endif %}>{{ label }}</option>
    {% endfor %}
</select>
```

### Pattern: Adding Time Range to DateRange Class

```python
# utils.py - Add to TIME_RANGES dict
TIME_RANGES = {
    'last_7_days': '最近 7 天',  # Added for FIND-02
    'this_week': '本周',
    # ...
}

# utils.py - Add to get_range() method
@staticmethod
def get_range(time_range):
    time_range_methods = {
        'last_7_days': lambda: DateRange.last_n_days(7),  # Added
        'this_week': DateRange.this_week,
        # ...
    }
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| N/A (new feature) | Template-level defaults via request.args.get() | This phase | Cleaner separation of concerns |

## Open Questions

1. **Should the "最近 7 天" option appear first in the dropdown?**
   - What we know: TIME_RANGES dict order determines dropdown order
   - Recommendation: Yes, place 'last_7_days' first in TIME_RANGES since it's the default

## Environment Availability

> Step 2.6: SKIPPED (no external dependencies identified - code/config-only changes)

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | pytest 8.3.5 |
| Config file | pytest.ini |
| Quick run command | `pytest tests/test_routes.py -x -v` |
| Full suite command | `pytest --tb=short` |

### Phase Requirements -> Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| FIND-01 | User dropdown defaults to current user | integration | `pytest tests/test_routes.py::TestRecordCRUD::test_manage_records_default_user_filter -x` | Wave 0 (new test needed) |
| FIND-02 | Time range defaults to last 7 days | integration | `pytest tests/test_routes.py::TestRecordCRUD::test_manage_records_default_time_filter -x` | Wave 0 (new test needed) |
| FIND-03 | Existing filters work unchanged | integration | `pytest tests/test_routes.py::TestRecordCRUD -x` | Existing tests |

### Sampling Rate
- **Per task commit:** `pytest tests/test_routes.py -x`
- **Per wave merge:** `pytest --tb=short`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `tests/test_routes.py` - add `test_manage_records_default_user_filter` test
- [ ] `tests/test_routes.py` - add `test_manage_records_default_time_filter` test
- [ ] `tests/test_utils.py` - add `test_last_7_days_in_time_ranges` test (verify new option exists)

## Sources

### Primary (HIGH confidence)
- Code analysis: `routes.py`, `forms.py`, `utils.py`, `templates/manage_records.html`
- Existing test patterns: `tests/test_routes.py`, `tests/conftest.py`

### Secondary (MEDIUM confidence)
- N/A - All findings from direct code inspection

### Tertiary (LOW confidence)
- N/A

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - Direct code inspection, existing patterns
- Architecture: HIGH - Code fully understood, clear implementation path
- Pitfalls: HIGH - Based on understanding of Flask/Jinja2 patterns

**Research date:** 2026-03-25
**Valid until:** 30 days (stable Flask patterns)