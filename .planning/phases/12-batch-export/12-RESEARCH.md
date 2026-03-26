# Phase 12: Batch Export - Research

**Researched:** 2026-03-26
**Domain:** Python zipfile, Flask route design, permission-based data access
**Confidence:** HIGH

## Summary

Phase 12 implements batch export functionality allowing team leaders to export all group members' weekly reports as a ZIP file. The implementation leverages the existing ExporterFactory pattern (Phases 8-11) without duplication. The key technical approach is:

1. Create a new route `batch_export` that queries records for all group members
2. Use Python's built-in `zipfile` module with `BytesIO` for in-memory ZIP creation
3. Reuse existing exporters (PDF, DOCX, Excel) via ExporterFactory for each individual report
4. Add a batch export button on `manage_records.html` visible only to users with `view_group` permission

**Primary recommendation:** Reuse ExporterFactory for individual files; create ZIP in-memory using zipfile + BytesIO; permission check via `view_group` permission.

## User Constraints (from CONTEXT.md)

No CONTEXT.md exists for this phase. Research is unconstrained.

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| BATCH-01 | Team leaders can batch export all group reports as ZIP | ExporterFactory reuse, zipfile module, permission model documented below |

## Standard Stack

### Core (Existing - Reuse)
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| zipfile | stdlib | ZIP archive creation | Python standard library, no dependencies |
| BytesIO | stdlib | In-memory binary streams | Standard pattern for Flask file responses |
| ExporterFactory | existing | Get format-specific exporters | Already implemented in Phase 8 |

### Supporting (Existing - Reuse)
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| PdfExporter | existing | PDF generation | When format='pdf' |
| DocxExporter | existing | DOCX generation | When format='docx' |
| ExcelExporter | existing | XLSX generation | When format='xlsx' |
| send_file | Flask | File download response | Return ZIP to client |

**No new dependencies required** - all functionality uses existing code and Python standard library.

## Architecture Patterns

### Recommended Implementation Pattern

```python
# New route in routes.py
@app.route('/batch_export', methods=['POST'])
@login_required
def batch_export():
    # 1. Permission check - only team leaders
    permissions = User.all_permissions(current_user)
    if 'view_group' not in permissions and 'view_all' not in permissions:
        abort(403)

    # 2. Get format and time range from form
    format = request.form.get('format', 'pdf')
    time_range = request.form.get('time_range', 'this_week')

    # 3. Get all group members' records
    groups = User.managed_group(current_user)
    # Build query for all group members within time range
    # ... (use existing build_record_query pattern)

    # 4. Group records by user for individual files
    # 5. Export each user's records using ExporterFactory
    # 6. Add to ZIP archive
    # 7. Return ZIP via send_file
```

### ZIP File Creation Pattern

```python
from zipfile import ZipFile
from io import BytesIO

def create_batch_zip(records_by_user: dict, format: str) -> BytesIO:
    """Create ZIP containing individual reports per user.

    Args:
        records_by_user: Dict mapping username to list of Record objects
        format: Export format ('pdf', 'docx', 'xlsx')

    Returns:
        BytesIO buffer containing ZIP file
    """
    zip_buffer = BytesIO()

    with ZipFile(zip_buffer, 'w') as zf:
        exporter = ExporterFactory.get_exporter(format)

        for username, records in records_by_user.items():
            # Generate individual report
            report_buffer = exporter.export(records, title=f'{username} Weekly Report')

            # Create filename with username and date range
            date_str = records[0].date.strftime('%Y%m%d') if records else 'nodate'
            filename = f'{username}_{date_str}.{exporter.file_extension}'

            # Add to ZIP
            zf.writestr(filename, report_buffer.getvalue())

    zip_buffer.seek(0)
    return zip_buffer
```

### File Naming Convention

**Pattern:** `{username}_{start_date}-{end_date}.{ext}`

**Examples:**
- `zhangsan_20260320-20260326.pdf`
- `lisi_20260320-20260326.docx`
- `wangwu_20260320-20260326.xlsx`

**Rationale:** Clear identification of user and date range; no special characters that could cause filesystem issues.

### UI Placement

Add batch export button in `manage_records.html` after the existing download form:

```html
{% if not hide_groups %}
<!-- Batch export for team leaders -->
<div class="col-12 mt-3">
    <form action="{{ url_for('batch_export') }}" method="post" class="d-inline-block">
        <input type="hidden" name="time_range" value="">
        <select name="format" class="form-select form-select-sm d-inline-block w-auto">
            <option value="pdf">PDF (ZIP)</option>
            <option value="docx">Word (ZIP)</option>
            <option value="xlsx">Excel (ZIP)</option>
        </select>
        <button type="submit" class="btn btn-primary">
            批量导出全组周报
        </button>
    </form>
</div>
{% endif %}
```

**Location:** After line 156 in `manage_records.html`, inside the same row div as the existing download form.

**Visibility:** Only shown when `hide_groups` is False (i.e., user has `view_group` permission).

### Permission Model

| Permission | Can Batch Export? | Scope |
|------------|-------------------|-------|
| `view_all` | Yes | All groups |
| `view_group` | Yes | Managed groups only |
| Neither | No | 403 Forbidden |

**Implementation:** Reuse existing `User.managed_group()` and `User.all_permissions()` methods.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| ZIP creation | Custom archive logic | `zipfile.ZipFile` | Standard library, handles edge cases |
| Report generation | New exporter code | `ExporterFactory.get_exporter()` | Already tested, DRY |
| Permission check | Custom permission logic | `User.all_permissions()` | Consistent with existing code |
| File streaming | Custom response | `send_file()` | Handles MIME types, headers |

**Key insight:** This phase is primarily orchestration of existing components, not new functionality.

## Common Pitfalls

### Pitfall 1: Memory Issues with Large Batches
**What goes wrong:** ZIP file in memory consumes excessive RAM with many users/reports.
**Why it happens:** Each report is fully generated before being added to ZIP.
**How to avoid:** Current scale (10-50 users) is acceptable. If scale grows, consider streaming ZIP or background task queue.
**Warning signs:** Memory errors, slow response times, timeouts.

### Pitfall 2: Filename Encoding Issues
**What goes wrong:** Chinese characters in usernames cause ZIP extraction errors on some systems.
**Why it happens:** ZIP format has inconsistent Unicode support across implementations.
**How to avoid:** Use ASCII-safe filenames (Pinyin or user IDs) or set `flag_bits` for UTF-8 encoding.
**Warning signs:** Extracted files with garbled names on Windows.

### Pitfall 3: Empty ZIP for No Records
**What goes wrong:** ZIP contains no files when no records match the time range.
**Why it happens:** Query returns empty results.
**How to avoid:** Check if any records exist before creating ZIP; show flash message if none.
**Warning signs:** User downloads empty ZIP file.

### Pitfall 4: Permission Bypass via Form Manipulation
**What goes wrong:** User modifies form to export records they shouldn't see.
**Why it happens:** Trusting client-side data without server validation.
**How to avoid:** Always verify permissions server-side using `User.managed_group()` for query filtering.
**Warning signs:** Logs showing unexpected data access.

### Pitfall 5: Time Range Mismatch Between Records
**What goes wrong:** Some users have records outside the selected time range but are included.
**Why it happens:** Query not properly filtering by date.
**How to avoid:** Reuse `build_record_query()` pattern which handles time range filtering correctly.
**Warning signs:** Unexpected records in ZIP.

## Code Examples

### Complete Batch Export Route

```python
@app.route('/batch_export', methods=['POST'])
@login_required
def batch_export():
    """Export all group members' reports as a ZIP file."""
    # Permission check
    permissions = User.all_permissions(current_user)
    if 'view_group' not in permissions and 'view_all' not in permissions:
        abort(403)

    # Get parameters
    format = request.form.get('format', 'pdf')
    time_range = request.form.get('time_range', 'this_week')

    # Get allowed groups and build user list
    groups = User.managed_group(current_user)
    allowed_usernames = set()
    for group in groups:
        for user in group.users:
            allowed_usernames.add(user.username)

    if not allowed_usernames:
        flash('没有可导出的组成员', 'warning')
        return redirect(url_for('manage_records'))

    # Build query with time range
    from utils import DateRange
    start_date, end_date = DateRange.get_range(time_range) if time_range else (None, None)

    query = Record.query.join(user_records).join(User).filter(
        User.username.in_(allowed_usernames)
    )
    if start_date and end_date:
        query = query.filter(Record.date >= start_date, Record.date <= end_date)

    records = query.order_by(Record.date.desc()).all()

    if not records:
        flash('所选时间范围内没有周报记录', 'warning')
        return redirect(url_for('manage_records'))

    # Group records by user
    records_by_user = {}
    for record in records:
        for user in record.user:
            if user.username not in records_by_user:
                records_by_user[user.username] = []
            records_by_user[user.username].append(record)

    # Create ZIP
    from zipfile import ZipFile
    from exporters import ExporterFactory

    zip_buffer = BytesIO()
    exporter = ExporterFactory.get_exporter(format)

    with ZipFile(zip_buffer, 'w') as zf:
        for username, user_records in records_by_user.items():
            report_buffer = exporter.export(user_records, title=f'{username} 周报')

            # Create filename
            date_range_str = f"{user_records[0].date.strftime('%Y%m%d')}-{user_records[-1].date.strftime('%Y%m%d')}"
            filename = f'{username}_{date_range_str}.{exporter.file_extension}'

            zf.writestr(filename, report_buffer.getvalue())

    zip_buffer.seek(0)

    # Generate ZIP filename
    date_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    zip_filename = f'group_reports_{date_str}.zip'

    return send_file(
        zip_buffer,
        mimetype='application/zip',
        as_attachment=True,
        download_name=zip_filename
    )
```

### Form for Batch Export

Add to `forms.py`:

```python
class BatchExportForm(FlaskForm):
    """Form for batch exporting group reports."""
    format = SelectField("格式", choices=[
        ('pdf', 'PDF'),
        ('docx', 'Word'),
        ('xlsx', 'Excel'),
    ], default='pdf')
    time_range = SelectField("时间范围", choices=[(key, value) for key, value in DateRange.TIME_RANGES.items()])
    submit = SubmitField("批量导出")
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Custom export code per format | ExporterFactory pattern | Phase 8 (v1.2) | DRY, testable, extensible |
| Individual file downloads only | Batch ZIP export | This phase | Team efficiency |

**Deprecated/outdated:**
- Direct WeasyPrint/openpyxl usage in routes → Use ExporterFactory instead

## Open Questions

1. **Filename encoding for Chinese usernames**
   - What we know: ZIP format has inconsistent Unicode support
   - What's unclear: Best approach for Chinese filenames (Pinyin vs UTF-8 flag)
   - Recommendation: Start with UTF-8 encoding; if issues reported, add Pinyin fallback

2. **Progress indication for large batches**
   - What we know: Current scale (10-50 users) completes in seconds
   - What's unclear: At what scale is progress feedback needed
   - Recommendation: Defer until scale increases; current synchronous approach is sufficient

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Python zipfile | ZIP creation | Yes (stdlib) | 3.x | N/A |
| BytesIO | In-memory streams | Yes (stdlib) | 3.x | N/A |
| Flask send_file | File response | Yes | 3.0.3 | N/A |
| ExporterFactory | Report generation | Yes | existing | N/A |

**Missing dependencies with no fallback:** None

**Missing dependencies with fallback:** None

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | pytest 8.3.5 |
| Config file | None (conftest.py fixtures) |
| Quick run command | `pytest tests/test_routes.py -x -v` |
| Full suite command | `pytest tests/ -v --cov=.` |

### Phase Requirements -> Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| BATCH-01 | Team leaders can batch export group reports as ZIP | integration | `pytest tests/test_routes.py::TestBatchExport -x -v` | No - Wave 0 |

### Sampling Rate
- **Per task commit:** `pytest tests/test_routes.py -x -v`
- **Per wave merge:** `pytest tests/ -v --cov=.`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `tests/test_routes.py::TestBatchExport` - covers BATCH-01
- [ ] Test fixtures: `group_leader` user with `view_group` permission
- [ ] Test: batch_export returns ZIP file
- [ ] Test: ZIP contains expected files with correct naming
- [ ] Test: non-leader users get 403 Forbidden
- [ ] Test: empty result shows flash message

## Sources

### Primary (HIGH confidence)
- Python stdlib documentation - zipfile module
- Existing codebase: `exporters/__init__.py`, `exporters/base.py`, `routes.py`, `models.py`
- Flask documentation - send_file function

### Secondary (MEDIUM confidence)
- Existing test patterns in `tests/test_exporters.py`
- Existing permission patterns in `models.py`

### Tertiary (LOW confidence)
- None - all findings verified from codebase

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - zipfile is stdlib, exporters already implemented
- Architecture: HIGH - follows existing patterns exactly
- Pitfalls: MEDIUM - some edge cases (Chinese filenames) may need real-world testing

**Research date:** 2026-03-26
**Valid until:** 90 days (stable patterns, stdlib components)