---
phase: 12-batch-export
plan: 02
subsystem: ui
tags: [batch-export, template, button, permission-based-visibility]
requires: [12-01]
provides: [batch-export-ui]
affects: [manage_records.html]
tech-stack:
  added: []
  patterns: [jinja2-conditional, url_for-routing, bootstrap-form]
key-files:
  created: []
  modified:
    - path: templates/manage_records.html
      change: Added batch export button with conditional visibility
decisions: []
metrics:
  duration: 2m
  completed: 2026-03-26
  tasks: 1
  files: 1
---

# Phase 12 Plan 02: Batch Export Button UI Summary

## One-liner
Added batch export button to manage_records.html, visible only to team leaders with view_group permission.

## What Was Done

### Task 1: Add batch export button to manage_records.html
- Added batch export form after the existing download form (line 156-170)
- Wrapped in `{% if not hide_groups %}` conditional for team leader visibility
- Format selector with PDF (ZIP), Word (ZIP), Excel (ZIP) options
- Uses `archive` icon for visual distinction from single download button
- JavaScript populates time_range from URL params for consistent filtering
- Clear Chinese label: "批量导出全组周报" (Batch export all group reports)

## Implementation Details

**Location:** templates/manage_records.html, after existing download form

**Key elements:**
- Form posts to `batch_export` route (exists from plan 12-01)
- Hidden time_range field populated via JavaScript
- Format selector with ZIP-indicated options
- Conditional visibility based on `hide_groups` variable

**JavaScript integration:**
```javascript
const batchForm = document.getElementById('batchExportForm');
if (batchForm) {
    batchForm.querySelector('input[name="time_range"]').value = urlParams.get('time_range') || 'this_week';
}
```

## Verification

- `grep -c "batch_export" templates/manage_records.html` = 1 (url_for reference)
- `grep -c "批量导出" templates/manage_records.html` = 1 (button label)
- Form wrapped in `{% if not hide_groups %}` block
- `batchExportForm` id present for JavaScript access

## Acceptance Criteria Met

- [x] File contains `url_for('batch_export')`
- [x] File contains "批量导出全组周报"
- [x] File contains `{% if not hide_groups %}` wrapping the batch export section
- [x] File contains `batchExportForm` id
- [x] Format options show "(ZIP)" suffix
- [x] JavaScript populates time_range from URL params

## Deviations from Plan

None - plan executed exactly as written.

## Files Modified

| File | Change |
|------|--------|
| templates/manage_records.html | Added batch export form with conditional visibility (18 lines) |

## Commit

- 0e9ca5c: feat(12-02): add batch export button to UI

## Self-Check: PASSED

- [x] templates/manage_records.html modified and committed
- [x] Commit hash 0e9ca5c exists in git log