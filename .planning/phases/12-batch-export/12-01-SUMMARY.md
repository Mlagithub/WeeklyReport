---
phase: 12-batch-export
plan: 01
subsystem: routes, exporters
tags: [batch-export, zip, team-leader, permission]
dependencies:
  requires: [12-00]
  provides: [batch_export route, exporters/batch.py]
  affects: [routes.py]
tech-stack:
  added: [zipfile.ZipFile]
  patterns: [in-memory ZIP generation, ExporterFactory reuse]
key-files:
  created: [exporters/batch.py]
  modified: [routes.py]
decisions:
  - Use create_batch_zip helper function for testability
  - Sort records by date string (strftime) to handle mock objects in tests
  - Reuse ExporterFactory for individual report generation
metrics:
  duration: 5min
  tasks: 1
  files: 2
---

# Phase 12 Plan 01: Batch Export Route Summary

## One-liner

Added batch_export route with ZIP generation using existing ExporterFactory, enabling team leaders to export all group reports in a single download.

## Changes Made

### Files Created

1. **exporters/batch.py** - New module with batch export utilities
   - `group_records_by_user(records)` - Groups records by username
   - `create_batch_zip(records_by_user, format)` - Creates ZIP with individual reports

### Files Modified

1. **routes.py**
   - Added `from zipfile import ZipFile` import
   - Added `batch_export()` route at line 351
   - Permission check for view_group/view_all
   - Uses User.managed_group() to get allowed users
   - Returns ZIP file via send_file()

## Test Results

All 4 TestBatchExport tests pass:
- `test_create_zip_with_files` - ZIP creation in memory works
- `test_batch_export_returns_bytesio` - Returns BytesIO with 'PK' magic bytes
- `test_batch_export_filename_format` - Filename follows {username}_{date_range}.{ext}
- `test_batch_export_groups_by_user` - Records grouped correctly by username

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed sorting mock objects in tests**
- **Found during:** Running tests
- **Issue:** Test used MagicMock for records where record.date couldn't be compared with `<`
- **Fix:** Changed `sorted(user_records, key=lambda r: r.date)` to `sorted(user_records, key=lambda r: r.date.strftime('%Y%m%d'))`
- **Files modified:** exporters/batch.py
- **Commit:** d22f815

None other - plan executed exactly as written.

## Key Implementation Details

### Route Flow

1. Permission check (view_group or view_all required)
2. Get managed groups and extract usernames
3. Build query filtering by usernames and time range
4. Group records by user
5. Create ZIP with individual reports
6. Return ZIP file with timestamped filename

### Filename Format

Individual files in ZIP: `{username}_{YYYYMMDD-YYYYMMDD}.{ext}`

Example: `zhangsan_20260320-20260326.pdf`

### ZIP Filename

`group_reports_{YYYYMMDD_HHMMSS}.zip`

## Known Stubs

None - implementation is complete.

## Self-Check: PASSED

- [x] exporters/batch.py exists
- [x] routes.py contains batch_export route
- [x] Commit d22f815 exists
- [x] All 4 TestBatchExport tests pass