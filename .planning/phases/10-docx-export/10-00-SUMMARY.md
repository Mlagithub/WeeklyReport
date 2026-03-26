---
phase: 10-docx-export
plan: 00
subsystem: exporters
tags: [tdd, test-scaffolding, docx]
dependencies:
  requires: [08-export-foundation, 09-pdf-export]
  provides: [TestDocxExporter test suite]
  affects: [tests/test_exporters.py]
tech-stack:
  added: []
  patterns: [TDD test-first, pytest fixtures, MagicMock]
key-files:
  created: []
  modified:
    - path: tests/test_exporters.py
      changes: Added TestDocxExporter class with 7 failing tests
decisions: []
metrics:
  duration: 3 minutes
  completed_date: 2026-03-26
  task_count: 1
  file_count: 1
---

# Phase 10 Plan 00: DOCX Test Scaffolding Summary

## One-liner

TDD test scaffolding with 7 failing tests defining expected DocxExporter behavior including image embedding helpers.

## Summary

Created test scaffolding for DocxExporter class following test-driven development principles. The tests define the expected interface and behavior for DOCX export functionality that will be implemented in Plan 01.

**Tests added:**

| Test | Purpose | Expected Behavior |
|------|---------|-------------------|
| `test_file_extension` | Property validation | Returns 'docx' |
| `test_mime_type` | MIME type validation | Returns correct DOCX MIME type |
| `test_export_returns_bytesio` | Output validation | Returns BytesIO with PK magic bytes |
| `test_html_to_docx_conversion` | HTML conversion | Converts p, strong, em, ul, ol, table, h1-h3, a, pre/code |
| `test_image_embedding` | Image handling | Embeds images from /files/ URLs |
| `test_extract_images_helper` | Helper method | Extracts img tags from HTML |
| `test_add_image_to_document_helper` | Helper method | Embeds image bytes into document |

**TDD RED phase:** All 7 tests fail with `ModuleNotFoundError: No module named 'exporters.docx'` as expected, since DocxExporter implementation is in Plan 01.

## Key Decisions

1. **Extended test count (7 instead of 5):** Added dedicated tests for `_extract_images()` and `_add_image_to_document()` helper methods to validate image handling independently.

2. **Image embedding approach:** Tests expect custom image handling methods since htmldocx does not support images natively (per research findings).

## Deviations from Plan

### Plan Adjustments

**1. [Extended Coverage] Added 2 additional tests beyond plan's 5**
- **Found during:** Task 1 implementation
- **Rationale:** Plan mentioned helper methods `_extract_images()` and `_add_image_to_document()` but didn't explicitly list them as separate tests. Added dedicated tests for comprehensive coverage.
- **Impact:** More thorough testing of image handling, which is identified as a critical complexity area in research.
- **Commit:** eb0a063

## Verification Results

```
pytest tests/test_exporters.py::TestDocxExporter -v
============================= test session starts ==============================
platform linux -- Python 3.10.12, pytest-8.3.5
collected 7 items

tests/test_exporters.py::TestDocxExporter::test_file_extension FAILED
tests/test_exporters.py::TestDocxExporter::test_mime_type FAILED
tests/test_exporters.py::TestDocxExporter::test_export_returns_bytesio FAILED
tests/test_exporters.py::TestDocxExporter::test_html_to_docx_conversion FAILED
tests/test_exporters.py::TestDocxExporter::test_image_embedding FAILED
tests/test_exporters.py::TestDocxExporter::test_extract_images_helper FAILED
tests/test_exporters.py::TestDocxExporter::test_add_image_to_document_helper FAILED

============================== 7 failed in 0.20s ===============================
```

All tests fail with `ModuleNotFoundError: No module named 'exporters.docx'` - correct TDD RED behavior.

## Files Modified

| File | Changes |
|------|---------|
| `tests/test_exporters.py` | Added TestDocxExporter class with 7 test methods (+194 lines) |

## Next Steps

Plan 01 will implement `exporters/docx.py` with:
- DocxExporter class inheriting from ExporterBase
- `_generate()` method using python-docx + htmldocx
- `_extract_images()` and `_add_image_to_document()` helpers for image embedding
- Integration with ImageResolver for /files/ URL resolution

## Self-Check: PASSED

- [x] TestDocxExporter class exists in tests/test_exporters.py
- [x] 7 test methods with clear docstrings
- [x] pytest discovers and runs all tests
- [x] Tests fail as expected (implementation not yet created)
- [x] Commit eb0a063 exists in git log