---
phase: 10
plan: 01
subsystem: exporters
tags: [docx, export, python-docx, htmldocx, image-embedding]
requires: [08-export-foundation]
provides: [DocxExporter, DOCX export functionality]
affects: [exporters/__init__.py, exporters/docx.py, tests/test_exporters.py]
tech-stack:
  added: [python-docx, htmldocx, beautifulsoup4]
  patterns: [template-method, factory, html-parsing]
key-files:
  created: [exporters/docx.py]
  modified: [exporters/__init__.py, tests/test_exporters.py]
decisions:
  - Use htmldocx for HTML-to-DOCX conversion (standard library for this purpose)
  - Custom image handling required (htmldocx doesn't support images)
  - Placeholder-based image replacement for embedding
metrics:
  duration: ~10 minutes
  tasks_completed: 4
  tests_passed: 27
  completed_date: 2026-03-26
---

# Phase 10 Plan 01: DocxExporter Implementation Summary

## One-liner

Created DocxExporter class extending ExporterBase with HTML-to-DOCX conversion via htmldocx and custom image embedding using BeautifulSoup and python-docx.

## What Was Done

### Task 1: Create DocxExporter class structure
- Created `exporters/docx.py` with DocxExporter class extending ExporterBase
- Implemented `__init__`, `uploads_path`, `image_resolver` properties (following PdfExporter pattern)
- Implemented `file_extension` returning 'docx'
- Implemented `mime_type` returning 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
- Implemented `_generate()` method with basic document structure

### Task 2: Implement HTML-to-DOCX conversion with formatting
- Used htmldocx HtmlToDocx for HTML conversion
- Implemented `_convert_html_to_document` method
- Added Chinese font support via `_apply_chinese_font` method (Microsoft YaHei)
- Supports headings, lists, tables, links, and code blocks through htmldocx

### Task 3: Implement image embedding
- CRITICAL: htmldocx does NOT support images - implemented custom handling
- Implemented `_extract_images()` using BeautifulSoup to parse HTML and replace img tags with placeholders
- Implemented `_embed_images()` to find placeholders and replace with actual images
- Implemented `_replace_paragraph_with_image()` for proper image insertion at placeholder location
- Used ImageResolver.get_image_bytes() for image data retrieval
- Fixed test issues with invalid PNG headers (changed to use PIL for valid test images)

### Task 4: Register DocxExporter in ExporterFactory
- Updated `exporters/__init__.py` to import and register DocxExporter
- Factory now supports 'pdf' and 'docx' formats

## Key Implementation Details

### Image Embedding Flow

1. `_extract_images(html)`: Parse HTML with BeautifulSoup, find all `<img>` tags, replace with `[[IMAGE_PLACEHOLDER_N]]` placeholders, return (processed_html, images_list)
2. `_convert_html_to_document(doc, html)`: Convert processed HTML (without images) using htmldocx
3. `_embed_images(doc, images)`: For each placeholder, find the paragraph containing it and replace with actual image
4. `_replace_paragraph_with_image(paragraph, image_bytes)`: Clear paragraph runs, add new run with embedded picture

### Chinese Font Support

Applied Microsoft YaHei font to all runs in the document, including East Asian font settings via `w:eastAsia` XML attribute.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Critical Functionality] Fixed test PNG images**
- **Found during:** Task 3 (image embedding test)
- **Issue:** Test used minimal PNG headers that weren't valid images, causing python-docx to fail embedding
- **Fix:** Updated tests to use PIL for creating valid 1x1 pixel PNG images
- **Files modified:** tests/test_exporters.py
- **Commit:** 8b4dc83

**2. [Rule 3 - Blocking Issue] Fixed test_extract_images_helper return value expectation**
- **Found during:** Task 3
- **Issue:** Test expected `_extract_images` to return a list, but implementation returns tuple (html, images)
- **Fix:** Updated test to expect tuple return and properly destructure
- **Files modified:** tests/test_exporters.py
- **Commit:** 8b4dc83

## Test Results

All 27 tests pass:
- TestExporterBase: 4 tests
- TestExporterFactory: 4 tests
- TestImageResolver: 4 tests
- TestDependencies: 3 tests
- TestPdfExporter: 5 tests
- TestDocxExporter: 7 tests

## Known Stubs

None - all functionality is complete and tested.

## Next Steps

Phase 10 Plan 02: Route and form integration
- Add DOCX format option to export forms
- Integrate DocxExporter with download route
- UI updates for format selection

## Self-Check: PASSED

- exporters/docx.py: FOUND
- 10-01-SUMMARY.md: FOUND
- Commit 60bd61c: FOUND
- Commit 8b4dc83: FOUND
- Commit b7d727f: FOUND