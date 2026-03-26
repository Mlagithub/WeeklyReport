# Pitfalls Research

**Domain:** HTML to DOCX/PDF Conversion for Rich Text Export
**Researched:** 2026-03-26
**Confidence:** MEDIUM (based on official documentation and GitHub issues; some areas lack real-world implementation data)

## Critical Pitfalls

### Pitfall 1: Image Path Resolution Failure

**What goes wrong:**
Images uploaded via CKEditor are stored as `/uploaded_files/filename.ext` but the export libraries cannot resolve these relative URLs. DOCX and PDF exports produce broken image placeholders or missing images entirely.

**Why it happens:**
- CKEditor stores image URLs as web paths (`/static/uploads/...` or `/uploaded_files/...`)
- `python-docx.add_picture()` requires absolute file paths or file-like objects, not URLs
- WeasyPrint requires correct `base_url` parameter to resolve relative paths
- Developers often pass the web path directly without conversion

**How to avoid:**
1. Create a utility function to convert web URLs to filesystem paths:
   ```python
   def url_to_filepath(url):
       # /uploaded_files/abc.jpg -> /home/one/weekly/static/uploads/abc.jpg
       filename = url.split('/')[-1]
       return os.path.join(app.config['UPLOAD_FOLDER'], filename)
   ```
2. For WeasyPrint, always pass `base_url` pointing to static directory
3. Validate image exists before adding to document

**Warning signs:**
- Exported documents show "Image not found" placeholders
- Logs show `FileNotFoundError` when adding pictures
- PDF exports succeed but images appear blank

**Phase to address:**
Phase implementing DOCX/PDF export (EXPORT-01, EXPORT-02)

---

### Pitfall 2: HTML-to-DOCX Conversion Data Loss

**What goes wrong:**
CKEditor produces complex HTML with nested elements, tables, lists, and inline styles. Direct conversion to DOCX loses formatting, breaks tables, or omits content.

**Why it happens:**
- `htmldocx` library has limited HTML element support
- Tables lack default styling (must set `table_style`)
- Code blocks (`<pre>`, `<code>`) are not handled specially
- Nested lists may lose indentation
- Complex table structures (merged cells) cause parsing errors

**How to avoid:**
1. Pre-process HTML to normalize structure before conversion
2. Set table style explicitly: `parser.table_style = 'TableGrid'`
3. Create custom handlers for unsupported elements (code blocks, special formatting)
4. Test with representative CKEditor output to identify gaps
5. Consider hybrid approach: use htmldocx for basic elements, custom code for complex structures

**Warning signs:**
- Exported DOCX has broken table layouts
- Code blocks lose monospace formatting
- List indentation is flat instead of hierarchical
- Bold/italic formatting disappears

**Phase to address:**
Phase implementing DOCX export (EXPORT-01)

---

### Pitfall 3: WeasyPrint CSS Compatibility Issues

**What goes wrong:**
PDF exports don't match the HTML preview - layouts break, styling is lost, or content overflows incorrectly.

**Why it happens:**
WeasyPrint has known CSS limitations:
- **No 3D transforms** - only 2D supported
- **No `box-shadow`** - shadows ignored entirely
- **Limited Grid/Flexbox** - works for simple cases only
- **No `calc()`, `vw`, `vh`** - viewport units unsupported
- **No `text-shadow`** - text effects lost
- **`:hover`, `:active`, `:focus`** - accepted but never match (static PDF)
- **RTL support incomplete** - bidirectional text issues

**How to avoid:**
1. Use WeasyPrint-compatible CSS subset for print styles
2. Create separate print stylesheet without unsupported properties
3. Test with WeasyPrint early, don't rely on browser preview
4. Use `@page` rules for pagination control
5. Avoid complex flexbox/grid layouts in export HTML

**Warning signs:**
- Content overlaps in PDF
- Page breaks split content awkwardly
- Font sizes differ from browser preview
- Layout completely broken in PDF

**Phase to address:**
Phase implementing PDF export (EXPORT-02)

---

### Pitfall 4: Memory Leak in Batch Document Generation

**What goes wrong:**
Batch export for team leads causes server memory to grow until OOM or severe slowdown. System becomes unresponsive after processing many documents.

**Why it happens:**
- `BytesIO` objects not properly closed after use
- `python-docx` Document objects hold references
- Open file handles accumulate
- Python garbage collection may not run during tight loops
- Large images loaded into memory for each document

**How to avoid:**
1. Always close BytesIO streams after Flask `send_file()`:
   ```python
   output = BytesIO()
   doc.save(output)
   output.seek(0)
   response = send_file(output, ...)
   # Flask closes the stream, but for batch:
   # Process one at a time, not all in memory
   ```
2. For batch export, stream to zip incrementally, not accumulate in memory:
   ```python
   with zipfile.ZipFile(zip_buffer, 'w') as zf:
       for record in records:
           doc = create_docx(record)
           zf.writestr(f"{record.name}.docx", doc.getvalue())
           doc.close()  # Explicit cleanup
   ```
3. Consider generator-based streaming for large batches
4. Limit batch size (e.g., max 50 records per request)

**Warning signs:**
- Memory usage grows linearly during batch exports
- Server becomes sluggish after batch operations
- Timeout errors on large team exports

**Phase to address:**
Phase implementing batch export (EXPORT-04)

---

### Pitfall 5: Zero-DPI Image Crash

**What goes wrong:**
Export fails with "division by zero" error when processing certain images.

**Why it happens:**
Some uploaded images have missing or zero DPI metadata. `python-docx` attempts to calculate dimensions based on DPI, causing division by zero.

**How to avoid:**
1. Validate image DPI before adding to document
2. Set explicit width/height when adding pictures:
   ```python
   from docx.shared import Inches
   doc.add_picture(path, width=Inches(4))  # Explicit size bypasses DPI
   ```
3. Normalize images on upload using Pillow to ensure valid metadata

**Warning signs:**
- `ZeroDivisionError` in export logs
- Exports fail inconsistently (depends on which images included)
- Error trace shows `add_picture()` call

**Phase to address:**
Phase implementing DOCX export with images (EXPORT-01, EXPORT-05)

---

## Technical Debt Patterns

| Shortcut | Immediate Benefit | Long-term Cost | When Acceptable |
|----------|-------------------|----------------|-----------------|
| Strip all HTML formatting for exports | Simpler code, no conversion issues | Users lose rich text value - defeats feature purpose | Never - defeats the milestone goal |
| Use browser print for PDF | No library needed | Inconsistent output, requires user action, can't batch | MVP demo only |
| Export images as separate files | Simpler implementation | Broken offline viewing, confusing for users | Never - violates EXPORT-05 |
| Skip batch export optimization | Faster initial implementation | OOM on production, limits team size | Only if team size < 10 |
| Ignore CKEditor HTML quirks | Faster conversion | Data loss in exports, user complaints | Never |

## Integration Gotchas

| Integration | Common Mistake | Correct Approach |
|-------------|----------------|------------------|
| CKEditor HTML | Assume clean semantic HTML | Normalize output: strip proprietary attributes, handle nested elements |
| python-docx tables | Use default table style | Set `table_style` explicitly for borders |
| WeasyPrint images | Pass relative paths without `base_url` | Always provide `base_url` parameter |
| BytesIO + Flask | Assume Flask closes stream | For batch: manage lifecycle explicitly, close after use |
| Excel rich text | Convert HTML to plain text | Use openpyxl's `CellRichText` for inline formatting |

## Performance Traps

| Trap | Symptoms | Prevention | When It Breaks |
|------|----------|------------|----------------|
| Full HTML parse in every export | Slow exports, CPU spikes | Cache parsed HTML or pre-process on save | >100 records exported |
| Load all images into memory | OOM on image-heavy batches | Load images lazily, process one at a time | >20 images in batch |
| Generate all docs before streaming | Timeout on large batches | Stream to zip incrementally | >30 records in batch |
| No DPI normalization | Crashes on edge-case images | Normalize on upload, handle exceptions | Occurs randomly based on upload source |

## Security Mistakes

| Mistake | Risk | Prevention |
|---------|------|------------|
| Include unvalidated image paths | Path traversal, arbitrary file read | Validate paths are within uploads directory |
| Export deleted user's records | Information disclosure | Check user permissions before export |
| Accept any HTML for PDF | Malicious content in generated files | Sanitize HTML same as display (existing `sanitize_html` filter) |
| Store generated docs on server | Disk fill, stale data | Stream directly to client, don't persist |

## UX Pitfalls

| Pitfall | User Impact | Better Approach |
|---------|-------------|-----------------|
| Long export with no feedback | User thinks it's broken, refreshes, causes duplicate load | Show progress indicator, use async for large batches |
| Batch export creates one giant file | Hard to navigate, slow to open | Create ZIP with individual files per record |
| Exported formatting differs from preview | Users feel feature is broken | Use print-specific stylesheet, test visually |
| No option to exclude images | Large file sizes, slow downloads | Offer "with/without images" option for batch |

## "Looks Done But Isn't" Checklist

- [ ] **DOCX Export:** Often missing embedded images - verify images display offline
- [ ] **PDF Export:** Often missing proper page breaks - verify multi-page documents
- [ ] **Tables:** Often missing borders - verify `table_style` set
- [ ] **Lists:** Often lose nesting - verify multi-level lists indent correctly
- [ ] **Code blocks:** Often lose monospace - verify `<pre>` handled specially
- [ ] **Links:** Often broken in DOCX - verify hyperlinks work when clicked
- [ ] **Batch export:** Often causes OOM - verify with realistic team size (20+ records)
- [ ] **Chinese text:** Often has encoding issues - verify UTF-8 throughout

## Recovery Strategies

| Pitfall | Recovery Cost | Recovery Steps |
|---------|---------------|----------------|
| Image path resolution | LOW | Add path conversion utility, re-export |
| HTML conversion data loss | MEDIUM | Write custom handlers for missing elements |
| CSS compatibility | MEDIUM | Create print-specific stylesheet |
| Memory leak | HIGH | Redesign batch export to stream incrementally |
| Zero-DPI image crash | LOW | Add explicit dimensions, normalize on upload |

## Pitfall-to-Phase Mapping

| Pitfall | Prevention Phase | Verification |
|---------|------------------|--------------|
| Image path resolution | EXPORT-01 (DOCX) | Export with images, open offline |
| HTML-to-DOCX data loss | EXPORT-01 (DOCX) | Compare exported DOCX to browser preview |
| WeasyPrint CSS issues | EXPORT-02 (PDF) | Export complex HTML, compare to browser |
| Memory leak | EXPORT-04 (Batch) | Export 50+ records, monitor memory |
| Zero-DPI image crash | EXPORT-05 (Images) | Test with various image sources |

## Sources

- **python-docx GitHub Issues:** https://github.com/python-openxml/python-docx/issues - Zero-DPI crashes, table parsing issues, image handling bugs
- **WeasyPrint Features Documentation:** https://doc.courtbouillon.org/weasyprint/stable/features.html - CSS limitations, unsupported properties
- **WeasyPrint GitHub Issues:** https://github.com/Kozea/WeasyPrint/issues - Grid/flexbox bugs, table rendering issues
- **htmldocx PyPI:** https://pypi.org/project/htmldocx/ - Table styling defaults, library capabilities
- **Project codebase analysis:** `/home/one/weekly/utils.py`, `/home/one/weekly/routes.py` - Existing export implementation, upload handling

---
*Pitfalls research for: Rich Text Export Implementation*
*Researched: 2026-03-26*