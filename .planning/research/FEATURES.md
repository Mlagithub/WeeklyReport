# Feature Research

**Domain:** Rich Text Document Export for Flask Weekly Report System
**Researched:** 2026-03-26
**Confidence:** MEDIUM (WebSearch results limited, relied on official documentation where available)

## Feature Landscape

### Table Stakes (Users Expect These)

Features users assume exist in a document export system. Missing these = product feels incomplete.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| DOCX format export | Industry standard format, editable | MEDIUM | python-docx + htmldocx; images need special handling |
| PDF format export | Read-only sharing, universal viewing | MEDIUM | WeasyPrint (active) or xhtml2pdf; wkhtmltopdf archived 2023 |
| Text formatting preservation | Bold, italic, underline, lists | MEDIUM | htmldocx supports basic HTML; custom handling may be needed |
| Table export | CKEditor generates tables | LOW | htmldocx supports tables with styling |
| Heading hierarchy | CKEditor generates h1-h6 | LOW | Direct conversion supported |
| Link preservation | Hyperlinks in reports | LOW | python-docx supports hyperlinks |
| Code block formatting | CKEditor generates pre/code | LOW | Pre-formatted text conversion |
| Downloadable file | Immediate download response | LOW | Flask send_file with BytesIO |

### Differentiators (Competitive Advantage)

Features that set the product apart. Not required, but valuable.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| Image embedding (not links) | Offline viewing, self-contained documents | HIGH | Requires downloading images, embedding as binary; htmldocx lacks native support |
| Batch export for team leads | Export entire group's reports in one action | MEDIUM | zipfile + BytesIO; memory considerations for large batches |
| Rich text in Excel cells | Better readability in spreadsheet format | HIGH | openpyxl supports CellRun for inline formatting; significant rework needed |
| PDF page headers/footers | Professional document appearance | MEDIUM | WeasyPrint CSS paged media; @page rules |
| PDF table of contents | Navigation in long documents | MEDIUM | WeasyPrint running elements; requires document structure |
| Custom export templates | Branding, company logo | MEDIUM | Jinja2 templates for HTML input to converters |

### Anti-Features (Commonly Requested, Often Problematic)

Features that seem good but create problems.

| Feature | Why Requested | Why Problematic | Alternative |
|---------|---------------|-----------------|-------------|
| Real-time preview before export | Users want to see output | Significant latency; doubles processing; storage for previews | Offer format selection with clear descriptions |
| Export to Google Docs | Cloud collaboration | OAuth complexity; API rate limits; format loss | Export DOCX, let users upload manually |
| Editable PDF forms | Data entry in PDF | Complex JavaScript; limited tool support | PDF for viewing only; DOCX for editing |
| Embedded Excel in DOCX | Multi-format in one file | OLE objects not well supported; file bloat | Separate exports per format |

## Feature Dependencies

```
DOCX Export
    └──requires──> python-docx library
    └──requires──> htmldocx library (or custom HTML parser)
    └──requires──> Image download for embedded images
                       └──requires──> Image file access (existing /files/<filename> route)

PDF Export
    └──requires──> WeasyPrint library (or xhtml2pdf)
    └──requires──> Image path resolution for embedded images

Excel Rich Text
    └──requires──> openpyxl (already installed)
    └──requires──> HTML parser to CellRun conversion (custom implementation)

Batch Export
    └──requires──> DOCX or PDF export working
    └──requires──> zipfile module (stdlib)
    └──requires──> Permission system (already exists: view_group)

Image Embedding
    └──requires──> File system access to uploaded images
    └──requires──> Image download/resolution logic
    └──enhances──> DOCX Export
    └──enhances──> PDF Export
```

### Dependency Notes

- **DOCX Export requires python-docx:** Core library for Word document creation; stable, well-documented.
- **PDF Export requires WeasyPrint:** Active project with BSD license; wkhtmltopdf archived Jan 2023 (DO NOT USE).
- **Batch Export requires DOCX/PDF:** Must have working single-export before batch can function.
- **Image Embedding enhances DOCX/PDF:** Without embedding, images show as broken links in offline viewing.
- **Excel Rich Text requires custom HTML parser:** openpyxl supports rich text but no HTML-to-CellRun converter exists; must build custom.

## MVP Definition

### Launch With (v1)

Minimum viable product - what's needed to validate the export feature.

- [ ] **DOCX Export (Basic)** - Tables, lists, headings, links, code blocks; images as links initially
- [ ] **PDF Export (Basic)** - Same content as DOCX; WeasyPrint for reliable rendering
- [ ] **Batch Export (Simple)** - Zip file of individual DOCX files; memory limits enforced

### Add After Validation (v1.x)

Features to add once core is working.

- [ ] **Image Embedding** - Download and embed images in DOCX/PDF; offline viewing support
- [ ] **PDF Headers/Footers** - Page numbers, date, document title
- [ ] **Excel Rich Text** - Inline formatting with openpyxl CellRun

### Future Consideration (v2+)

Features to defer until product-market fit is established.

- [ ] **Custom Export Templates** - Company branding, custom headers
- [ ] **PDF Table of Contents** - For multi-report exports
- [ ] **Export Scheduling** - Automated weekly exports to email

## Feature Prioritization Matrix

| Feature | User Value | Implementation Cost | Priority |
|---------|------------|---------------------|----------|
| DOCX Export (Basic) | HIGH | MEDIUM | P1 |
| PDF Export (Basic) | HIGH | MEDIUM | P1 |
| Batch Export | MEDIUM | LOW | P1 |
| Image Embedding | HIGH | HIGH | P2 |
| Excel Rich Text | MEDIUM | HIGH | P2 |
| PDF Headers/Footers | LOW | MEDIUM | P3 |
| Custom Templates | LOW | MEDIUM | P3 |

**Priority key:**
- P1: Must have for launch
- P2: Should have, add when possible
- P3: Nice to have, future consideration

## Format-Specific Analysis

### DOCX Export

**Library Choice: python-docx + htmldocx**

| Aspect | Status | Notes |
|--------|--------|-------|
| Text formatting (b/i/u) | Supported | Direct conversion via htmldocx |
| Headings (h1-h6) | Supported | htmldocx maps to Word styles |
| Lists (ul/ol) | Supported | htmldocx handles list conversion |
| Tables | Supported | htmldocx supports tables; styling available |
| Links | Supported | python-docx add_hyperlink method |
| Code blocks | Partial | pre/code becomes formatted text; no syntax highlighting |
| Images | NOT AUTOMATIC | htmldocx does not embed images; requires custom implementation |
| Batch export | Supported | zipfile + BytesIO pattern |

**Image Embedding Strategy for DOCX:**
1. Parse HTML to find `<img>` tags
2. Extract `src` attribute (URLs like `/files/<uuid>_<filename>`)
3. Resolve to file system path
4. Use `document.add_picture()` to embed inline
5. Handle missing images gracefully (placeholder or skip)

### PDF Export

**Library Choice: WeasyPrint (RECOMMENDED)**

| Aspect | Status | Notes |
|--------|--------|-------|
| HTML rendering | Good | CSS 2.1 + partial CSS 3 support |
| Text formatting | Good | Standard CSS styling |
| Lists/Tables | Good | Full support |
| Links | Good | PDF hyperlinks generated |
| Images | Good | From file paths or data URIs |
| Page breaks | Good | CSS `page-break-*` properties |
| Headers/Footers | Good | CSS `@page` rules with running elements |
| Dependency | LOW | Pure Python, no external binary |

**Why NOT wkhtmltopdf:**
- Project archived January 2023
- Last release June 2020
- Requires external binary installation
- Qt WebKit engine outdated

**Alternative: xhtml2pdf**
- Pure Python (ReportLab-based)
- HTML5 + CSS 2.1 (partial CSS 3)
- Good for simpler documents
- Less CSS support than WeasyPrint

### Excel Rich Text

**Library: openpyxl (already installed v3.1.5)**

| Aspect | Status | Notes |
|--------|--------|-------|
| Basic cells | Working | Current implementation |
| Rich text cells | Possible | CellRun class for inline formatting |
| Bold/italic | Possible | Via Font objects |
| Colors | Possible | Via Font and PatternFill |
| Links | Possible | Hyperlink cells |
| Images in cells | Limited | openpyxl supports images but not inline with text |
| HTML conversion | NOT BUILT | Must parse HTML and create CellRun objects |

**Implementation Approach for Excel Rich Text:**
1. Parse HTML content (BeautifulSoup already available)
2. For each text segment, create Font with appropriate properties
3. Build CellRun list with text + font pairs
4. Assign to cell.value as CellRunRichText object
5. Handle complex nesting (bold inside italic) carefully

### Batch Export

**Implementation Pattern:**

```python
from zipfile import ZipFile
from io import BytesIO

def batch_export(records):
    zip_buffer = BytesIO()
    with ZipFile(zip_buffer, 'w') as zf:
        for record in records:
            docx_content = generate_docx(record)
            zf.writestr(f"{record.username}_{record.date}.docx", docx_content)
    zip_buffer.seek(0)
    return send_file(zip_buffer, mimetype='application/zip', ...)
```

**Memory Considerations:**
- Process records in chunks for large batches
- Set maximum records per batch (e.g., 50)
- Consider streaming response for very large exports

## CKEditor HTML Element Support

Based on ALLOWED_TAGS in app.py, CKEditor produces:

| Element | DOCX Support | PDF Support | Excel Support |
|---------|-------------|-------------|---------------|
| p | Yes | Yes | Yes (cell text) |
| br | Yes | Yes | Yes |
| b, strong | Yes | Yes | Yes (Font bold) |
| i, em | Yes | Yes | Yes (Font italic) |
| u | Yes | Yes | Yes (Font underline) |
| ul, ol, li | Yes | Yes | Converted to text with bullets |
| a | Yes (hyperlink) | Yes | Yes (Hyperlink) |
| img | Requires custom | Yes | Limited |
| h1-h6 | Yes | Yes | Yes (bold, larger) |
| blockquote | Yes (indent) | Yes | Yes (indent) |
| pre, code | Yes (monospace) | Yes | Yes (font) |
| table elements | Yes | Yes | Yes (native) |
| span, div | Partial | Yes | Partial |

## Sources

- [python-docx PyPI](https://pypi.org/project/python-docx/) - Core DOCX library
- [htmldocx PyPI](https://pypi.org/project/htmldocx/) - HTML to DOCX conversion
- [WeasyPrint PyPI](https://pypi.org/project/weasyprint/) - PDF generation
- [WeasyPrint Features](https://weasyprint.org/) - CSS paged media, headers/footers
- [WeasyPrint GitHub](https://github.com/Kozea/WeasyPrint) - Active project, BSD license
- [wkhtmltopdf GitHub](https://github.com/wkhtmltopdf/wkhtmltopdf) - ARCHIVED Jan 2023, DO NOT USE
- [xhtml2pdf PyPI](https://pypi.org/project/xhtml2pdf/) - Alternative PDF library
- [openpyxl requirements.txt] - Already installed v3.1.5
- [app.py ALLOWED_TAGS] - CKEditor output elements

---
*Feature research for: Rich Text Export Functionality*
*Researched: 2026-03-26*