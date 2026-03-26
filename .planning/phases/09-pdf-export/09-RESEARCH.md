# Phase 9: PDF Export - Research

**Researched:** 2026-03-26
**Domain:** WeasyPrint PDF generation, CSS Paged Media, image embedding
**Confidence:** HIGH

## Summary

Phase 9 implements PDF export functionality using WeasyPrint 68.1, which is already installed and verified working. The phase builds on Phase 8 infrastructure (ExporterBase, ExporterFactory, ImageResolver) to create a PdfExporter class that handles HTML-to-PDF conversion with embedded images and professional headers/footers using CSS Paged Media.

WeasyPrint provides native support for CSS Paged Media (`@page` rules), enabling headers with document titles, footers with page numbers, and running elements for dynamic content. Image embedding is achieved via a custom `url_fetcher` that intercepts `/files/` URLs and resolves them to local filesystem paths using the existing ImageResolver.

**Primary recommendation:** Create PdfExporter extending ExporterBase with CSS Paged Media stylesheet and custom url_fetcher for image resolution.

---

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| WeasyPrint | 68.1 | HTML to PDF conversion | Pure Python, active maintenance, best CSS Paged Media support |
| python-docx | 1.2.0 | DOCX creation | Already installed for Phase 10 |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| Pillow | 11.0.0 | Image processing | Required by WeasyPrint (already installed) |
| beautifulsoup4 | 4.12.3 | HTML parsing | Already installed, used for HTML preprocessing |
| lxml | 4.8.0 | XML parsing | Required by WeasyPrint (already installed) |

### Project Infrastructure (Phase 8)

| Component | Location | Purpose |
|-----------|----------|---------|
| ExporterBase | exporters/base.py | Abstract base class with template method pattern |
| ExporterFactory | exporters/__init__.py | Factory for creating format-specific exporters |
| ImageResolver | exporters/image_resolver.py | Convert /files/ URLs to filesystem paths |

**Installation:** Already complete from Phase 8.

**Version verification:**
- WeasyPrint 68.1 (verified installed 2026-03-26)
- Pillow 11.0.0 (verified)
- lxml 4.8.0 (verified)

---

## Architecture Patterns

### Recommended Project Structure

```
/home/one/weekly/
├── exporters/
│   ├── __init__.py         # ExporterFactory (add pdf registration)
│   ├── base.py             # ExporterBase (existing)
│   ├── image_resolver.py   # ImageResolver (existing)
│   └── pdf.py              # NEW: PdfExporter class
├── routes.py               # Modify download_records for format param
├── forms.py                # Modify RecordDownloadForm for format dropdown
└── templates/
    └── manage_records.html # Add format selector UI
```

### Pattern 1: PdfExporter Implementation

**What:** Extend ExporterBase to create PDF documents via WeasyPrint
**When to use:** All PDF export requests
**Example:**

```python
# exporters/pdf.py
from weasyprint import HTML, CSS
from io import BytesIO
from typing import List, Dict, Any
import os
from datetime import datetime

from .base import ExporterBase
from .image_resolver import ImageResolver


class PdfExporter(ExporterBase):
    """PDF exporter using WeasyPrint with CSS Paged Media support."""

    def __init__(self, uploads_path: str = None):
        """Initialize with uploads path for image resolution.

        Args:
            uploads_path: Path to uploads directory (default: from config)
        """
        self._uploads_path = uploads_path
        self._image_resolver = None

    @property
    def uploads_path(self) -> str:
        """Get uploads path, initializing from Flask config if needed."""
        if self._uploads_path is None:
            from flask import current_app
            self._uploads_path = current_app.config['UPLOADED_PATH']
        return self._uploads_path

    @property
    def image_resolver(self) -> ImageResolver:
        """Get image resolver instance."""
        if self._image_resolver is None:
            self._image_resolver = ImageResolver(self.uploads_path)
        return self._image_resolver

    @property
    def file_extension(self) -> str:
        return 'pdf'

    @property
    def mime_type(self) -> str:
        return 'application/pdf'

    def _generate(self, records: List[Any], options: Dict) -> BytesIO:
        """Generate PDF from records using WeasyPrint.

        Args:
            records: List of Record objects with content and date
            options: Export options (title, include_date, etc.)

        Returns:
            BytesIO buffer containing PDF
        """
        title = options.get('title', 'Weekly Report')
        include_date = options.get('include_date', True)

        # Build HTML content with CSS Paged Media
        html_content = self._build_html(records, title, include_date)

        # Create custom URL fetcher for image resolution
        def url_fetcher(url):
            return self._resolve_image_url(url)

        # Generate PDF
        html = HTML(string=html_content, url_fetcher=url_fetcher)
        output = BytesIO()
        html.write_pdf(output)
        output.seek(0)
        return output

    def _build_html(self, records: List[Any], title: str, include_date: bool) -> str:
        """Build HTML document with CSS Paged Media stylesheet.

        Args:
            records: List of Record objects
            title: Document title for header
            include_date: Whether to include date in footer

        Returns:
            Complete HTML document string
        """
        date_str = datetime.now().strftime('%Y-%m-%d') if include_date else ''

        # CSS Paged Media stylesheet for headers/footers
        css = '''
        <style>
        @page {
            size: A4;
            margin: 2.5cm 2cm;

            @top-center {
                content: element(header);
            }

            @bottom-left {
                content: element(footer-left);
            }

            @bottom-right {
                content: "Page " counter(page);
                font-size: 9pt;
            }
        }

        #header {
            position: running(header);
            text-align: center;
            font-size: 12pt;
            font-weight: bold;
            border-bottom: 1px solid #333;
            padding-bottom: 5px;
        }

        #footer-left {
            position: running(footer-left);
            font-size: 9pt;
            color: #666;
        }

        body {
            font-family: "Microsoft YaHei", Arial, sans-serif;
            line-height: 1.6;
        }

        h1, h2, h3 { color: #333; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f5f5f5; }
        img { max-width: 100%; height: auto; }
        </style>
        '''

        # Build content sections
        content_sections = []
        for record in records:
            if record.content:
                content_sections.append(f'''
                <div class="record">
                    <p class="date"><small>{record.date.strftime('%Y-%m-%d')}</small></p>
                    {record.content}
                </div>
                <hr>
                ''')

        return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            {css}
        </head>
        <body>
            <div id="header">{title}</div>
            <div id="footer-left">Generated: {date_str}</div>

            {''.join(content_sections)}
        </body>
        </html>
        '''

    def _resolve_image_url(self, url: str) -> dict:
        """Resolve /files/ URLs to local image data.

        Custom URL fetcher for WeasyPrint that intercepts /files/ URLs
        and returns image data from the uploads directory.

        Args:
            url: Image URL from HTML src attribute

        Returns:
            Dict with 'string' (bytes) and 'mime_type' for images,
            or raises exception for unresolvable URLs
        """
        if url.startswith('/files/'):
            filename = url[7:]  # Remove '/files/' prefix
            local_path = os.path.join(self.uploads_path, filename)

            if os.path.exists(local_path):
                with open(local_path, 'rb') as f:
                    image_data = f.read()

                # Determine MIME type from extension
                ext = filename.rsplit('.', 1)[-1].lower()
                mime_types = {
                    'jpg': 'image/jpeg',
                    'jpeg': 'image/jpeg',
                    'png': 'image/png',
                    'gif': 'image/gif',
                }
                mime_type = mime_types.get(ext, 'application/octet-stream')

                return {'string': image_data, 'mime_type': mime_type}

        # External URLs are not resolved (will fail if image is required)
        raise Exception(f"Cannot resolve URL: {url}")
```

**Source:** WeasyPrint API documentation, tested locally 2026-03-26

### Pattern 2: CSS Paged Media for Headers/Footers

**What:** Use `@page` rules and running elements for professional document headers/footers
**When to use:** All PDF exports requiring page numbers, dates, or titles
**Implementation approaches:**

1. **Simple approach with @page margin rules:**
```css
@page {
    @top-center { content: "Document Title"; }
    @bottom-right { content: "Page " counter(page); }
}
```

2. **Advanced approach with running elements (recommended):**
```css
@page {
    @top-center { content: element(header); }
    @bottom-left { content: element(footer); }
}

#header { position: running(header); }
#footer { position: running(footer); }
```

**Source:** MDN CSS @page documentation, WeasyPrint tested locally

### Pattern 3: Image Embedding via url_fetcher

**What:** Custom URL fetcher intercepts /files/ URLs and returns local image data
**When to use:** CKEditor images stored in uploads/ directory
**Why this approach:** WeasyPrint's base_url works for relative URLs, but CKEditor uses `/files/` absolute paths

```python
def url_fetcher(url):
    if url.startswith('/files/'):
        filename = url[7:]
        local_path = os.path.join(uploads_path, filename)
        if os.path.exists(local_path):
            with open(local_path, 'rb') as f:
                return {'string': f.read(), 'mime_type': 'image/png'}
    raise Exception(f"URL not found: {url}")

html = HTML(string=html_content, url_fetcher=url_fetcher)
```

**Source:** WeasyPrint API, tested locally 2026-03-26

### Pattern 4: Route Integration

**What:** Modify download_records route to support format parameter
**When to use:** All export requests

```python
# routes.py - modification to download_records
@app.route('/download_records', methods=['POST'])
@login_required
def download_records():
    format = request.form.get('format', 'xlsx')  # Default to Excel
    query, start_date, end_date, _ = build_record_query(request.form)

    records = query.all()

    if format == 'pdf':
        from exporters import ExporterFactory
        exporter = ExporterFactory.get_exporter('pdf')
        output = exporter.export(records, title='Weekly Report')

        filename = f"周报_{start_date.strftime('%Y%m%d')}.pdf"
        return send_file(
            output,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
    # ... existing Excel logic ...
```

### Anti-Patterns to Avoid

- **Using base_url with /files/ URLs:** base_url only works for relative URLs, not absolute `/files/` paths. Use url_fetcher instead.
- **Ignoring CSS Paged Media support:** WeasyPrint has excellent @page support - use it instead of JavaScript-based pagination.
- **External image URLs in PDFs:** Images should be embedded for offline viewing. Strip or warn about external URLs.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| PDF generation | Custom PDF library | WeasyPrint | Handles CSS, images, tables, complex layouts |
| Headers/footers | Manual page counting | CSS @page rules | Native support, automatic page breaks |
| Image resolution | String manipulation | ImageResolver + url_fetcher | Handles edge cases, testable |
| HTML to PDF | ReportLab, FPDF | WeasyPrint | HTML/CSS rendering, much simpler |

**Key insight:** WeasyPrint is purpose-built for HTML-to-PDF with CSS styling. Don't fight it - use its native features.

---

## Common Pitfalls

### Pitfall 1: Image URL Resolution with /files/ Prefix

**What goes wrong:** CKEditor stores images as `/files/<uuid>` but WeasyPrint base_url doesn't resolve these
**Why it happens:** base_url only works for relative URLs (e.g., `image.png`), not absolute paths (`/files/image.png`)
**How to avoid:** Use custom `url_fetcher` parameter to intercept `/files/` URLs
**Warning signs:** Images missing in PDF, no error messages

**Solution:**
```python
# WRONG - base_url doesn't work for /files/ URLs
html = HTML(string=content, base_url='/path/to/uploads/')

# RIGHT - use url_fetcher
def url_fetcher(url):
    if url.startswith('/files/'):
        return read_local_image(url)
    raise Exception(f"Unknown URL: {url}")

html = HTML(string=content, url_fetcher=url_fetcher)
```

### Pitfall 2: CSS Not Rendering in PDF

**What goes wrong:** Styles from external stylesheets not applied
**Why it happens:** WeasyPrint needs inline styles or embedded CSS in the HTML string
**How to avoid:** Include CSS in `<style>` tags within the HTML string
**Warning signs:** Plain text appearance, no formatting

### Pitfall 3: Chinese Font Issues

**What goes wrong:** Chinese characters appear as boxes or fallback fonts
**Why it happens:** PDF doesn't embed fonts, system may lack Chinese fonts
**How to avoid:** Specify Chinese fonts in CSS: `font-family: "Microsoft YaHei", "SimSun", Arial, sans-serif;`
**Warning signs:** Garbled Chinese text in PDF

### Pitfall 4: Memory Issues with Large Documents

**What goes wrong:** Large PDFs consume excessive memory
**Why it happens:** WeasyPrint builds entire document in memory
**How to avoid:** For batch exports (Phase 12), generate individual PDFs before ZIP creation
**Warning signs:** OutOfMemoryError, slow generation

---

## Code Examples

### Basic PdfExporter Class Structure

```python
# exporters/pdf.py
from weasyprint import HTML
from io import BytesIO
from typing import List, Dict, Any

from .base import ExporterBase


class PdfExporter(ExporterBase):
    """PDF exporter using WeasyPrint."""

    @property
    def file_extension(self) -> str:
        return 'pdf'

    @property
    def mime_type(self) -> str:
        return 'application/pdf'

    def _generate(self, records: List[Any], options: Dict) -> BytesIO:
        html_content = self._build_html(records, options)
        html = HTML(string=html_content, url_fetcher=self._url_fetcher)
        output = BytesIO()
        html.write_pdf(output)
        output.seek(0)
        return output
```

### CSS Paged Media Stylesheet

```css
@page {
    size: A4;
    margin: 2.5cm 2cm;

    @top-center {
        content: element(header);
    }

    @bottom-left {
        content: element(footer);
    }

    @bottom-right {
        content: "Page " counter(page);
        font-size: 9pt;
    }
}

#header {
    position: running(header);
    text-align: center;
    font-weight: bold;
}

#footer {
    position: running(footer);
    font-size: 9pt;
    color: #666;
}
```

### Format Selection in Form

```python
# forms.py - add to RecordDownloadForm
class RecordDownloadForm(FlaskForm):
    format = SelectField("格式", choices=[
        ('xlsx', 'Excel'),
        ('pdf', 'PDF'),
        ('docx', 'Word'),  # Phase 10
    ], default='xlsx')
    download_submit = SubmitField("下载")
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| wkhtmltopdf | WeasyPrint | 2023 (wkhtmltopdf archived) | Pure Python, no external binary |
| Manual pagination | CSS Paged Media @page | Native support | Professional documents |
| Image URL rewriting | Custom url_fetcher | Phase 9 | Clean separation, testable |

**Deprecated/outdated:**
- **wkhtmltopdf:** Archived in 2023, requires external binary - use WeasyPrint instead
- **xhtml2pdf:** Limited CSS support, poor maintenance - use WeasyPrint instead
- **ReportLab:** Too low-level for HTML content - use WeasyPrint for HTML-to-PDF

---

## Open Questions

1. **Page number format**
   - What we know: `counter(page)` gives current page, `counter(pages)` gives total
   - What's unclear: Best format for Chinese documents ("第 X 页 / 共 Y 页")
   - Recommendation: Use `"Page " counter(page) " of " counter(pages)` for now, localize in Phase 12 if needed

2. **Multi-record PDF layout**
   - What we know: Records can be combined in single HTML document
   - What's unclear: Best separator between records (horizontal rule, page break, title)
   - Recommendation: Use horizontal rule with date header per record

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| WeasyPrint | PDF export | Yes | 68.1 | - |
| Pillow | Image processing | Yes | 11.0.0 | - |
| lxml | XML parsing | Yes | 4.8.0 | - |
| beautifulsoup4 | HTML parsing | Yes | 4.12.3 | - |
| libpango | Font rendering | Yes | 1.50.6 | - |
| libharfbuzz | Text shaping | Yes | 2.7.4 | - |

**Missing dependencies with no fallback:** None

**Missing dependencies with fallback:** None

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | pytest 8.3.5 |
| Config file | pytest.ini |
| Quick run command | `pytest tests/ -v -x` |
| Full suite command | `pytest tests/ -v --cov=. --cov-report=term-missing` |

### Phase Requirements -> Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| PDF-01 | PDF format export with HTML rendering | unit | `pytest tests/test_exporters.py::TestPdfExporter -v` | Wave 0 |
| PDF-02 | Image embedding in PDF | unit | `pytest tests/test_exporters.py::TestPdfExporter::test_image_embedding -v` | Wave 0 |
| PDF-03 | Headers/footers with page numbers | unit | `pytest tests/test_exporters.py::TestPdfExporter::test_headers_footers -v` | Wave 0 |

### Sampling Rate

- **Per task commit:** `pytest tests/ -v -x`
- **Per wave merge:** `pytest tests/ -v --cov=.`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps

- [ ] `tests/test_exporters.py::TestPdfExporter` - Test PdfExporter class
- [ ] `tests/test_exporters.py::TestPdfExporter::test_file_extension` - Verify 'pdf' extension
- [ ] `tests/test_exporters.py::TestPdfExporter::test_mime_type` - Verify 'application/pdf'
- [ ] `tests/test_exporters.py::TestPdfExporter::test_image_embedding` - Test url_fetcher with /files/ URLs
- [ ] `tests/test_exporters.py::TestPdfExporter::test_headers_footers` - Test CSS Paged Media output
- [x] Framework installed: pytest 8.3.5
- [x] WeasyPrint installed: 68.1

---

## Integration Points

### Existing Components (Phase 8)

| Component | Location | Current State | Phase 9 Change |
|-----------|----------|---------------|----------------|
| ExporterBase | exporters/base.py | Complete | Inherit for PdfExporter |
| ExporterFactory | exporters/__init__.py | Complete | Register 'pdf' format |
| ImageResolver | exporters/image_resolver.py | Complete | Use for url_fetcher |
| `/download_records` | routes.py | Excel only | Add format parameter |
| RecordDownloadForm | forms.py | Submit only | Add format dropdown |
| UPLOADED_PATH | config.py | Configured | Used by PdfExporter |

### New Components

| Component | Dependencies | Risk |
|-----------|--------------|------|
| exporters/pdf.py | WeasyPrint, ImageResolver | Low |
| tests/test_exporters.py::TestPdfExporter | pytest | Low |

### Key Configuration

```python
# config.py (existing)
UPLOADED_PATH = os.path.join(basedir, 'uploads')

# PdfExporter will use this path for image resolution
```

---

## Sources

### Primary (HIGH confidence)

- WeasyPrint local testing - CSS Paged Media, image embedding verified 2026-03-26
- MDN CSS @page documentation - https://developer.mozilla.org/en-US/docs/Web/CSS/@page
- `.planning/research/SUMMARY.md` - Milestone research with library recommendations
- `.planning/research/ARCHITECTURE.md` - Export architecture patterns
- `.planning/phases/08-export-foundation/08-RESEARCH.md` - Phase 8 infrastructure

### Secondary (MEDIUM confidence)

- `.planning/STATE.md` - Project decisions (D-01: no Blueprints, D-11: UUID filenames)
- Existing codebase - exporters/base.py, routes.py, config.py analyzed
- WeasyPrint PyPI - https://pypi.org/project/weasyprint/

### Tertiary (LOW confidence)

- None - all critical features verified locally

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - WeasyPrint 68.1 verified installed and working
- Architecture: HIGH - Patterns tested locally with actual code
- Pitfalls: HIGH - Verified solutions through testing
- Image embedding: HIGH - All three approaches (file://, base_url, url_fetcher) tested
- CSS Paged Media: HIGH - @page rules and running elements tested

**Research date:** 2026-03-26
**Valid until:** 30 days (stable library)