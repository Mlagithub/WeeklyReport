# Stack Research: Rich Text Export

**Domain:** Document export with rich text formatting (DOCX/PDF/Excel)
**Researched:** 2026-03-26
**Confidence:** HIGH (verified via PyPI API, official docs, and local testing)

## Recommended Stack

### Core Export Libraries

| Library | Version | Purpose | Why Recommended |
|---------|---------|---------|-----------------|
| python-docx | 1.2.0 | DOCX file creation | Industry standard for Word documents. Active maintenance (June 2025 release). Supports images, tables, lists, hyperlinks, and all formatting needed for CKEditor output. |
| WeasyPrint | 68.1 | HTML to PDF conversion | Best HTML/CSS-to-PDF renderer. Pure Python with excellent CSS Paged Media support. Handles complex layouts from CKEditor. Requires Python 3.10+ (compatible with existing stack). |
| openpyxl | 3.1.5 | Excel rich text support | Already installed. Supports CellRichText for multiple fonts in single cell. Native support for bold, italic, colors, fonts without external dependencies. |

### Supporting Libraries

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| htmldocx | 0.0.6 | HTML to DOCX bridge | Converts CKEditor HTML to DOCX format. Works with python-docx. Note: Last updated 2021, may need custom tweaks for complex HTML. |
| Pillow | 11.0.0 | Image processing | Already installed. Required by WeasyPrint for image embedding. Handles image resizing for exports. |
| lxml | 4.8.0 | XML/HTML parsing | Already installed. Required by python-docx. Used for HTML parsing during conversion. |
| beautifulsoup4 | 4.12.3 | HTML parsing | Already installed. Required by htmldocx. Useful for custom HTML-to-format conversion. |
| requests | 2.33.0 | HTTP client | For downloading images from URLs in CKEditor content. Lightweight, already common in Flask apps. |

### System Dependencies

| Package | Purpose | Installation |
|---------|---------|--------------|
| libpango-1.0-0 | Text rendering for WeasyPrint | `apt install libpango-1.0-0` |
| libharfbuzz0b | Font shaping | `apt install libharfbuzz0b` |
| libpangoft2-1.0-0 | Pango FreeType support | `apt install libpangoft2-1.0-0` |

**Ubuntu one-liner:** `apt install weasyprint` (installs all dependencies)

## Installation

```bash
# Core export libraries
pip install python-docx==1.2.0
pip install WeasyPrint==68.1
pip install htmldocx==0.0.6

# Already installed (verify versions)
pip install openpyxl==3.1.5
pip install Pillow==11.0.0
pip install lxml==4.8.0
pip install beautifulsoup4==4.12.3

# For image downloading
pip install requests==2.33.0

# System dependencies for WeasyPrint (Ubuntu 22.04)
sudo apt install libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0
# Or simply:
sudo apt install weasyprint
```

## How Each Export Works

### DOCX Export (Word Format)

```
CKEditor HTML -> beautifulsoup4 parse -> htmldocx convert -> python-docx document
                                                            -> add images (Pillow)
                                                            -> save .docx
```

**Key capabilities:**
- Bold, italic, underline, strikethrough
- Font family, size, color
- Bulleted and numbered lists
- Tables with cell formatting
- Hyperlinks
- Embedded images (local files or base64)
- Code blocks (need custom styling)

**Limitation:** htmldocx is unmaintained (2021). May need custom HTML parser for complex CKEditor content.

### PDF Export

```
CKEditor HTML -> WeasyPrint render -> PDF document
             -> CSS styling added
             -> Images embedded (Pillow)
```

**Key capabilities:**
- Full CSS 2.1 + CSS 3 Paged Media support
- Flexbox layouts (simple cases)
- @page rules for headers/footers
- Custom page sizes, margins
- Embedded fonts
- Embedded images
- Table of contents generation

**CSS Support (WeasyPrint 68.1):**
- Supported: @page, margin boxes, page counters, flexbox, 2D transforms, @font-face
- Not supported: calc(), viewport units, box-shadow, text-shadow, :hover states

### Excel Rich Text

```
CKEditor HTML -> parse to runs -> openpyxl CellRichText -> apply InlineFont
                                   -> TextBlock for each style segment
                                   -> cell.value = rich_text_object
```

**Key capabilities:**
- CellRichText: Multiple fonts in single cell
- InlineFont: Bold, italic, underline, color, size, font family
- Works with existing openpyxl export code
- No additional dependencies

## Alternatives Considered

| Recommended | Alternative | Why Not |
|-------------|-------------|---------|
| WeasyPrint | xhtml2pdf 0.2.17 | xhtml2pdf has limited CSS support (only CSS 2.1 + some CSS3). WeasyPrint supports modern CSS, @page rules, better typography. xhtml2pdf's last significant update was years ago. |
| WeasyPrint | ReportLab 4.4.10 | ReportLab is a drawing library, not HTML-to-PDF. Would require building layouts manually. Too much code for rich HTML content. |
| python-docx | docxtpl | docxtpl is a templating wrapper around python-docx. Useful for templates, but we need HTML-to-DOCX conversion, not Jinja2 templates. |
| htmldocx | html-to-docx 0.0.5 | html-to-docx has no declared dependencies and minimal documentation. htmldocx at least depends on python-docx and beautifulsoup4 (both we have). |
| htmldocx | Custom HTML parser | More work but better control. Consider if htmldocx fails on CKEditor HTML. Use beautifulsoup4 to parse HTML and python-docx to build document manually. |

## What NOT to Use

| Avoid | Why | Use Instead |
|-------|-----|-------------|
| pdfkit | Requires wkhtmltopdf binary. Additional deployment complexity. | WeasyPrint |
| pisa | Old xhtml2pdf name. Same limitations. | WeasyPrint |
| docx-python | Typo-squatting package, not official. | python-docx |
| python-docx-template | Adds templating layer we don't need. | python-docx directly |

## Version Compatibility

| Package A | Compatible With | Notes |
|-----------|-----------------|-------|
| python-docx 1.2.0 | lxml >= 3.1.0 | Already have lxml 4.8.0 |
| WeasyPrint 68.1 | Python >= 3.10 | Current stack is Python 3.10.12 |
| WeasyPrint 68.1 | Pillow >= 9.1.0 | Already have Pillow 11.0.0 |
| htmldocx 0.0.6 | python-docx >= 0.8.10 | Compatible with python-docx 1.2.0 |
| htmldocx 0.0.6 | beautifulsoup4 >= 4.7.0 | Already have beautifulsoup4 4.12.3 |
| openpyxl 3.1.5 | Python >= 3.6 | Compatible |

## Flask Integration Patterns

### DOCX Export Route

```python
from flask import send_file
from docx import Document
from htmldocx import HtmlToDocx
import io

@app.route('/export/docx/<int:record_id>')
def export_docx(record_id):
    record = get_record(record_id)  # Get HTML content
    document = Document()
    parser = HtmlToDocx()
    parser.add_html_to_document(record.content, document)

    # Send as downloadable file
    buffer = io.BytesIO()
    document.save(buffer)
    buffer.seek(0)
    return send_file(buffer, mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                     as_attachment=True, download_name=f'report_{record_id}.docx')
```

### PDF Export Route

```python
from flask import send_file
from weasyprint import HTML, CSS
import io

@app.route('/export/pdf/<int:record_id>')
def export_pdf(record_id):
    record = get_record(record_id)
    html_content = f"""
    <html><head>
    <style>
        @page {{ margin: 2cm; }}
        body {{ font-family: sans-serif; }}
    </style>
    </head><body>{record.content}</body></html>
    """
    pdf = HTML(string=html_content).write_pdf()

    buffer = io.BytesIO(pdf)
    return send_file(buffer, mimetype='application/pdf',
                     as_attachment=True, download_name=f'report_{record_id}.pdf')
```

### Excel Rich Text Cell

```python
from openpyxl.cell.rich_text import CellRichText, TextBlock
from openpyxl.cell.text import InlineFont

# Create rich text cell
bold_font = InlineFont(b=True)
normal_font = InlineFont()

cell.value = CellRichText(
    TextBlock(bold_font, "Bold text"),
    " normal text",
    TextBlock(InlineFont(i=True, color="FF0000"), " italic red")
)
```

## Sources

- PyPI API — python-docx 1.2.0, WeasyPrint 68.1, xhtml2pdf 0.2.17, openpyxl 3.1.5 versions verified
- https://pypi.org/project/python-docx/ — Core DOCX library
- https://pypi.org/project/WeasyPrint/ — HTML to PDF renderer
- https://doc.courtbouillon.org/weasyprint/stable/features.html — CSS support details (HIGH confidence)
- https://pypi.org/project/htmldocx/ — HTML to DOCX bridge
- https://openpyxl.readthedocs.io/en/stable/ — Excel library (local verification of rich text support)
- Local testing — openpyxl 3.1.5 CellRichText, Pillow 11.0.0, lxml 4.8.0 confirmed installed

---
*Stack research for: Rich text export (DOCX/PDF/Excel)*
*Researched: 2026-03-26*