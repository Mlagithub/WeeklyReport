# Architecture Research: Rich Text Export Integration

**Domain:** Flask weekly report management system
**Researched:** 2026-03-26
**Confidence:** MEDIUM (library documentation limited for image handling details)

## Executive Summary

The existing Flask application uses a modular monolith pattern with clear separation of concerns. Export functionality currently lives in `utils.py` with the `RecordDownloader` class. The recommended approach for rich text exports is to create a dedicated `exporters/` module with format-specific exporter classes, following the existing utility pattern. WeasyPrint is recommended for PDF generation (native HTML/CSS rendering with image support via `base_url`). For DOCX, use `htmldocx` for basic conversion combined with custom image handling via `python-docx`. Excel enhancement uses openpyxl's existing `CellRichText` API.

---

## Current Architecture Integration Points

### Existing Export Flow

```
[POST /download_records]
        |
        v
[build_record_query()] --> Filter records by user/group/time
        |
        v
[Aggregate by user/week] --> Dict structure for Excel
        |
        v
[RecordDownloader.download()] --> Generate Excel with openpyxl
        |
        v
[send_file(BytesIO)] --> Return to client
```

**Key files to modify:**
| File | Current Role | Export Integration |
|------|--------------|-------------------|
| `routes.py` | `/download_records` route | Add format parameter, route to appropriate exporter |
| `utils.py` | `RecordDownloader`, `html_to_text` | Extend with rich text handling |
| `forms.py` | `RecordDownloadForm` | Add format selection dropdown |

**Key files to create:**
| File | Purpose |
|------|---------|
| `exporters/__init__.py` | Exporter factory and base class |
| `exporters/docx_exporter.py` | DOCX generation with images |
| `exporters/pdf_exporter.py` | PDF generation via WeasyPrint |
| `exporters/excel_exporter.py` | Enhanced Excel with rich text |

---

## Recommended Architecture

### System Overview

```
                            [Route: /download_records]
                                       |
                          +------------+-------------+
                          |    Format Selection      |
                          +------------+-------------+
                                       |
              +------------------------+------------------------+
              |                        |                        |
              v                        v                        v
    [DocxExporter]           [PdfExporter]           [ExcelExporter]
              |                        |                        |
    +---------+---------+    +---------+---------+    +---------+---------+
    | HtmlToDocx        |    | WeasyPrint       |    | openpyxl         |
    | + python-docx     |    | HTML(base_url)   |    | CellRichText     |
    | + Image Handler   |    +-------------------+    +------------------+
    +-------------------+
              |
              v
    [BytesIO / ZIP file]
              |
              v
    [Flask send_file()]
```

### Component Responsibilities

| Component | Responsibility | Implementation |
|-----------|----------------|----------------|
| `ExporterBase` | Abstract base with common interface | ABC with `export(records, options)` method |
| `DocxExporter` | Generate DOCX with embedded images | `htmldocx` + custom image injection via `python-docx` |
| `PdfExporter` | Generate PDF preserving HTML formatting | WeasyPrint with `base_url` for image resolution |
| `ExcelExporter` | Enhanced Excel with rich text cells | openpyxl `CellRichText`, `InlineFont` |
| `BatchExporter` | Aggregate multiple exports into ZIP | zipfile module, streaming response |
| `ImageResolver` | Convert URL paths to local file paths | Parse `/files/<uuid>` URLs, map to `uploads/` |

---

## New Project Structure

```
/home/one/weekly/
├── app.py                  # (unchanged)
├── config.py               # (unchanged)
├── extensions.py           # (unchanged)
├── models.py               # (unchanged)
├── forms.py                # Add format field to RecordDownloadForm
├── routes.py               # Modify /download_records for multi-format
├── utils.py                # Keep DateRange, move RecordDownloader
├── exporters/              # NEW: Export functionality
│   ├── __init__.py         # ExporterFactory, ExporterBase
│   ├── base.py             # Abstract base class
│   ├── docx_exporter.py    # DOCX generation
│   ├── pdf_exporter.py     # PDF generation
│   ├── excel_exporter.py   # Enhanced Excel export
│   ├── batch.py            # Batch export orchestration
│   └── image_resolver.py   # Image path resolution
├── uploads/                # (unchanged) CKEditor images
├── templates/
│   └── manage_records.html # Add format selector to download form
└── tests/
    └── test_exporters.py   # NEW: Export tests
```

### Structure Rationale

- **`exporters/` module:** Follows existing flat module pattern, isolates export complexity
- **Separate files per format:** Each format has distinct dependencies and logic
- **`ImageResolver`:** Centralized image handling shared across DOCX/PDF exporters
- **No Blueprints:** Maintains D-01 decision (simple registration pattern)

---

## Architectural Patterns

### Pattern 1: Factory Pattern for Exporter Selection

**What:** Single entry point returns appropriate exporter based on format
**When to use:** Multiple export formats with similar interface
**Trade-offs:** Slight indirection, but enables easy format addition

```python
# exporters/__init__.py
class ExporterFactory:
    @staticmethod
    def get_exporter(format: str) -> 'ExporterBase':
        exporters = {
            'docx': DocxExporter,
            'pdf': PdfExporter,
            'xlsx': ExcelExporter,
        }
        if format not in exporters:
            raise ValueError(f"Unsupported format: {format}")
        return exporters[format]()

# Usage in routes.py
exporter = ExporterFactory.get_exporter(request.form.get('format', 'xlsx'))
return exporter.export(records, filename="周报")
```

### Pattern 2: Template Method for Common Export Flow

**What:** Base class defines algorithm skeleton, subclasses implement specific steps
**When to use:** Common preprocessing/postprocessing across formats
**Trade-offs:** Inheritance vs composition, keeps code DRY

```python
# exporters/base.py
from abc import ABC, abstractmethod
from io import BytesIO

class ExporterBase(ABC):
    def export(self, records, **options) -> BytesIO:
        """Template method defining export flow."""
        # Common preprocessing
        data = self._prepare_data(records, options)
        # Format-specific generation
        output = self._generate(data, options)
        return output

    @abstractmethod
    def _generate(self, data, options) -> BytesIO:
        """Format-specific generation logic."""
        pass

    def _prepare_data(self, records, options):
        """Common data preparation (override if needed)."""
        return records
```

### Pattern 3: Image Resolution Strategy

**What:** Convert CKEditor image URLs to embeddable content
**When to use:** HTML contains `<img src="/files/uuid_filename.jpg">`
**Trade-offs:** Requires filesystem access, handles missing images gracefully

```python
# exporters/image_resolver.py
import os
from urllib.parse import urlparse
from flask import current_app

class ImageResolver:
    def __init__(self, uploads_path: str):
        self.uploads_path = uploads_path

    def resolve_image_url(self, url: str) -> str:
        """Convert /files/<filename> URL to absolute path."""
        if url.startswith('/files/'):
            filename = url[7:]  # Remove '/files/' prefix
            return os.path.join(self.uploads_path, filename)
        return url  # External URL, return as-is

    def get_image_bytes(self, url: str) -> bytes:
        """Read image file contents for embedding."""
        local_path = self.resolve_image_url(url)
        if os.path.exists(local_path):
            with open(local_path, 'rb') as f:
                return f.read()
        return None  # Image not found
```

---

## Data Flow

### Single Record Export Flow

```
[User clicks export]
        |
        v
[POST /download_records]
        |-- format: docx|pdf|xlsx
        |-- user, groups, time_range filters
        v
[build_record_query()] --> Filtered Query
        |
        v
[ExporterFactory.get_exporter(format)]
        |
        v
[exporter.export(records, options)]
        |-- ImageResolver resolves <img src="/files/...">
        |-- Format-specific conversion
        v
[BytesIO returned]
        |
        v
[send_file(output, as_attachment=True)]
```

### Batch Export Flow

```
[User clicks "Batch Export Group"]
        |
        v
[POST /batch_export]
        |-- groups: [group_a, group_b]
        |-- time_range: this_month
        |-- format: docx
        v
[Query all users in selected groups]
        |
        v
[For each user]:
        |-- Query their records
        |-- Generate document
        |-- Add to ZIP with filename: {username}_{date}.docx
        v
[ZIP file generated in memory]
        |
        v
[send_file(zip_buffer, download_name="batch_export.zip")]
```

### Image Embedding Flow (DOCX)

```
[HTML content with <img src="/files/abc123.jpg">]
        |
        v
[BeautifulSoup parse HTML]
        |
        v
[For each <img> tag]:
        |-- Extract src attribute
        |-- ImageResolver.resolve_image_url(src) --> /path/uploads/abc123.jpg
        |-- Read image bytes
        |-- Create InlineShape with python-docx
        |-- Replace <img> tag with inline shape placeholder
        v
[Document with embedded images]
```

---

## Format-Specific Implementation Details

### DOCX Export (python-docx + htmldocx)

**Dependencies:** `python-docx`, `htmldocx`, `beautifulsoup4`

**Approach:**
1. Use `htmldocx.HtmlToDocx` for basic HTML-to-Docx conversion
2. Post-process to inject images from `<img>` tags
3. Handle lists, tables, code blocks via htmldocx

**Image Handling Challenge:** `htmldocx` does NOT support images. Must:
1. Parse HTML with BeautifulSoup first
2. Extract image URLs and positions
3. Run htmldocx conversion (images become empty)
4. Use python-docx to inject images at correct positions

**Code Pattern:**
```python
from docx import Document
from htmldocx import HtmlToDocx
from bs4 import BeautifulSoup

class DocxExporter(ExporterBase):
    def _generate(self, records, options) -> BytesIO:
        doc = Document()
        parser = HtmlToDocx()

        for record in records:
            # Pre-process HTML for images
            html = self._process_images(record.content, doc)
            # Convert remaining HTML
            parser.add_html_to_document(html, doc)

        output = BytesIO()
        doc.save(output)
        output.seek(0)
        return output
```

**Confidence:** MEDIUM - Image handling requires custom implementation

### PDF Export (WeasyPrint)

**Dependencies:** `weasyprint`, `pillow`

**Approach:**
1. Combine record HTML into single document
2. Pass `base_url` pointing to uploads directory
3. WeasyPrint resolves images automatically

**Key Configuration:**
```python
from weasyprint import HTML, CSS

class PdfExporter(ExporterBase):
    def _generate(self, records, options) -> BytesIO:
        # Combine HTML with embedded images
        combined_html = self._combine_records(records)

        # base_url enables relative image path resolution
        html = HTML(
            string=combined_html,
            base_url=f"file://{self.uploads_path}/"
        )

        output = BytesIO()
        html.write_pdf(output)
        output.seek(0)
        return output
```

**Image URL Transformation:**
WeasyPrint needs file:// URLs or absolute paths. Transform:
- `/files/abc123.jpg` -> `file:///path/to/uploads/abc123.jpg`

**Confidence:** HIGH - WeasyPrint designed for this use case

### Excel Export Enhancement (openpyxl)

**Dependencies:** `openpyxl` (already installed)

**Approach:**
1. Use `CellRichText` for multiple fonts in single cell
2. Parse HTML with BeautifulSoup
3. Convert `<strong>`, `<em>`, `<u>` to InlineFont variations

**Code Pattern:**
```python
from openpyxl.cell.rich_text import CellRichText, TextBlock
from openpyxl.cell.text import InlineFont

class ExcelExporter(ExporterBase):
    def _html_to_rich_text(self, html: str) -> CellRichText:
        soup = BeautifulSoup(html, 'html.parser')
        parts = []

        for element in soup.descendants:
            if element.name == 'strong':
                parts.append(TextBlock(
                    InlineFont(b=True),
                    element.get_text()
                ))
            elif element.name == 'em':
                parts.append(TextBlock(
                    InlineFont(i=True),
                    element.get_text()
                ))
            else:
                parts.append(element.get_text())

        return CellRichText(*parts)
```

**Limitations:**
- Images in Excel cells are complex, not recommended
- Focus on text formatting (bold, italic, colors)
- Keep existing `html_to_text()` as fallback

**Confidence:** MEDIUM - openpyxl rich text API is documented but less tested

---

## Batch Export Architecture

### Strategy: ZIP Archive with Streaming Response

**For small batches (< 20 users):** Generate all files in memory, return ZIP

```python
# exporters/batch.py
import zipfile
from io import BytesIO

class BatchExporter:
    def export_batch(self, users, time_range, format) -> BytesIO:
        exporter = ExporterFactory.get_exporter(format)
        zip_buffer = BytesIO()

        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            for user in users:
                records = self._get_user_records(user, time_range)
                doc_buffer = exporter.export(records)
                filename = f"{user.username}_{time_range}.{format}"
                zf.writestr(filename, doc_buffer.getvalue())

        zip_buffer.seek(0)
        return zip_buffer
```

**For large batches (> 20 users):** Consider background task

```python
# Alternative: Background task pattern (optional enhancement)
# 1. Create export job, return job_id immediately
# 2. Celery/task queue processes in background
# 3. User polls for completion, downloads from temp storage
# NOT RECOMMENDED for v1.2 - adds complexity
```

### Batch Export Route

```python
# routes.py addition
@app.route('/batch_export', methods=['POST'])
@login_required
def batch_export():
    format = request.form.get('format', 'docx')
    group_ids = request.form.getlist('groups')

    # Permission check
    allowed_groups = get_allowed_groups(current_user)
    groups_to_export = [g for g in allowed_groups if str(g.id) in group_ids]

    if not groups_to_export:
        abort(403)

    # Get all users from selected groups
    users = []
    for group in groups_to_export:
        users.extend(group.users)

    # Generate batch
    batch_exporter = BatchExporter(current_app.config['UPLOADED_PATH'])
    zip_buffer = batch_exporter.export_batch(users, time_range, format)

    return send_file(
        zip_buffer,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f"周报批量导出_{datetime.now().strftime('%Y%m%d')}.zip"
    )
```

---

## Scaling Considerations

| Scale | Architecture Adjustments |
|-------|--------------------------|
| 1-50 users (current) | In-memory generation, direct response |
| 50-200 users | Batch size limits, progress indicator |
| 200+ users | Background task queue (Celery), async generation |

### Current Scale Recommendation

The application serves 10-50 users. In-memory batch export is sufficient:
- Worst case: 50 users x 4 weeks x ~50KB = ~10MB ZIP
- Memory: < 50MB peak during generation
- Response time: < 5 seconds

**Do NOT implement:** Background tasks, async processing - premature optimization

---

## Anti-Patterns

### Anti-Pattern 1: Inline Conversion in Routes

**What people do:** Put all conversion logic directly in route handler
**Why it's wrong:** Routes become 200+ lines, hard to test, can't reuse
**Do this instead:** Create `exporters/` module with dedicated classes

### Anti-Pattern 2: Ignoring Missing Images

**What people do:** Skip broken image URLs silently
**Why it's wrong:** User sees blank spaces in exported documents, confusion
**Do this instead:** Log warnings, optionally insert placeholder text "[图片缺失]"

### Anti-Pattern 3: Synchronous Large Batch Exports

**What people do:** Generate 100+ documents synchronously
**Why it's wrong:** Request timeout (30s), user sees browser error
**Do this instead:** Limit batch size to 20 users, warn user for larger batches

### Anti-Pattern 4: External URL Dependencies for Images

**What people do:** Leave external image URLs as-is in exports
**Why it's wrong:** Images break when viewed offline, privacy concerns
**Do this instead:** Only embed local images from `uploads/`, strip external URLs

---

## Integration Points

### Existing Components to Modify

| Component | Modification | Risk |
|-----------|--------------|------|
| `routes.py` | Add format parameter to `/download_records` | Low |
| `forms.py` | Add format dropdown to `RecordDownloadForm` | Low |
| `manage_records.html` | Add format selector UI | Low |
| `requirements.txt` | Add `weasyprint`, `python-docx`, `htmldocx` | Low |

### New Components

| Component | Dependencies | Risk |
|-----------|--------------|------|
| `exporters/__init__.py` | None | Low |
| `exporters/docx_exporter.py` | python-docx, htmldocx, beautifulsoup4 | Medium (image handling) |
| `exporters/pdf_exporter.py` | weasyprint, pillow | Low |
| `exporters/excel_exporter.py` | openpyxl (existing) | Medium (rich text API) |
| `exporters/batch.py` | zipfile | Low |
| `exporters/image_resolver.py` | os, pathlib | Low |

---

## Build Order Recommendation

### Phase 1: Foundation (Low Risk)
1. Create `exporters/__init__.py` with `ExporterBase` and `ExporterFactory`
2. Create `exporters/image_resolver.py` for image path handling
3. Move existing `RecordDownloader` logic to `exporters/excel_exporter.py`
4. Update `requirements.txt` with new dependencies

### Phase 2: PDF Export (Highest Confidence)
1. Implement `PdfExporter` using WeasyPrint
2. Test with simple HTML (no images first)
3. Add image resolution with `base_url`
4. Integrate with route, add format parameter

### Phase 3: DOCX Export (Medium Confidence)
1. Implement `DocxExporter` with basic HTML conversion
2. Test with text, lists, tables
3. Add image embedding (requires custom code)
4. Handle edge cases (missing images, external URLs)

### Phase 4: Excel Enhancement (Medium Confidence)
1. Enhance `ExcelExporter` with `CellRichText`
2. Test bold, italic, underline conversions
3. Add as option alongside plain text export

### Phase 5: Batch Export (Low Risk)
1. Implement `BatchExporter` with ZIP generation
2. Add `/batch_export` route
3. Add batch UI to `manage_records.html`
4. Add batch size limits and warnings

---

## Sources

- **WeasyPrint Documentation:** https://doc.courtbouillon.org/weasyprint/stable/ (HIGH confidence)
- **WeasyPrint PyPI:** https://pypi.org/project/weasyprint/ (HIGH confidence, v68.1, 2026-02)
- **htmldocx PyPI:** https://pypi.org/project/htmldocx/ (MEDIUM confidence, v0.0.6, 2021-08)
- **html2docx PyPI:** https://pypi.org/project/html2docx/ (MEDIUM confidence)
- **python-docx PyPI:** https://pypi.org/project/python-docx/ (HIGH confidence)
- **openpyxl Documentation:** https://openpyxl.readthedocs.io/ (existing dependency)
- **Existing Architecture:** `.planning/codebase/ARCHITECTURE.md` (project-specific, HIGH confidence)

---

## Open Questions / Research Flags

| Topic | Confidence | Notes |
|-------|------------|-------|
| htmldocx image support | LOW | Documentation unclear, may need custom implementation |
| openpyxl CellRichText complexity | MEDIUM | Need to verify HTML-to-RichText conversion complexity |
| WeasyPrint base_url with Flask paths | MEDIUM | Test that `/files/` URLs resolve correctly |
| Batch export memory usage | MEDIUM | Profile with realistic data volumes |

---

*Architecture research for: Flask weekly report rich text export*
*Researched: 2026-03-26*