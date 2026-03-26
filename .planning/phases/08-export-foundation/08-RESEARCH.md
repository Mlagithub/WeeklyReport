# Phase 8: Export Foundation - Research

**Researched:** 2026-03-26
**Domain:** Flask export architecture, document generation libraries
**Confidence:** HIGH

## Summary

Phase 8 establishes the architectural foundation for multi-format document exports (PDF, DOCX, enhanced Excel). The existing Flask application uses a flat module structure without Blueprints (per D-01) and currently exports Excel files via `RecordDownloader` in `utils.py`. The recommended approach creates a dedicated `exporters/` module with an abstract base class (`ExporterBase`), a factory pattern for format selection, and a centralized `ImageResolver` for converting CKEditor image URLs to filesystem paths.

The phase has no direct user-facing requirements - it creates reusable infrastructure for Phases 9-12. Key dependencies (python-docx 1.2.0, WeasyPrint 68.1, htmldocx 0.0.6) are verified as current. System dependencies for WeasyPrint (libpango, libharfbuzz, libpangoft2) are already installed on the target system.

**Primary recommendation:** Create `exporters/` module with abstract base class, factory, and image resolver before implementing format-specific exporters.

---

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| python-docx | 1.2.0 | DOCX file creation | Industry standard, active maintenance (June 2025 release), supports all formatting elements |
| WeasyPrint | 68.1 | HTML to PDF conversion | Pure Python, active maintenance, best CSS Paged Media support |
| htmldocx | 0.0.6 | HTML to DOCX bridge | Works with python-docx for HTML conversion (unmaintained since 2021, but functional) |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| openpyxl | 3.1.5 | Excel operations | Already installed, will use CellRichText for rich text cells |
| beautifulsoup4 | 4.12.3 | HTML parsing | Already installed, used for image extraction from HTML |
| lxml | 4.8.0 | XML parsing | Already installed, required by python-docx |
| Pillow | 11.0.0 | Image processing | Already installed, required by WeasyPrint |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| htmldocx | html2docx | html2docx has better maintenance but less documentation; htmldocx is proven with python-docx |
| WeasyPrint | wkhtmltopdf | wkhtmltopdf archived in 2023, requires external binary; WeasyPrint is pure Python |
| WeasyPrint | xhtml2pdf | xhtml2pdf has limited CSS support; WeasyPrint supports CSS Paged Media |

**Installation:**

```bash
pip install python-docx==1.2.0 weasyprint==68.1 htmldocx==0.0.6
```

**Version verification:**
- python-docx 1.2.0 (PyPI, verified 2026-03-26)
- WeasyPrint 68.1 (PyPI, verified 2026-03-26)
- htmldocx 0.0.6 (PyPI, verified 2026-03-26)

---

## Architecture Patterns

### Recommended Project Structure

```
/home/one/weekly/
├── exporters/              # NEW: Export functionality module
│   ├── __init__.py         # ExporterFactory, exports
│   ├── base.py             # ExporterBase abstract class
│   └── image_resolver.py   # Image URL to path conversion
├── utils.py                # Keep DateRange, RecordDownloader (moved in Phase 11)
├── routes.py               # /download_records route (modified in Phase 9)
├── forms.py                # RecordDownloadForm (add format field in Phase 9)
└── requirements.txt        # Add export dependencies
```

**Rationale:**
- `exporters/` module follows existing flat module pattern
- No Blueprints (maintains D-01 decision)
- ImageResolver centralized for reuse across PDF/DOCX exporters
- Base class and factory in separate files for clarity

### Pattern 1: Abstract Base Class (ExporterBase)

**What:** Define common interface for all exporters with template method pattern
**When to use:** Multiple export formats with similar workflow
**Example:**

```python
# exporters/base.py
from abc import ABC, abstractmethod
from io import BytesIO
from typing import List, Dict, Any

class ExporterBase(ABC):
    """Abstract base class for document exporters.

    Implements template method pattern for common export flow.
    """

    def export(self, records: List[Any], **options) -> BytesIO:
        """Template method defining export flow.

        Args:
            records: List of Record objects to export
            **options: Format-specific options (filename, title, etc.)

        Returns:
            BytesIO buffer containing the generated document
        """
        # Common preprocessing
        data = self._prepare_data(records, options)
        # Format-specific generation
        output = self._generate(data, options)
        return output

    @abstractmethod
    def _generate(self, data: List[Any], options: Dict) -> BytesIO:
        """Format-specific generation logic.

        Must be implemented by subclasses.
        """
        pass

    def _prepare_data(self, records: List[Any], options: Dict) -> List[Any]:
        """Common data preparation (override if needed).

        Default implementation returns records unchanged.
        """
        return records

    @property
    @abstractmethod
    def file_extension(self) -> str:
        """Return file extension without dot (e.g., 'pdf', 'docx')."""
        pass

    @property
    @abstractmethod
    def mime_type(self) -> str:
        """Return MIME type for send_file()."""
        pass
```

**Source:** Template Method pattern from ARCHITECTURE.md research

### Pattern 2: Factory Pattern (ExporterFactory)

**What:** Single entry point returns appropriate exporter based on format
**When to use:** Multiple export formats with similar interface
**Example:**

```python
# exporters/__init__.py
from typing import Type
from .base import ExporterBase

class ExporterFactory:
    """Factory for creating format-specific exporters.

    Usage:
        exporter = ExporterFactory.get_exporter('pdf')
        output = exporter.export(records, title='Weekly Report')
    """

    _registry: Dict[str, Type[ExporterBase]] = {}

    @classmethod
    def register(cls, format: str, exporter_class: Type[ExporterBase]):
        """Register an exporter class for a format."""
        cls._registry[format.lower()] = exporter_class

    @classmethod
    def get_exporter(cls, format: str) -> ExporterBase:
        """Get an exporter instance for the specified format.

        Args:
            format: Format identifier ('pdf', 'docx', 'xlsx')

        Returns:
            Exporter instance

        Raises:
            ValueError: If format is not supported
        """
        format_lower = format.lower()
        if format_lower not in cls._registry:
            raise ValueError(f"Unsupported export format: {format}")
        return cls._registry[format_lower]()

    @classmethod
    def supported_formats(cls) -> List[str]:
        """Return list of supported format identifiers."""
        return list(cls._registry.keys())


# Register exporters as they are implemented (Phases 9-11)
# ExporterFactory.register('pdf', PdfExporter)
# ExporterFactory.register('docx', DocxExporter)
# ExporterFactory.register('xlsx', ExcelExporter)
```

**Source:** Factory pattern from ARCHITECTURE.md research

### Pattern 3: Image Resolution (ImageResolver)

**What:** Convert CKEditor image URLs to filesystem paths for embedding
**When to use:** HTML content contains `<img src="/files/uuid_filename.jpg">`
**Example:**

```python
# exporters/image_resolver.py
import os
from typing import Optional, Tuple
from urllib.parse import urlparse
from flask import current_app

class ImageResolver:
    """Resolve CKEditor image URLs to filesystem paths.

    CKEditor uploads images via /upload route, stores in uploads/
    directory with UUID-prefixed filenames, and references them
    via /files/<filename> route.

    This class converts web URLs to absolute paths for embedding
    in exported documents.
    """

    def __init__(self, uploads_path: str):
        """Initialize with uploads directory path.

        Args:
            uploads_path: Absolute path to uploads directory
        """
        self.uploads_path = uploads_path

    def resolve_url(self, url: str) -> Optional[str]:
        """Convert /files/<filename> URL to absolute filesystem path.

        Args:
            url: Image URL from HTML src attribute

        Returns:
            Absolute filesystem path if local image, None if external/invalid
        """
        if not url:
            return None

        # Handle /files/ prefix for local uploads
        if url.startswith('/files/'):
            filename = url[7:]  # Remove '/files/' prefix
            return os.path.join(self.uploads_path, filename)

        # External URLs return None (not embedded)
        if url.startswith(('http://', 'https://')):
            return None

        return None

    def get_image_bytes(self, url: str) -> Optional[bytes]:
        """Read image file contents for embedding.

        Args:
            url: Image URL from HTML

        Returns:
            Image bytes if found, None if missing or external
        """
        local_path = self.resolve_url(url)
        if local_path and os.path.exists(local_path):
            with open(local_path, 'rb') as f:
                return f.read()
        return None

    def resolve_for_weasyprint(self, url: str) -> str:
        """Convert URL to format suitable for WeasyPrint base_url.

        WeasyPrint needs file:// URLs for local images.

        Args:
            url: Image URL from HTML

        Returns:
            file:// URL for local images, original URL for external
        """
        local_path = self.resolve_url(url)
        if local_path and os.path.exists(local_path):
            return f"file://{local_path}"
        return url

    def image_exists(self, url: str) -> bool:
        """Check if image file exists locally.

        Args:
            url: Image URL from HTML

        Returns:
            True if file exists, False otherwise
        """
        local_path = self.resolve_url(url)
        return local_path is not None and os.path.exists(local_path)
```

**Source:** ImageResolver pattern from ARCHITECTURE.md research

### Anti-Patterns to Avoid

- **Inline conversion in routes:** Don't put export logic directly in route handlers - routes become 200+ lines, hard to test, can't reuse. Use `exporters/` module.
- **Ignoring missing images:** Don't skip broken image URLs silently - user sees blank spaces. Log warnings, optionally insert placeholder "[图片缺失]".
- **External URL dependencies:** Don't leave external image URLs as-is in exports - images break offline. Only embed local images from `uploads/`.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| HTML to PDF conversion | Custom HTML parser + PDF library | WeasyPrint | Handles CSS, images, tables, complex layouts |
| DOCX generation | XML manipulation | python-docx | Handles document structure, styles, images |
| HTML to DOCX conversion | Custom HTML parser | htmldocx | Handles common HTML elements (fallback to custom if needed) |
| Image path resolution | String manipulation in each exporter | ImageResolver class | Centralized, handles edge cases, testable |

**Key insight:** Document generation has many edge cases (encoding, images, tables, lists). Use established libraries, don't reinvent.

---

## Common Pitfalls

### Pitfall 1: Image Path Resolution Failure

**What goes wrong:** CKEditor stores images as `/files/<uuid>` but export libraries need absolute paths or file:// URLs
**Why it happens:** Web URLs don't map directly to filesystem paths
**How to avoid:** Create `ImageResolver` utility in Phase 8, use consistently in all exporters
**Warning signs:** Blank images in exports, FileNotFoundError exceptions

### Pitfall 2: Missing System Dependencies

**What goes wrong:** WeasyPrint fails with "Could not load Pango" or similar errors
**Why it happens:** WeasyPrint requires system libraries (libpango, libharfbuzz, libpangoft2)
**How to avoid:** Verify system dependencies before installing Python packages
**Warning signs:** ImportError, font-related errors, blank PDFs

**Verification (already confirmed on target system):**
```
ii  libharfbuzz0b:amd64    2.7.4-1ubuntu3.2
ii  libpango-1.0-0:amd64   1.50.6+ds-2ubuntu1
ii  libpangocairo-1.0-0    1.50.6+ds-2ubuntu1
ii  libpangoft2-1.0-0      1.50.6+ds-2ubuntu1
```

### Pitfall 3: htmldocx Image Handling

**What goes wrong:** htmldocx ignores `<img>` tags, images missing in DOCX output
**Why it happens:** htmldocx only handles text elements, not images
**How to avoid:** Pre-process HTML with BeautifulSoup, extract images, inject via python-docx
**Warning signs:** Empty spaces where images should be

---

## Code Examples

### ExporterBase Abstract Class

```python
# exporters/base.py
from abc import ABC, abstractmethod
from io import BytesIO
from typing import List, Dict, Any

class ExporterBase(ABC):
    """Abstract base class for document exporters."""

    def export(self, records: List[Any], **options) -> BytesIO:
        """Template method for export flow."""
        data = self._prepare_data(records, options)
        output = self._generate(data, options)
        return output

    @abstractmethod
    def _generate(self, data: List[Any], options: Dict) -> BytesIO:
        """Format-specific generation. Implement in subclasses."""
        pass

    @property
    @abstractmethod
    def file_extension(self) -> str:
        """File extension without dot."""
        pass

    @property
    @abstractmethod
    def mime_type(self) -> str:
        """MIME type for response."""
        pass
```

### ImageResolver Implementation

```python
# exporters/image_resolver.py
import os
from typing import Optional

class ImageResolver:
    """Convert CKEditor image URLs to filesystem paths."""

    def __init__(self, uploads_path: str):
        self.uploads_path = uploads_path

    def resolve_url(self, url: str) -> Optional[str]:
        """Convert /files/<filename> to absolute path."""
        if not url:
            return None
        if url.startswith('/files/'):
            filename = url[7:]
            return os.path.join(self.uploads_path, filename)
        return None

    def get_image_bytes(self, url: str) -> Optional[bytes]:
        """Read image file for embedding."""
        local_path = self.resolve_url(url)
        if local_path and os.path.exists(local_path):
            with open(local_path, 'rb') as f:
                return f.read()
        return None
```

### ExporterFactory Usage

```python
# exporters/__init__.py
from typing import Dict, Type

class ExporterFactory:
    _registry: Dict[str, Type['ExporterBase']] = {}

    @classmethod
    def register(cls, format: str, exporter_class: Type['ExporterBase']):
        cls._registry[format.lower()] = exporter_class

    @classmethod
    def get_exporter(cls, format: str) -> 'ExporterBase':
        if format.lower() not in cls._registry:
            raise ValueError(f"Unsupported format: {format}")
        return cls._registry[format.lower()]()

    @classmethod
    def supported_formats(cls) -> list:
        return list(cls._registry.keys())
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| wkhtmltopdf for PDF | WeasyPrint | 2023 (wkhtmltopdf archived) | Pure Python, no external binary |
| Inline export in routes | Dedicated exporters/ module | Phase 8 | Testable, reusable, maintainable |
| Image paths in each exporter | Centralized ImageResolver | Phase 8 | DRY, consistent handling |

**Deprecated/outdated:**
- **wkhtmltopdf:** Archived in 2023, requires external binary - use WeasyPrint instead
- **xhtml2pdf:** Limited CSS support, poor maintenance - use WeasyPrint instead

---

## Open Questions

1. **htmldocx image support**
   - What we know: htmldocx does NOT support images, requires custom handling
   - What's unclear: Exact injection point after HTML-to-Docx conversion
   - Recommendation: Prototype early in Phase 10, prepare fallback custom HTML parser

2. **WeasyPrint base_url configuration**
   - What we know: WeasyPrint can resolve relative URLs with base_url parameter
   - What's unclear: Best approach for /files/ URLs (file:// prefix vs base_url)
   - Recommendation: Test both approaches, use ImageResolver.resolve_for_weasyprint()

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| python-docx | DOCX export | Need install | 1.2.0 | - |
| WeasyPrint | PDF export | Need install | 68.1 | - |
| htmldocx | HTML-to-DOCX | Need install | 0.0.6 | Custom parser |
| libpango | WeasyPrint | Yes | 1.50.6 | - |
| libharfbuzz | WeasyPrint | Yes | 2.7.4 | - |
| libpangoft2 | WeasyPrint | Yes | 1.50.6 | - |
| openpyxl | Excel export | Yes | 3.1.5 | - |
| beautifulsoup4 | HTML parsing | Yes | 4.12.3 | - |

**Missing dependencies with no fallback:**
- None - all required dependencies have clear installation paths

**Missing dependencies with fallback:**
- htmldocx: If critical issues found, can build custom HTML-to-DOCX converter using python-docx directly (higher effort)

---

## Integration Points with Existing Code

### Existing Components

| Component | Location | Current State | Phase 8 Change |
|-----------|----------|---------------|----------------|
| `RecordDownloader` | `utils.py` | Excel export | No change (moved in Phase 11) |
| `/download_records` | `routes.py` | Excel only | No change (format param in Phase 9) |
| `RecordDownloadForm` | `forms.py` | Submit only | No change (format dropdown in Phase 9) |
| `UPLOADED_PATH` | `config.py` | Configured | Used by ImageResolver |
| `/files/<filename>` | `routes.py` | Serves uploads | Source for ImageResolver |

### New Components

| Component | Dependencies | Risk |
|-----------|--------------|------|
| `exporters/__init__.py` | None | Low |
| `exporters/base.py` | None | Low |
| `exporters/image_resolver.py` | os, pathlib | Low |

### Key Configuration

```python
# config.py (existing)
UPLOADED_PATH = os.path.join(basedir, 'uploads')

# ImageResolver will use this path
resolver = ImageResolver(app.config['UPLOADED_PATH'])
```

### CKEditor Image URL Pattern

```
Upload: POST /upload --> saves to {UPLOADED_PATH}/{uuid}_{filename}
Reference: <img src="/files/{uuid}_{filename}"> in HTML
Serve: GET /files/{filename} --> send_from_directory(UPLOADED_PATH, filename)
```

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
| INFRA-01 | ExporterBase defines abstract interface | unit | `pytest tests/test_exporters.py::TestExporterBase -v` | Wave 0 |
| INFRA-02 | ExporterFactory returns correct exporter | unit | `pytest tests/test_exporters.py::TestExporterFactory -v` | Wave 0 |
| INFRA-03 | ImageResolver converts /files/ URLs | unit | `pytest tests/test_exporters.py::TestImageResolver -v` | Wave 0 |
| INFRA-04 | Dependencies installed correctly | integration | `pytest tests/test_exporters.py::TestDependencies -v` | Wave 0 |

### Sampling Rate

- **Per task commit:** `pytest tests/ -v -x`
- **Per wave merge:** `pytest tests/ -v --cov=.`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps

- [ ] `tests/test_exporters.py` - Test ExporterBase, ExporterFactory, ImageResolver
- [ ] No shared fixtures needed beyond existing conftest.py
- [x] Framework installed: pytest 8.3.5

---

## Sources

### Primary (HIGH confidence)

- PyPI API - python-docx 1.2.0, WeasyPrint 68.1, htmldocx 0.0.6 versions verified
- `.planning/research/SUMMARY.md` - Milestone research with library recommendations
- `.planning/research/ARCHITECTURE.md` - Export architecture patterns
- `.planning/codebase/STRUCTURE.md` - Project structure and conventions

### Secondary (MEDIUM confidence)

- `.planning/STATE.md` - Project decisions (D-01: no Blueprints, D-11: UUID filenames)
- Existing codebase - `utils.py`, `routes.py`, `config.py` analyzed
- System package verification - libpango, libharfbuzz confirmed installed

### Tertiary (LOW confidence)

- htmldocx documentation - Limited, unmaintained since 2021

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - Versions verified via PyPI, dependencies analyzed
- Architecture: HIGH - Patterns documented in ARCHITECTURE.md, aligns with existing code
- Pitfalls: HIGH - Based on official docs and GitHub issues

**Research date:** 2026-03-26
**Valid until:** 30 days (stable libraries)