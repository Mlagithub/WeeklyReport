# Phase 11: Excel Enhancement - Research

**Researched:** 2026-03-26
**Domain:** openpyxl CellRichText for rich text in Excel cells
**Confidence:** HIGH (verified via local testing with openpyxl 3.1.5)

## Summary

Phase 11 enhances the existing Excel export functionality to support rich text formatting within cells. The current implementation in `utils.py` uses `html_to_text()` which strips all HTML formatting, converting CKEditor rich text to plain text. The solution uses openpyxl's `CellRichText`, `TextBlock`, and `InlineFont` classes to preserve bold, italic, underline, and strikethrough formatting.

**Primary recommendation:** Create an `ExcelExporter` class extending `ExporterBase` that converts HTML to `CellRichText` objects using BeautifulSoup for parsing, preserving inline formatting while maintaining the existing table structure (users as rows, weeks as columns).

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| XLSX-01 | Excel 导出支持富文本单元格（单元格内粗体、斜体等格式） | CellRichText API verified, HTML-to-RichText conversion approach tested |

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| openpyxl | 3.1.5 | Excel file generation | Already installed, industry standard, supports CellRichText |
| beautifulsoup4 | 4.12.3 | HTML parsing | Already installed, reliable for HTML traversal |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| lxml | 4.8.0 | XML/HTML parsing backend | Used by BeautifulSoup for faster parsing |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| CellRichText | Cell plain text | No formatting - defeats requirement |
| BeautifulSoup | html.parser (stdlib) | Slower, less robust for edge cases |
| Custom HTML parser | BeautifulSoup | More code, less tested |

**Installation:** Already installed - no new dependencies required.

**Version verification:**
```
openpyxl==3.1.5 (verified in requirements.txt)
beautifulsoup4==4.12.3 (already installed)
```

## Architecture Patterns

### Recommended Project Structure
```
exporters/
├── __init__.py           # ExporterFactory (update to register 'xlsx')
├── base.py               # ExporterBase (existing)
├── excel.py              # NEW: ExcelExporter with rich text support
├── pdf.py                # (existing)
├── docx.py               # (existing)
└── image_resolver.py     # (existing - not needed for Excel)
```

### Pattern 1: HTML-to-CellRichText Conversion

**What:** Parse HTML with BeautifulSoup, create TextBlock for each styled segment
**When to use:** Converting CKEditor HTML to Excel cell content
**Example:**
```python
from bs4 import BeautifulSoup, NavigableString
from openpyxl.cell.rich_text import CellRichText, TextBlock
from openpyxl.cell.text import InlineFont

def html_to_rich_text(html_content: str):
    """Convert HTML to CellRichText for openpyxl.

    Supports: <strong>, <b>, <em>, <i>, <u>, <s>, <del>
    """
    if not html_content:
        return ""

    soup = BeautifulSoup(html_content, 'html.parser')
    runs = []

    def process_node(node, styles=None):
        if styles is None:
            styles = {'bold': False, 'italic': False, 'underline': None, 'strike': False}

        if isinstance(node, NavigableString):
            text = str(node)
            if text.strip():
                font = InlineFont(
                    b=styles['bold'],
                    i=styles['italic'],
                    u=styles['underline'],  # 'single', 'double', or None
                    strike=styles['strike']
                )
                runs.append(TextBlock(font, text))
            return

        if node.name is None:
            for child in node.children:
                process_node(child, styles)
            return

        new_styles = styles.copy()

        # Map HTML tags to font properties
        if node.name in ('strong', 'b'):
            new_styles['bold'] = True
        elif node.name in ('em', 'i'):
            new_styles['italic'] = True
        elif node.name == 'u':
            new_styles['underline'] = 'single'  # MUST be string, not boolean!
        elif node.name in ('s', 'strike', 'del'):
            new_styles['strike'] = True

        for child in node.children:
            process_node(child, new_styles)

    for child in soup.children:
        process_node(child)

    if not runs:
        return soup.get_text()  # Fallback to plain text

    return CellRichText(*runs)
```

### Pattern 2: ExcelExporter Class Structure

**What:** Follow existing ExporterBase pattern, integrate with factory
**When to use:** Implementing Phase 11
**Example:**
```python
# exporters/excel.py
from openpyxl import Workbook
from openpyxl.styles import Font, Alignment, PatternFill, Border, Side
from openpyxl.cell.rich_text import CellRichText, TextBlock
from openpyxl.cell.text import InlineFont
from io import BytesIO
from typing import List, Dict, Any, Optional
from bs4 import BeautifulSoup, NavigableString

from .base import ExporterBase

class ExcelExporter(ExporterBase):
    """Excel exporter with rich text cell support."""

    def __init__(self, uploads_path: Optional[str] = None):
        self._uploads_path = uploads_path

    @property
    def file_extension(self) -> str:
        return 'xlsx'

    @property
    def mime_type(self) -> str:
        return 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'

    def _generate(self, records: List[Any], options: Dict) -> BytesIO:
        # Group records by user and week (same as existing RecordDownloader)
        # For each cell, use html_to_rich_text() instead of html_to_text()
        # Return BytesIO with .xlsx content
        pass

    def _html_to_rich_text(self, html: str):
        """Convert HTML to CellRichText for cell value."""
        # Implementation from Pattern 1
        pass
```

### Anti-Patterns to Avoid

- **Setting underline as boolean:** `InlineFont(u=True)` throws ValueError - must use `'single'` or `'double'`
- **Ignoring nested formatting:** `<strong>Bold <em>and italic</em></strong>` requires recursive processing
- **Stripping all HTML:** Defeats the purpose of this phase - must preserve formatting
- **Creating new ExporterBase:** Use existing pattern from `exporters/base.py`

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| HTML parsing | Custom regex/string manipulation | BeautifulSoup | Handles edge cases, nested elements, encoding |
| Excel file creation | Manual XML generation | openpyxl | OOXML spec is complex, openpyxl handles it |
| Font styling | Custom font objects | InlineFont | Proper XML serialization built-in |

**Key insight:** openpyxl's rich text API is well-designed and requires minimal wrapper code.

## Common Pitfalls

### Pitfall 1: Underline Property Value Type

**What goes wrong:** Setting `InlineFont(u=True)` raises `ValueError: Value must be one of {'double', 'doubleAccounting', 'singleAccounting', 'single'}`

**Why it happens:** The `u` (underline) property expects specific string values, not a boolean like `b` (bold) or `i` (italic).

**How to avoid:**
```python
# WRONG
InlineFont(u=True)  # ValueError!

# CORRECT
InlineFont(u='single')  # Single underline
InlineFont(u='double')  # Double underline
InlineFont(u=None)      # No underline (default)
```

**Warning signs:** Test failures with underline HTML tags, ValueError during export.

### Pitfall 2: Nested HTML Elements Not Handled

**What goes wrong:** `<strong>Bold with <em>italic</em> inside</strong>` loses formatting or duplicates text.

**Why it happens:** Non-recursive processing only captures top-level elements, missing nested combinations.

**How to avoid:** Use recursive processing that passes style state down the tree (see Pattern 1 example).

**Warning signs:** Bold-italic combinations show as plain text, nested formatting lost.

### Pitfall 3: Empty TextBlocks in CellRichText

**What goes wrong:** CellRichText with empty strings causes display issues or exceptions.

**Why it happens:** Whitespace-only nodes create empty TextBlocks.

**How to avoid:** Check `text.strip()` before adding to runs list.

**Warning signs:** Excel displays empty cells or shows errors when opening file.

### Pitfall 4: Not Registering with Factory

**What goes wrong:** `ExporterFactory.get_exporter('xlsx')` raises ValueError after implementation.

**Why it happens:** Forgetting to add registration in `exporters/__init__.py`.

**How to avoid:**
```python
# exporters/__init__.py - add these lines
from .excel import ExcelExporter
ExporterFactory.register('xlsx', ExcelExporter)
```

**Warning signs:** Tests pass but route integration fails.

## Code Examples

### Verified Pattern: Basic Rich Text Cell

```python
from openpyxl import Workbook
from openpyxl.cell.rich_text import CellRichText, TextBlock
from openpyxl.cell.text import InlineFont

wb = Workbook()
ws = wb.active

# Create fonts
bold_font = InlineFont(b=True)
italic_font = InlineFont(i=True)
normal_font = InlineFont()

# Create rich text cell
ws['A1'].value = CellRichText(
    TextBlock(bold_font, "Bold text"),
    " and normal text ",
    TextBlock(italic_font, "and italic")
)

# Result: "Bold text and normal text and italic" with formatting preserved
```

### Verified Pattern: Combined Bold+Italic

```python
# Combined styles
combined_font = InlineFont(b=True, i=True)
ws['A2'].value = CellRichText(
    TextBlock(combined_font, "Bold and italic together")
)
```

### Verified Pattern: HTML-to-CellRichText (tested)

```python
from bs4 import BeautifulSoup, NavigableString
from openpyxl.cell.rich_text import CellRichText, TextBlock
from openpyxl.cell.text import InlineFont

def html_to_rich_text(html_content: str):
    """Convert HTML to CellRichText - tested with CKEditor output."""
    if not html_content:
        return ""

    soup = BeautifulSoup(html_content, 'html.parser')
    runs = []

    def process_node(node, styles=None):
        if styles is None:
            styles = {'bold': False, 'italic': False, 'underline': None, 'strike': False}

        if isinstance(node, NavigableString):
            text = str(node)
            if text.strip():
                font = InlineFont(
                    b=styles['bold'],
                    i=styles['italic'],
                    u=styles['underline'],
                    strike=styles['strike']
                )
                runs.append(TextBlock(font, text))
            return

        if node.name is None:
            for child in node.children:
                process_node(child, styles)
            return

        new_styles = styles.copy()

        if node.name in ('strong', 'b'):
            new_styles['bold'] = True
        elif node.name in ('em', 'i'):
            new_styles['italic'] = True
        elif node.name == 'u':
            new_styles['underline'] = 'single'
        elif node.name in ('s', 'strike', 'del'):
            new_styles['strike'] = True

        for child in node.children:
            process_node(child, new_styles)

    for child in soup.children:
        process_node(child)

    if not runs:
        return soup.get_text()

    return CellRichText(*runs)

# Test cases verified:
# html_to_rich_text("<strong>Bold</strong>") -> CellRichText with bold
# html_to_rich_text("<em>Italic</em>") -> CellRichText with italic
# html_to_rich_text("<strong>Bold <em>italic</em></strong>") -> Nested formatting works
```

## Supported HTML Tags

Based on `ALLOWED_TAGS` in `app.py`:

| HTML Tag | InlineFont Property | Notes |
|----------|---------------------|-------|
| `<strong>`, `<b>` | `b=True` | Bold |
| `<em>`, `<i>` | `i=True` | Italic |
| `<u>` | `u='single'` | Underline (must be string) |
| `<s>`, `<del>` | `strike=True` | Strikethrough |
| `<p>`, `<span>`, `<div>` | No style change | Container elements |
| `<br>` | Newline in text | Handled by BeautifulSoup |
| `<ul>`, `<ol>`, `<li>` | Plain text with bullets | Convert to bullet/number format |
| `<a>` | Plain text (link lost) | No hyperlink support in CellRichText |
| `<img>` | Skip | Images not supported inline |
| `<h1>`-`<h6>` | Bold + larger | Convert to bold text |
| `<blockquote>` | Indent prefix | Add ">" prefix |
| `<pre>`, `<code>` | Monospace font | Could use `rFont` property |

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `html_to_text()` strips all formatting | `CellRichText` preserves formatting | Phase 11 | Users see formatted content in Excel |

**Deprecated/outdated:**
- `html_to_text()` in `utils.py`: Still exists for backward compatibility, but ExcelExporter should use new approach.

## Open Questions

1. **How to handle lists (`<ul>`, `<ol>`)?**
   - What we know: Current `html_to_text()` converts lists to bullet/number format.
   - What's unclear: Should rich text cells preserve list formatting visually?
   - Recommendation: Keep existing list-to-text conversion from `utils.py`, but wrap result in CellRichText for consistency.

2. **How to handle hyperlinks (`<a>`)?**
   - What we know: CellRichText does not support hyperlinks inline with other text.
   - What's unclear: Should we show URL in parentheses? Skip entirely?
   - Recommendation: Show link text only (lose URL), or append URL in parentheses like "Link Text (https://...)". Document decision in code.

3. **Should we update existing RecordDownloader or create new ExcelExporter?**
   - What we know: RecordDownloader is a static class in `utils.py`.
   - Recommendation: Create new `ExcelExporter` class following the established pattern, keep `RecordDownloader` for backward compatibility during transition.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | pytest (existing) |
| Config file | tests/conftest.py |
| Quick run command | `pytest tests/test_exporters.py -x -v` |
| Full suite command | `pytest tests/ -v` |

### Phase Requirements -> Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|--------------|
| XLSX-01 | Rich text cells display bold/italic | unit | `pytest tests/test_exporters.py::TestExcelExporter -x` | No - Wave 0 |

### Sampling Rate
- **Per task commit:** `pytest tests/test_exporters.py -x -q`
- **Per wave merge:** `pytest tests/test_exporters.py -v`
- **Phase gate:** Full exporter test suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `tests/test_exporters.py` - Add `TestExcelExporter` class with tests for:
  - `test_file_extension` returns 'xlsx'
  - `test_mime_type` returns correct MIME
  - `test_export_returns_bytesio` with valid XLSX (ZIP magic bytes)
  - `test_html_to_rich_text_bold` converts `<strong>` correctly
  - `test_html_to_rich_text_italic` converts `<em>` correctly
  - `test_html_to_rich_text_nested` handles nested formatting
  - `test_rich_text_in_cell` verifies cell value is CellRichText

## Sources

### Primary (HIGH confidence)
- openpyxl 3.1.5 installed locally - CellRichText, TextBlock, InlineFont API verified via Python help() and runtime testing
- `/home/one/weekly/utils.py` - existing `RecordDownloader` implementation to reference
- `/home/one/weekly/exporters/base.py` - ExporterBase pattern to follow

### Secondary (MEDIUM confidence)
- `/home/one/weekly/.planning/research/STACK.md` - confirmed openpyxl rich text support
- `/home/one/weekly/.planning/research/ARCHITECTURE.md` - integration patterns

### Tertiary (LOW confidence)
- None - all findings verified locally

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - openpyxl 3.1.5 verified installed and tested
- Architecture: HIGH - existing ExporterBase pattern is clear
- Pitfalls: HIGH - tested underline gotcha, verified solution

**Research date:** 2026-03-26
**Valid until:** 30 days (openpyxl API stable)