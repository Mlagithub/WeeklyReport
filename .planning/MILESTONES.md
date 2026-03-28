# Milestones

## v1.2 增强富文本导出功能 (Shipped: 2026-03-28)

**Phases completed:** 6 phases, 22 plans, 40 tasks

**Key accomplishments:**

- ExporterBase abstract class with template method pattern for unified export interface
- ExporterFactory with registry-based format selection
- ImageResolver for CKEditor image URL to filesystem path conversion
- PdfExporter with WeasyPrint, CSS headers/footers, and image embedding
- DocxExporter with HTML-to-DOCX conversion and embedded images
- ExcelExporter with HTML-to-CellRichText for bold, italic, underline formatting
- Batch export ZIP functionality for team leaders
- Code quality: 54 linting errors → 0, 3 high-CC functions → CC < 10
- pyproject.toml with ruff/black configuration for unified linting

---
