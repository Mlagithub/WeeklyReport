# Milestones

## v1.2 增强富文本导出功能 (Shipped: 2026-03-28)

**Phases completed:** 6 phases, 22 plans, 40 tasks

**Key accomplishments:**

- ExporterBase/ExporterFactory/ImageResolver export architecture
- PdfExporter with WeasyPrint, headers/footers, image embedding
- DocxExporter with HTML-to-DOCX conversion
- ExcelExporter with CellRichText for bold/italic/underline
- Batch export ZIP for team leaders
- Code quality: 54 linting errors → 0, all functions CC < 10

---

## v1.1 UI Optimization (Shipped: 2026-03-28)

**Phases completed:** 2 phases, 4 plans, 6 tasks

**Key accomplishments:**

- 'last_7_days' time range in DateRange class
- Default user/time filters in find page template
- Server-side HTML sanitization with bleach
- XSS protection for homepage rendering

---

## v1.0 FixIOBug (Shipped: 2026-03-24)

**Phases completed:** 5 phases, 11 plans, 20 tasks

**Key accomplishments:**

- Gunicorn + systemd production deployment
- SQLite WAL mode for concurrent access
- @with_db_transaction decorator for session management
- pytest test infrastructure (122 tests, 88% coverage)
- Modular code structure (8 modules)

---