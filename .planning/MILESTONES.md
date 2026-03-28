# Milestones

## v1.3 AI (Shipped: 2026-03-28)

**Phases completed:** 5 phases, 17 plans, 34 tasks

**Key accomplishments:**

- Wave 0 scaffolding: cryptography dependency and test stubs for Phase 14 AI configuration features
- Fernet encryption helpers and AIConfig database model for secure API key storage with masked display
- WTForms form class with URL validation, required fields, and Chinese error messages for AI service configuration
- /ai-config route with admin permission check and AI configuration card in config.html for secure configuration management
- test_ai_connection function in ai_utils.py and test button handling in routes.py for verifying AI service availability before saving configuration
- TDD test scaffolds for AI API integration layer with 16 stub tests across 3 test classes
- Core AI API infrastructure with OpenAI-compatible POST /chat/completions, Chinese error messages, 30-second timeout, and audit logging without content exposure
- AI response processing with whitespace stripping and Markdown-to-HTML conversion using markdown library with extra/nl2br extensions for display-ready output
- Database model and WTForm for AI prompt template management with unique name validation and Chinese localization
- Template management CRUD routes with admin UI and default template auto-initialization
- Test scaffold with 16 stub tests defining expected behavior for fetch_user_records, assemble_prompt, generate_summary, and /generate-summary route
- Core summary generation logic: SummaryGenerationForm, fetch_user_records, assemble_prompt, and generate_summary with comprehensive test coverage
- 1. [Rule 3 - Blocking Issue] Missing dependency from Plan 17-01
- Text polish feature for report editor and filtered summary generation for team leaders with multi-user grouping

---

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
