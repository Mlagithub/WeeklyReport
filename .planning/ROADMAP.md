# Roadmap: 周报管理系统

## Milestones

- **v1.2 增强富文本导出功能** — Phases 8-12 (current)
- **v1.1 UI Optimization** — Phases 6-7 (in progress)
- **v1.3 Code Quality** — Phase 13 (planned)
- **v1.0 FixIOBug** — Phases 1-5 (shipped 2026-03-24)

## Phases

### v1.2 增强富文本导出功能 (Current)

- [x] **Phase 8: Export Foundation** - 导出架构基础设施
- [x] **Phase 9: PDF Export** - PDF 格式导出完整功能
- [x] **Phase 10: DOCX Export** - Word 格式导出完整功能
- [x] **Phase 11: Excel Enhancement** - Excel 富文本单元格支持
- [ ] **Phase 12: Batch Export** - 团队领导批量导出功能

<details>
<summary>v1.1 UI Optimization (Phases 6-7) — In Progress</summary>

- [x] Phase 6: Find Page Filtering (1/2 plans) — 默认过滤减少信息过载
- [ ] Phase 7: Homepage Rendering (0/2 plans) — 富文本渲染与 XSS 防护

</details>

<details>
<summary>**v1.3 Code Quality (Phase 13) — Planned**</summary>

- [ ] Phase 13: Comprehensive Code Review (0/5 plans) — Linting, complexity reduction, code cleanup

</details>

<details>
<summary>✅ v1.0 FixIOBug (Phases 1-5) — SHIPPED 2026-03-24</summary>

- [x] Phase 1: Production WSGI Server (3/3 plans) — Gunicorn + systemd
- [x] Phase 2: Session Management (1/1 plan) — @with_db_transaction decorator
- [x] Phase 3: SQLite Optimization (1/1 plan) — WAL mode
- [x] Phase 4: Unit Testing (3/3 plans) — 62 tests, 68% coverage
- [x] Phase 5: Code Refactoring (3/3 plans) — Modular structure

</details>

## Phase Details

### Phase 8: Export Foundation
**Goal**: 建立导出功能的架构基础，为后续格式导出提供可复用组件
**Depends on**: Phase 7 (v1.1 complete)
**Requirements**: None (infrastructure phase)
**Success Criteria** (what must be TRUE):
  1. 项目依赖已更新，包含 python-docx、WeasyPrint 等导出库
  2. exporters/ 模块已创建，包含 ExporterBase 抽象基类
  3. ImageResolver 工具类可将 CKEditor 图片 URL 转换为文件系统路径
  4. ExporterFactory 可根据格式参数返回对应的导出器实例
**Plans**: 5 plans (Wave 0: test scaffolding, Wave 1: infrastructure)

Plans:
- [x] 08-00-PLAN.md — Wave 0: Test scaffolding for exporters module
- [x] 08-01-PLAN.md — Wave 1: Update requirements.txt with export dependencies
- [x] 08-02-PLAN.md — Wave 1: Create ExporterBase abstract class
- [x] 08-03-PLAN.md — Wave 1: Create ExporterFactory
- [x] 08-04-PLAN.md — Wave 1: Create ImageResolver utility

### Phase 9: PDF Export
**Goal**: 用户可将周报导出为保留完整格式的 PDF 文件
**Depends on**: Phase 8
**Requirements**: PDF-01, PDF-02, PDF-03
**Success Criteria** (what must be TRUE):
  1. 用户点击导出按钮可选择 PDF 格式下载周报
  2. 导出的 PDF 正确渲染富文本格式（粗体、斜体、列表、表格、标题、链接）
  3. 导出的 PDF 包含嵌入的图片，离线可查看
  4. PDF 文档包含页眉（文档标题）和页脚（页码、日期）
**Plans**: 3 plans (Wave 0: test scaffolding, Wave 1: PdfExporter, Wave 2: integration)

Plans:
- [x] 09-00-PLAN.md — Wave 0: Test scaffolding for PdfExporter
- [x] 09-01-PLAN.md — Wave 1: Create PdfExporter with image embedding and headers/footers
- [x] 09-02-PLAN.md — Wave 2: Route and form integration

### Phase 10: DOCX Export
**Goal**: 用户可将周报导出为可编辑的 Word 文档，保留完整格式
**Depends on**: Phase 8
**Requirements**: DOCX-01, DOCX-02
**Success Criteria** (what must be TRUE):
  1. 用户点击导出按钮可选择 DOCX 格式下载周报
  2. 导出的 DOCX 正确保留富文本格式（粗体、斜体、列表、表格、标题、链接、代码块）
  3. 导出的 DOCX 包含嵌入的图片，离线可查看
**Plans**: 3 plans (Wave 0: test scaffolding, Wave 1: DocxExporter, Wave 2: integration)

Plans:
- [x] 10-00-PLAN.md — Wave 0: Test scaffolding for DocxExporter
- [x] 10-01-PLAN.md — Wave 1: Create DocxExporter with HTML-to-DOCX conversion and image embedding
- [x] 10-02-PLAN.md — Wave 2: Route and form integration

### Phase 11: Excel Enhancement
**Goal**: Excel 导出的单元格支持富文本格式，提升可读性
**Depends on**: Phase 8
**Requirements**: XLSX-01
**Success Criteria** (what must be TRUE):
  1. 用户导出 Excel 时，周报内容单元格正确显示粗体、斜体等格式
  2. 原有 Excel 导出功能保持不变（表格结构、列名等）
**Plans**: 3 plans (Wave 0: test scaffolding, Wave 1: ExcelExporter + integration)

Plans:
- [x] 11-00-PLAN.md — Wave 0: Test scaffolding for ExcelExporter
- [x] 11-01-PLAN.md — Wave 1: Create ExcelExporter with HTML-to-CellRichText conversion
- [x] 11-02-PLAN.md — Wave 1: Register ExcelExporter and update routes

### Phase 12: Batch Export
**Goal**: 团队领导可一键导出整个组的周报，打包为 ZIP 文件
**Depends on**: Phase 9, Phase 10, Phase 11
**Requirements**: BATCH-01
**Success Criteria** (what must be TRUE):
  1. 团队领导在管理页面看到批量导出按钮
  2. 点击后可选择导出格式（PDF、DOCX、Excel）
  3. 系统生成 ZIP 压缩包，包含所选时间范围内所有组员的周报
  4. ZIP 文件中的每个周报文件名包含用户名和日期，便于识别
**Plans**: 3 plans (Wave 0: test scaffolding, Wave 1: route, Wave 2: UI)

Plans:
- [x] 12-00-PLAN.md — Wave 0: Test scaffolding for batch export
- [x] 12-01-PLAN.md — Wave 1: Create batch_export route with ZIP generation
- [ ] 12-02-PLAN.md — Wave 2: Add UI button to manage_records.html

### Phase 13: Comprehensive Code Review
**Goal**: Comprehensive code review covering syntax, style, and redundancy; implement fixes
**Depends on**: Phase 12
**Requirements**: None (quality improvement phase)
**Success Criteria** (what must be TRUE):
  1. Zero linting errors (ruff check returns clean)
  2. All functions have cyclomatic complexity < 10
  3. No invalid escape sequences or SyntaxWarnings
  4. No variable shadowing issues
  5. All imports properly organized
  6. Test coverage maintained at ~88%
**Plans**: 5 plans

Plans:
- [x] 13-01-PLAN.md — Wave 1: Create pyproject.toml with ruff and black configuration
- [x] 13-02-PLAN.md — Wave 2: Auto-fix 40 linting issues with ruff --fix
- [x] 13-03-PLAN.md — Wave 3: Manual fixes (invalid escapes, variable shadowing, E402 imports)
- [x] 13-04-PLAN.md — Wave 4: Refactor high-complexity functions (CC < 10)
- [x] 13-05-PLAN.md — Wave 5: Final verification and quality metrics report

## Progress

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1. Production WSGI Server | v1.0 | 3/3 | Complete | 2026-03-23 |
| 2. Session Management | v1.0 | 1/1 | Complete | 2026-03-23 |
| 3. SQLite Optimization | v1.0 | 1/1 | Complete | 2026-03-23 |
| 4. Unit Testing | v1.0 | 3/3 | Complete | 2026-03-23 |
| 5. Code Refactoring | v1.0 | 3/3 | Complete | 2026-03-23 |
| 6. Find Page Filtering | v1.1 | 1/2 | In Progress | - |
| 7. Homepage Rendering | v1.1 | 0/2 | Ready to execute | - |
| 8. Export Foundation | v1.2 | 5/5 | Complete | 2026-03-26 |
| 9. PDF Export | v1.2 | 3/3 | Complete | 2026-03-26 |
| 10. DOCX Export | v1.2 | 3/3 | Complete | 2026-03-26 |
| 11. Excel Enhancement | v1.2 | 3/3 | Complete | 2026-03-26 |
| 12. Batch Export | v1.2 | 2/3 | In Progress | - |
| 13. Comprehensive Code Review | v1.3 | 5/5 | Complete   | 2026-03-28 |

---

*For milestone details, see `.planning/milestones/`*
*Current milestone: v1.2 增强富文本导出功能 — Phases 8-12*