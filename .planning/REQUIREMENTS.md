# Requirements — Milestone v1.2 增强富文本导出功能

> Last updated: 2026-03-26

## Summary

**Milestone Goal:** 让团队领导能导出保留格式的周报，支持多种格式和批量导出

**Total Requirements:** 7 active requirements

---

## Active Requirements

### DOCX Export

- [ ] **DOCX-01**: 用户可将周报导出为 DOCX 格式（支持表格、列表、标题、链接、代码块）
- [ ] **DOCX-02**: 导出的 DOCX 文档中图片嵌入（离线可查看）

### PDF Export

- [ ] **PDF-01**: 用户可将周报导出为 PDF 格式（完整 HTML 渲染）
- [ ] **PDF-02**: 导出的 PDF 文档中图片嵌入
- [ ] **PDF-03**: PDF 导出包含页眉页脚（页码、日期、文档标题）

### Excel Enhancement

- [ ] **XLSX-01**: Excel 导出支持富文本单元格（单元格内粗体、斜体等格式）

### Batch Export

- [ ] **BATCH-01**: 团队领导可批量导出整个组的周报（ZIP 压缩包）

---

## Future Requirements

*Deferred from this milestone:*

- **Custom export templates** — 公司品牌、自定义页眉
- **PDF table of contents** — 多报告导航
- **Export scheduling** — 自动定期导出到邮箱

---

## Out of Scope

| Feature | Reason |
|---------|--------|
| HTML 导出格式 | 用户明确不需要 HTML 格式 |
| Google Docs 导出 | OAuth 复杂度高，用户可手动上传 DOCX |
| 实时预览 | 增加延迟，用户可通过格式说明了解输出 |
| 可编辑 PDF 表单 | 技术复杂度高，PDF 仅用于查看 |

---

## Traceability

| REQ-ID | Phase | Status |
|--------|-------|--------|
| DOCX-01 | — | Pending |
| DOCX-02 | — | Pending |
| PDF-01 | — | Pending |
| PDF-02 | — | Pending |
| PDF-03 | — | Pending |
| XLSX-01 | — | Pending |
| BATCH-01 | — | Pending |

*Traceability updated after roadmap creation.*

---

## Research References

- `.planning/research/STACK.md` — Library recommendations (python-docx, WeasyPrint, openpyxl)
- `.planning/research/FEATURES.md` — Feature landscape and dependencies
- `.planning/research/ARCHITECTURE.md` — Integration patterns
- `.planning/research/PITFALLS.md` — Common mistakes and prevention
- `.planning/research/SUMMARY.md` — Consolidated findings

---

*Requirements for Milestone v1.2 — Rich Text Export Enhancement*