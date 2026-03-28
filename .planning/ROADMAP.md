# Roadmap: 周报管理系统

## Milestones

- 🔄 **v1.3 AI** — Phases 14-18 (in progress)
- ✅ **v1.2 增强富文本导出功能** — Phases 8-13 (shipped 2026-03-28)
- ✅ **v1.1 UI Optimization** — Phases 6-7 (shipped 2026-03-28)
- ✅ **v1.0 FixIOBug** — Phases 1-5 (shipped 2026-03-24)

## Phases

### v1.3 AI (Phases 14-18) — IN PROGRESS

- [x] **Phase 14: AI Configuration & Security** — Admins can securely configure AI service
- [ ] **Phase 15: API Integration Layer** — System can reliably call AI APIs with error handling
- [ ] **Phase 16: Template Management** — Admins can manage summary templates with variables
- [ ] **Phase 17: Personal Summary Generation** — Users can generate personal work summaries on home page
- [ ] **Phase 18: Filtered Summary & Text Polish** — Team leaders can summarize filtered results, users can polish text

<details>
<summary>✅ v1.2 增强富文本导出功能 (Phases 8-13) — SHIPPED 2026-03-28</summary>

- [x] Phase 8: Export Foundation (5/5 plans) — 导出架构基础设施
- [x] Phase 9: PDF Export (3/3 plans) — PDF 格式导出完整功能
- [x] Phase 10: DOCX Export (3/3 plans) — Word 格式导出完整功能
- [x] Phase 11: Excel Enhancement (3/3 plans) — Excel 富文本单元格支持
- [x] Phase 12: Batch Export (3/3 plans) — 团队领导批量导出功能
- [x] Phase 13: Code Review (5/5 plans) — Linting, complexity reduction, code cleanup

</details>

<details>
<summary>✅ v1.1 UI Optimization (Phases 6-7) — SHIPPED 2026-03-28</summary>

- [x] Phase 6: Find Page Filtering (2/2 plans) — 默认过滤减少信息过载
- [x] Phase 7: Homepage Rendering (2/2 plans) — 富文本渲染与 XSS 防护

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

### Phase 14: AI Configuration & Security

**Goal:** 管理员可以安全配置AI服务，权限体系就位

**Depends on:** Phase 13 (v1.2 completion)

**Requirements:** CONFIG-01, CONFIG-02, CONFIG-03, SEC-01, SEC-03

**Success Criteria** (what must be TRUE):
1. Admin can input and save API URL, API Key, and model name in settings page
2. Admin can test AI connection and see success/failure status with error messages
3. Configuration persists after system restart
4. API Key is encrypted in database, not stored in plaintext
5. Permission matrix for AI features is defined and enforced (admin config, user summary, team leader filtered summary)

**Plans:** 5/5 plans complete

Plans:
- [x] 14-00-PLAN.md — Wave 0: Test infrastructure + cryptography dependency
- [x] 14-01-PLAN.md — Wave 1: AIConfig model + ai_utils.py encryption (SEC-01, CONFIG-03)
- [x] 14-02-PLAN.md — Wave 1: AIConfigForm with validation (CONFIG-01)
- [x] 14-03-PLAN.md — Wave 2: Route + UI + permissions (CONFIG-01, SEC-03)
- [x] 14-04-PLAN.md — Wave 3: Test connection functionality (CONFIG-02)

**UI hint:** yes

---

### Phase 15: API Integration Layer

**Goal:** 系统能可靠调用AI API，妥善处理各种错误情况

**Depends on:** Phase 14

**Requirements:** API-01, API-02, API-03, API-04, SEC-02

**Success Criteria** (what must be TRUE):
1. System can send requests to any OpenAI-compatible API endpoint
2. User sees friendly Chinese error messages for network/auth/rate-limit/model failures
3. API calls timeout after 30 seconds with proper notification
4. AI responses are correctly processed (Markdown to HTML, whitespace handling)
5. API calls are logged for audit (time, user, function type, status, without full content)

**Plans:** 3 plans

Plans:
- [ ] 15-00-PLAN.md — Wave 0: Test infrastructure for AI API calls
- [ ] 15-01-PLAN.md — Wave 1: Core API call function with error handling, timeout, audit logging (API-01, API-02, API-03, SEC-02)
- [ ] 15-02-PLAN.md — Wave 2: Response processing utilities (API-04)

---

### Phase 16: Template Management

**Goal:** 管理员可以创建和管理带变量支持的总结模板

**Depends on:** Phase 14 (AI config must exist)

**Requirements:** TEMPLATE-01, TEMPLATE-02, TEMPLATE-03

**Success Criteria** (what must be TRUE):
1. Admin can create, edit, and delete templates via dedicated management page
2. Templates support placeholder variables ({time_range}, {user_name}, {records}, {record_count}, {date_range})
3. Four default templates (weekly, monthly, quarterly, yearly) are initialized on first run
4. Templates are stored in database and persist across sessions

**Plans:** TBD

**UI hint:** yes

---

### Phase 17: Personal Summary Generation

**Goal:** 用户可以在主页一键生成个人工作总结

**Depends on:** Phase 15 (API layer), Phase 16 (Templates)

**Requirements:** SUMMARY-01, SUMMARY-02, SUMMARY-03, SUMMARY-04, UI-01, UI-02

**Success Criteria** (what must be TRUE):
1. User can select time range (week/month/quarter/year/custom) and click to generate summary
2. User can choose a pre-configured template from dropdown
3. User can input custom prompt to guide AI generation style
4. Generated summary displays in page with copy and export options
5. Loading indicator shows during generation, buttons are disabled to prevent duplicate clicks
6. User can regenerate with same parameters or edit before copying

**Plans:** TBD

**UI hint:** yes

---

### Phase 18: Filtered Summary & Text Polish

**Goal:** 组长可对筛选结果AI总结，用户可润色周报文本

**Depends on:** Phase 17 (Summary patterns established)

**Requirements:** FILTER-SUM-01, FILTER-SUM-02, POLISH-01, POLISH-02

**Success Criteria** (what must be TRUE):
1. Team leader can click "AI Summary" button on filtered results in find page
2. Summary modal shows filter criteria summary (users, groups, time range)
3. Multi-user summary clearly groups content by user
4. User can click "Polish" button in report editor to AI-enhance text
5. Polished text replaces editor content, user can continue editing before save
6. Admin can configure default polish prompt in settings

**Plans:** TBD

**UI hint:** yes

---

## Coverage Validation

| Category | Requirements | Phase |
|----------|--------------|-------|
| CONFIG | CONFIG-01, CONFIG-02, CONFIG-03 | 14 |
| TEMPLATE | TEMPLATE-01, TEMPLATE-02, TEMPLATE-03 | 16 |
| SUMMARY | SUMMARY-01, SUMMARY-02, SUMMARY-03, SUMMARY-04 | 17 |
| FILTER-SUM | FILTER-SUM-01, FILTER-SUM-02 | 18 |
| POLISH | POLISH-01, POLISH-02 | 18 |
| API | API-01, API-02, API-03, API-04 | 15 |
| SEC | SEC-01, SEC-03 | 14 |
| SEC | SEC-02 | 15 |
| UI | UI-01, UI-02 | 17 |

**Total mapped:** 23/23 (100%)

**Orphaned:** None

---

## Progress

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1. Production WSGI Server | v1.0 | 3/3 | Complete | 2026-03-23 |
| 2. Session Management | v1.0 | 1/1 | Complete | 2026-03-23 |
| 3. SQLite Optimization | v1.0 | 1/1 | Complete | 2026-03-23 |
| 4. Unit Testing | v1.0 | 3/3 | Complete | 2026-03-23 |
| 5. Code Refactoring | v1.0 | 3/3 | Complete | 2026-03-23 |
| 6. Find Page Filtering | v1.1 | 2/2 | Complete | 2026-03-28 |
| 7. Homepage Rendering | v1.1 | 2/2 | Complete | 2026-03-28 |
| 8. Export Foundation | v1.2 | 5/5 | Complete | 2026-03-26 |
| 9. PDF Export | v1.2 | 3/3 | Complete | 2026-03-26 |
| 10. DOCX Export | v1.2 | 3/3 | Complete | 2026-03-26 |
| 11. Excel Enhancement | v1.2 | 3/3 | Complete | 2026-03-26 |
| 12. Batch Export | v1.2 | 3/3 | Complete | 2026-03-27 |
| 13. Code Review | v1.2 | 5/5 | Complete | 2026-03-28 |
| 14. AI Configuration & Security | v1.3 | 5/5 | Complete    | 2026-03-28 |
| 15. API Integration Layer | v1.3 | 0/3 | Not started | - |
| 16. Template Management | v1.3 | 0/3 | Not started | - |
| 17. Personal Summary Generation | v1.3 | 0/6 | Not started | - |
| 18. Filtered Summary & Text Polish | v1.3 | 0/4 | Not started | - |

---

## Dependency Graph

```
Phase 13 (v1.2)
      │
      ▼
Phase 14: AI Configuration & Security
      │
      ├─────────────────┐
      ▼                 ▼
Phase 15: API      Phase 16: Templates
Integration         Management
      │                 │
      └────────┬────────┘
               ▼
Phase 17: Personal Summary Generation
               │
               ▼
Phase 18: Filtered Summary & Text Polish
```

---

*For milestone details, see `.planning/milestones/`*
*Last updated: 2026-03-28 — Phase 15 plans created*