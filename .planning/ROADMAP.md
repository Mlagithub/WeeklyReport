# Roadmap: 周报管理系统

## Milestones

- **v1.1 UI Optimization** — Phases 6-7 (current)
- ✅ **v1.0 FixIOBug** — Phases 1-5 (shipped 2026-03-24)

## Phases

- [ ] **Phase 6: Find Page Filtering** - 默认过滤减少信息过载
- [ ] **Phase 7: Homepage Rendering** - 富文本渲染与 XSS 防护

<details>
<summary>✅ v1.0 FixIOBug (Phases 1-5) — SHIPPED 2026-03-24</summary>

- [x] Phase 1: Production WSGI Server (3/3 plans) — Gunicorn + systemd
- [x] Phase 2: Session Management (1/1 plan) — @with_db_transaction decorator
- [x] Phase 3: SQLite Optimization (1/1 plan) — WAL mode
- [x] Phase 4: Unit Testing (3/3 plans) — 62 tests, 68% coverage
- [x] Phase 5: Code Refactoring (3/3 plans) — Modular structure

</details>

## Phase Details

### Phase 6: Find Page Filtering
**Goal**: 查找页面默认显示用户关注的记录，减少信息过载
**Depends on**: Nothing (independent feature)
**Requirements**: FIND-01, FIND-02, FIND-03
**Success Criteria** (what must be TRUE):
  1. 查找页面打开时，"按用户"过滤默认选中当前用户
  2. 查找页面打开时，"按日期"过滤默认选中最近 7 天
  3. 现有的三个过滤工具（按用户、按小组、按日期）功能不变
  4. 用户可以修改过滤条件查看其他记录
**Plans**: 2 plans

Plans:
- [x] 06-01-PLAN.md — Add 'last_7_days' time range to DateRange class
- [ ] 06-02-PLAN.md — Update template default selection logic

### Phase 7: Homepage Rendering
**Goal**: 主页正确显示富文本格式的周报内容
**Depends on**: Nothing (independent feature)
**Requirements**: RENDER-01, RENDER-02
**Success Criteria** (what must be TRUE):
  1. 最近提交列表中的周报内容正确渲染富文本格式（粗体、斜体、列表等）
  2. XSS 攻击代码被安全过滤，不会在浏览器中执行
  3. 原有周报内容显示不受影响
**Plans**: 2 plans
**UI hint**: yes

Plans:
- [ ] 07-01-PLAN.md — Create sanitize_html Jinja2 filter with bleach
- [ ] 07-02-PLAN.md — Integrate filter into home template and add tests

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

---

*For milestone details, see `.planning/milestones/v1.0-ROADMAP.md`*
*Current milestone: v1.1 UI Optimization — Phases 6-7*