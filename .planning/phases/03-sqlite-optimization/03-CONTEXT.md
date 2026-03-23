# Phase 3: SQLite Optimization - Context

**Gathered:** 2026-03-23
**Status:** Ready for planning

<domain>
## Phase Boundary

启用 SQLite WAL 模式，优化并发性能，避免写入锁定问题。

</domain>

<decisions>
## Implementation Decisions

### WAL 启用方式
- **D-01:** 在数据库连接时执行 `PRAGMA journal_mode=WAL`
- **D-02:** 使用 SQLAlchemy `engine.connect()` 事件或 Flask-SQLAlchemy 配置

### Checkpoint 策略
- **D-03:** 使用 SQLite 默认自动 Checkpoint，无需额外配置
- **D-04:** 不设置 `wal_autocheckpoint` 阈值（使用默认值 1000 页）

### 验证方法
- **D-05:** 应用启动后执行 `PRAGMA journal_mode` 查询，验证返回值为 'wal'
- **D-06:** 在日志中记录 WAL 模式启用状态

### Claude's Discretion
- 具体实现位置（SQLAlchemy 事件 vs raw SQL）
- 日志消息格式

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### 现有代码分析
- `.planning/codebase/STACK.md` — SQLite 数据库
- `app.py:31-36` — SQLALCHEMY_ENGINE_OPTIONS 配置位置

### 需求文档
- `.planning/REQUIREMENTS.md` — STAB-03
- `.planning/ROADMAP.md` — Phase 3 目标和成功标准

</canonical_refs>

<code_context>
## Existing Code Insights

### 数据库配置位置
- `app.py:29` — SQLALCHEMY_DATABASE_URI
- `app.py:31-36` — SQLALCHEMY_ENGINE_OPTIONS (pool 配置)

### 集成点
- 可在 SQLALCHEMY_ENGINE_OPTIONS 中添加 `connect_args` 或使用事件监听器
- 或在 `db.create_all()` 之前执行 PRAGMA

</code_context>

<specifics>
## Specific Ideas

- SQLite WAL 模式对于 10-50 用户的小型应用足够
- 使用 SQLAlchemy 事件监听器是标准做法
- 启动时验证确保配置生效

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 03-sqlite-optimization*
*Context gathered: 2026-03-23*