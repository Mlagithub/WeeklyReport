# Phase 2: Session Management - Context

**Gathered:** 2026-03-23
**Status:** Ready for planning

<domain>
## Phase Boundary

实现数据库会话正确管理和错误处理机制，防止连接泄漏和事务错误。确保应用在数据库错误后能继续运行而不崩溃。

</domain>

<decisions>
## Implementation Decisions

### Session 清理机制
- **D-01:** 依赖 Flask-SQLAlchemy 自动管理 session 生命周期
- **D-02:** 不添加显式 `teardown_appcontext` 清理（Flask-SQLAlchemy 3.x 自动处理）

### 错误处理模式
- **D-03:** 创建 `@with_db_transaction` 装饰器统一处理数据库错误
- **D-04:** 装饰器仅应用于**写操作**（insert/update/delete），只读操作无需处理
- **D-05:** 装饰器实现 try/except/rollback/re-raise 模式

### 事务回滚策略
- **D-06:** 异常时执行 `db.session.rollback()` 然后 re-raise 异常
- **D-07:** 不捕获异常，让 Flask 错误处理器统一处理

### 错误消息设计
- **D-08:** 用户看到简单通用消息："操作失败，请重试"
- **D-09:** 日志记录完整异常堆栈，使用 Phase 1 配置的日志系统
- **D-10:** 使用 `current_app.logger.error()` 记录数据库错误

### Claude's Discretion
- 装饰器的具体命名和参数设计
- 哪些路由函数需要应用装饰器
- 是否需要专门的错误页面或使用 Flask 默认 500 处理

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### 现有代码分析
- `.planning/codebase/ARCHITECTURE.md` — 应用架构，数据库模型位置
- `.planning/codebase/CONCERNS.md` — 已知问题，缺少错误处理的位置
- `.planning/codebase/CONVENTIONS.md` — 错误处理模式（flash 消息）

### 需求文档
- `.planning/REQUIREMENTS.md` — STAB-02, STAB-04
- `.planning/ROADMAP.md` — Phase 2 目标和成功标准

### Phase 1 上下文
- `.planning/phases/01-production-wsgi-server/01-CONTEXT.md` — 日志配置决策
- `app.py` — 新增的日志配置 (RotatingFileHandler)

</canonical_refs>

<code_context>
## Existing Code Insights

### 当前数据库操作位置
- `app.py:488-489` — Record 创建，无错误处理
- `app.py:528-529` — Record 更新，无错误处理
- `app.py:567-568` — Record 删除，无错误处理
- `app.py:103-104` — Schema migration (ensure_record_columns)
- `app.py:465, 552, 738, 751, 778` — 其他 commit 调用

### 已有错误处理模式
- `abort(404)`, `abort(403)` 用于 HTTP 错误
- `flash('message', 'warning')` 用于用户反馈
- 无数据库错误处理

### 连接池配置
- `app.py:31-36` — pool_pre_ping, pool_recycle, pool_size, max_overflow
- 已配置，可复用

### 集成点
- 所有写操作路由需要添加装饰器
- 日志使用 Phase 1 配置的 `app` logger

</code_context>

<specifics>
## Specific Ideas

- 装饰器应该简洁，类似 Flask-SQLAlchemy 的 `@db.atomic` 模式
- 保持与现有 `flash()` 模式一致的用户体验
- 利用已有的日志系统，不需要额外配置

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 02-session-management*
*Context gathered: 2026-03-23*