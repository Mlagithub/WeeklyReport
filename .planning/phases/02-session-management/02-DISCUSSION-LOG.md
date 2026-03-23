# Phase 2: Session Management - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-03-23
**Phase:** 02-session-management
**Areas discussed:** Session 清理机制, 错误处理模式, 事务回滚策略, 错误消息设计

---

## Session 清理机制

| Option | Description | Selected |
|--------|-------------|----------|
| 依赖自动管理 | Flask-SQLAlchemy 3.x 自动处理，无需显式 teardown | ✓ |
| 添加显式清理 | 添加 teardown_appcontext 显式调用 db.session.remove() | |
| 混合模式 | 显式清理 + 健康检查，最安全但代码更多 | |

**User's choice:** 依赖自动管理
**Notes:** Flask-SQLAlchemy 3.x 已自动处理 session 管理

---

## 错误处理模式

| Option | Description | Selected |
|--------|-------------|----------|
| 装饰器模式 | 创建 @with_db_transaction 装饰器，统一处理 try/except/rollback | ✓ |
| 内联 try/except | 在每处 commit 添加 try/except/rollback，更灵活但重复代码 | |
| 上下文管理器 | 创建 with db_transaction(): 上下文管理器 | |

**User's choice:** 装饰器模式
**Notes:** 统一处理，代码整洁

---

## 装饰器应用范围

| Option | Description | Selected |
|--------|-------------|----------|
| 仅写操作 | 所有写操作（insert/update/delete）使用装饰器，只读操作无需处理 | ✓ |
| 所有操作 | 所有数据库操作都使用装饰器 | |

**User's choice:** 仅写操作
**Notes:** 只读操作不需要事务处理

---

## 事务回滚策略

| Option | Description | Selected |
|--------|-------------|----------|
| 回滚并抛出异常 | 异常时 db.session.rollback()，然后 re-raise 异常 | ✓ |
| 回滚并返回错误 | 回滚后返回错误结果，不抛出异常 | |
| 混合策略 | 根据异常类型决定是否抛出 | |

**User's choice:** 回滚并抛出异常
**Notes:** 标准做法，确保事务清理并传播错误

---

## 用户错误消息

| Option | Description | Selected |
|--------|-------------|----------|
| 简单通用消息 | 显示"操作失败，请重试"，不暴露细节 | ✓ |
| 分类错误消息 | 显示具体错误类型，如"保存失败：数据库连接错误" | |
| 详细错误信息 | 显示完整错误信息，适合调试但不适合生产 | |

**User's choice:** 简单通用消息
**Notes:** 安全实践，不暴露内部细节

---

## 日志记录详细程度

| Option | Description | Selected |
|--------|-------------|----------|
| 完整日志 | 记录完整异常堆栈到日志，便于调试 | ✓ |
| 简要日志 | 只记录错误类型和消息，日志量小 | |
| 不额外记录 | 数据库错误不记录，依赖 Flask 默认 | |

**User's choice:** 完整日志
**Notes:** 利用 Phase 1 日志配置

---

## Claude's Discretion

- 装饰器的具体命名和参数设计
- 哪些路由函数需要应用装饰器
- 是否需要专门的错误页面或使用 Flask 默认 500 处理

## Deferred Ideas

None — discussion stayed within phase scope