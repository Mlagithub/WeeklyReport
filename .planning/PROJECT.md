# 周报管理系统稳定性修复

## Current Milestone: v1.0 FixIOBug

**Goal:** 解决 IO 过载问题，确保系统长期稳定运行

**Target features:**
- STAB-01: 修复 Flask 开发服务器生产环境问题
- STAB-02: 添加 SQLAlchemy Session 清理机制
- STAB-03: 启用 SQLite WAL 模式优化并发性能
- STAB-04: 添加数据库操作错误处理和事务回滚
- TEST-01: 添加核心功能的单元测试
- REFAC-01: 代码结构优化（可选）

## What This Is

Flask 周报管理系统，用于软件开发团队的周报提交、管理和导出。支持用户分组、权限控制、富文本编辑和 Excel 导出。

**问题：** 应用运行约一周后导致 Ubuntu 系统 IO 过载，系统无响应，强制重启后数据库无法打开。

## Core Value

**解决 IO 过载问题，确保系统长期稳定运行。**

如果这个问题不解决，其他所有功能都没有意义。

## Requirements

### Validated

*已上线运行的功能（从现有代码推断）：*

- ✓ 用户注册/登录/登出 — Flask-Security 实现
- ✓ 周报创建、编辑、删除 — CKEditor 富文本
- ✓ 周报列表查看 — 分页、按用户/组/时间过滤
- ✓ 基于角色的权限控制 — view_self/view_group/view_all/edit_database
- ✓ 分组管理 — 组长可查看组员周报
- ✓ Excel 导出 — openpyxl 生成周报表
- ✓ 主题切换 — Bootstrap Bootswatch 主题
- ✓ 文件上传 — CKEditor 图片上传

### Active

*本次里程碑目标：*

- [ ] **STAB-01**: 修复 Flask 开发服务器导致的生产环境问题
- [ ] **STAB-02**: 添加 SQLAlchemy Session 清理机制，防止连接泄漏
- [ ] **STAB-03**: 启用 SQLite WAL 模式优化并发性能
- [ ] **STAB-04**: 添加数据库操作错误处理和事务回滚
- [ ] **TEST-01**: 添加核心功能的单元测试
- [ ] **REFAC-01**: 代码结构优化（可选，时间允许时）

### Out of Scope

- **数据库迁移到 PostgreSQL/MySQL** — 用户选择先修复现有代码
- **多里程碑** — 本次只修复稳定性问题，快速上线
- **API 接口开发** — 无此需求
- **移动端适配** — 无此需求

## Context

**技术环境：**
- Python 3.10 + Flask 3.0.3
- SQLite 数据库（约 110KB，10-50 用户）
- Ubuntu 22.04 服务器
- 部署方式：`python app.py`（Flask 开发服务器）

**已知问题（从代码分析）：**
1. `app.py:747` 使用 `debug=True` 运行 Flask 开发服务器
2. 缺少 `teardown_appcontext` 清理数据库 session
3. 多处 `db.session.commit()` 无错误处理和回滚
4. SQLite 未启用 WAL 模式，并发写入易锁定
5. 硬编码密钥（`SECRET_KEY`, `SECURITY_PASSWORD_SALT`）

**问题复现：**
- 运行约一周后系统 IO 过载
- SSH 和本地显示器都无法响应
- 强制重启后系统恢复正常，但问题会再次出现

## Constraints

- **技术栈**: 保持 Flask + SQLite，不迁移数据库
- **时间**: 单里程碑，快速修复上线
- **兼容性**: 不能破坏现有功能，密码哈希值不能更改
- **部署**: 优先支持 `python app.py`，后续可考虑生产级部署

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| 修复现有代码而非迁移数据库 | 用户选择，SQLite 对于 10-50 用户足够 | — Pending |
| 单里程碑 | 快速修复上线，最小改动 | — Pending |
| 保持 `python app.py` 部署方式 | 最小改动，降低风险 | — Pending |

---

*Last updated: 2026-03-23 after initialization*

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd:transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd:complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state