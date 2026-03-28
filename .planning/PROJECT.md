# 周报管理系统稳定性修复

## Current Milestone: v1.2 增强富文本导出功能

**Goal:** 让团队领导能导出保留格式的周报，支持多种格式和批量导出

**Target features:**
- DOCX 导出 — Word 格式，支持图片、链接、列表、表格、代码片段
- PDF 导出 — 只读格式，方便分享
- Excel 增强 — 增强现有导出，支持富文本
- 批量导出 — 团队领导可一键导出整个组的周报
- 图片嵌入 — 图片嵌入文档，离线可查看

**Status:** Complete — All v1.2 phases (8-13) finished. Code review complete.

## What This Is

Flask 周报管理系统，用于软件开发团队的周报提交、管理和导出。支持用户分组、权限控制、富文本编辑和 Excel 导出。

**v1.0 已解决：** 应用运行约一周后导致系统 IO 过载的问题已修复。生产环境部署了 Gunicorn + systemd，启用了 SQLite WAL 模式，添加了单元测试（62 tests，68% coverage），代码已模块化重构。

## Core Value

**解决 IO 过载问题，确保系统长期稳定运行。**

v1.0 已完成此目标。系统现在可以长期稳定运行。

## Requirements

### Validated

- ✓ 用户注册/登录/登出 — Flask-Security 实现
- ✓ 周报创建、编辑、删除 — CKEditor 富文本
- ✓ 周报列表查看 — 分页、按用户/组/时间过滤
- ✓ 基于角色的权限控制 — view_self/view_group/view_all/edit_database
- ✓ 分组管理 — 组长可查看组员周报
- ✓ Excel 导出 — openpyxl 生成周报表
- ✓ 主题切换 — Bootstrap Bootswatch 主题
- ✓ 文件上传 — CKEditor 图片上传
- ✓ **STAB-01**: 生产级 WSGI 服务器部署 — v1.0
- ✓ **STAB-02**: 数据库会话管理 — v1.0
- ✓ **STAB-03**: SQLite WAL 模式 — v1.0
- ✓ **STAB-04**: 数据库错误处理和回滚 — v1.0
- ✓ **TEST-01**: 单元测试 — v1.0
- ✓ **REFAC-01**: 代码结构优化 — v1.0
- ✓ **FIND-01**: 查找页面默认选中当前用户 — v1.1 Phase 6
- ✓ **FIND-02**: 查找页面默认日期范围为本周 — v1.1 Phase 6
- ✓ **FIND-03**: 保留现有过滤工具功能 — v1.1 Phase 6
- ✓ **RENDER-01**: 主页最近提交正确渲染富文本格式 — v1.1 Phase 7
- ✓ **RENDER-02**: 渲染时保持 XSS 防护 — v1.1 Phase 7
- ✓ **CODE-01**: 代码语法审查和修复 — v1.2 Phase 13
- ✓ **CODE-02**: 代码风格统一 (PEP 8) — v1.2 Phase 13
- ✓ **CODE-03**: 冗余代码清理 — v1.2 Phase 13

### Active

- **EXPORT-01**: 用户可导出周报为 DOCX 格式（保留富文本格式）
- **EXPORT-02**: 用户可导出周报为 PDF 格式（保留富文本格式）
- **EXPORT-03**: Excel 导出支持富文本格式
- **EXPORT-04**: 团队领导可批量导出整个组的周报
- **EXPORT-05**: 导出时图片嵌入文档（离线可查看）

### Out of Scope

- **数据库迁移到 PostgreSQL/MySQL** — SQLite 对 10-50 用户足够
- **API 接口开发** — 无此需求
- **移动端适配** — 无此需求

## Context

**技术环境：**
- Python 3.10 + Flask 3.0.3
- SQLite 数据库（WAL 模式）
- Ubuntu 22.04 服务器
- 部署方式：Gunicorn + systemd 服务

**代码规模：**
- 2,500+ 行 Python 代码
- 6 个模块（config, extensions, models, forms, routes, app）
- 87 个测试用例

**已解决问题：**
1. Flask 开发服务器 IO 过载 → Gunicorn + systemd
2. 数据库连接泄漏 → Flask-SQLAlchemy 3.x 自动清理
3. 数据库锁定 → SQLite WAL 模式
4. 硬编码密钥 → 环境变量配置

## Constraints

- **技术栈**: 保持 Flask + SQLite
- **兼容性**: 不能破坏现有功能
- **部署**: Gunicorn + systemd

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Gunicorn + systemd 部署 | 稳定、文档完善 | ✓ Phase 1 完成 |
| @with_db_transaction 装饰器 | DRY、一致性 | ✓ Phase 2 完成 |
| SQLAlchemy 事件监听器启用 WAL | 自动、无需手动 PRAGMA | ✓ Phase 3 完成 |
| pytest 测试框架 | Flask 测试支持好 | ✓ Phase 4 完成 |
| 模块化 Flask 结构 | 可维护性 | ✓ Phase 5 完成 |
| Jinja2 template-level defaults | 用户可清除过滤器 | ✓ Phase 6 完成 |

---

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

---

*Last updated: 2026-03-28 — Phase 13 (Code Review) complete*