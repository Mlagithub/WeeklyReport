# 周报管理系统稳定性修复

## Current Milestone: v2.0 (Planning)

**Goal:** 待定

**Status:** Milestone v1.0 shipped. Ready for next milestone planning.

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

### Active

*等待下一里程碑规划*

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
- 2,476 行 Python 代码
- 6 个模块（config, extensions, models, forms, routes, app）
- 62 个测试用例

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

---

*Last updated: 2026-03-24 after v1.0 milestone completion*