# 周报管理系统

## Current Milestone: v1.3 AI (In Progress)

**Goal:** 集成AI能力，支持工作总结生成和周报文本润色

**Target features:**
- 一键生成工作总结 — 主页，支持周/月/季度/年范围
- 筛选结果AI总结 — 查找页，组长和管理员可用
- 周报文本润色 — 新建/编辑页，所有用户可用
- AI服务配置 — 管理员配置API URL/Key/模型名称
- 自定义提示词 — 用户生成总结时可输入自定义提示词指导AI
- 管理员模板配置 — 管理员可配置预设总结模板供用户选择

**Status:** In Progress — Defining requirements

## What This Is

Flask 周报管理系统，用于软件开发团队的周报提交、管理和多格式导出。支持用户分组、权限控制、富文本编辑和多格式导出（Excel、PDF、DOCX）。

**v1.2 已发布：** 增强富文本导出功能。PDF、DOCX、Excel 三种格式均支持富文本格式保留，团队领导可批量导出整组周报为 ZIP。

**v1.0 已解决：** 应用运行约一周后导致系统 IO 过载的问题已修复。生产环境部署了 Gunicorn + systemd，启用了 SQLite WAL 模式，添加了单元测试（122 tests，88% coverage），代码已模块化重构并通过 linting 验证。

## Core Value

**让团队领导能导出保留格式的周报，支持多种格式和批量导出。**

v1.2 已完成此目标。系统支持 PDF、DOCX、Excel 三种格式，均保留富文本格式。

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
- ✓ **TEST-01**: 单元测试 — v1.0 (122 tests, 88% coverage)
- ✓ **REFAC-01**: 代码结构优化 — v1.0
- ✓ **FIND-01**: 查找页面默认选中当前用户 — v1.1 Phase 6
- ✓ **FIND-02**: 查找页面默认日期范围为本周 — v1.1 Phase 6
- ✓ **FIND-03**: 保留现有过滤工具功能 — v1.1 Phase 6
- ✓ **RENDER-01**: 主页最近提交正确渲染富文本格式 — v1.1 Phase 7
- ✓ **RENDER-02**: 渲染时保持 XSS 防护 — v1.1 Phase 7
- ✓ **EXPORT-01**: 用户可导出周报为 DOCX 格式 — v1.2 Phase 10
- ✓ **EXPORT-02**: 用户可导出周报为 PDF 格式 — v1.2 Phase 9
- ✓ **EXPORT-03**: Excel 导出支持富文本格式 — v1.2 Phase 11
- ✓ **EXPORT-04**: 团队领导可批量导出整个组的周报 — v1.2 Phase 12
- ✓ **EXPORT-05**: 导出时图片嵌入文档 — v1.2 Phases 9-11
- ✓ **CODE-01**: 代码语法审查和修复 — v1.2 Phase 13
- ✓ **CODE-02**: 代码风格统一 (PEP 8) — v1.2 Phase 13
- ✓ **CODE-03**: 冗余代码清理 — v1.2 Phase 13

### Active

(None — all v1.2 requirements validated)

### Out of Scope

- **数据库迁移到 PostgreSQL/MySQL** — SQLite 对 10-50 用户足够
- **API 接口开发** — 无此需求
- **移动端适配** — 无此需求

## Context

**技术环境：**
- Python 3.12 + Flask 3.0.3
- SQLite 数据库（WAL 模式）
- Ubuntu 22.04 服务器
- 部署方式：Gunicorn + systemd 服务

**代码规模：**
- 4,644 行 Python 代码
- 8 个模块（app, routes, models, forms, utils, config, extensions, exporters/）
- 122 个测试用例，88% coverage
- 0 linting errors (ruff)

**已解决问题：**
1. Flask 开发服务器 IO 过载 → Gunicorn + systemd
2. 数据库连接泄漏 → Flask-SQLAlchemy 3.x 自动清理
3. 数据库锁定 → SQLite WAL 模式
4. 硬编码密钥 → 环境变量配置
5. 无多格式导出 → PDF/DOCX/Excel with rich text
6. 代码质量问题 → ruff/black 配置，CC < 10

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
| ExporterBase template method pattern | 统一导出接口 | ✓ Phase 8 完成 |
| WeasyPrint for PDF | 纯 Python，CSS 支持好 | ✓ Phase 9 完成 |
| python-docx + htmldocx for DOCX | 行业标准 | ✓ Phase 10 完成 |
| openpyxl CellRichText for Excel | 原生富文本支持 | ✓ Phase 11 完成 |
| ZIP 批量导出 | 简单、通用 | ✓ Phase 12 完成 |
| ruff + black for linting | 快速、统一配置 | ✓ Phase 13 完成 |

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

*Last updated: 2026-03-28 — v1.3 milestone started*