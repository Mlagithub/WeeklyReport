# Phase 1: Production WSGI Server - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-03-23
**Phase:** 01-production-wsgi-server
**Areas discussed:** WSGI 服务器选择, 进程配置, 进程管理方式, 日志配置

---

## WSGI 服务器选择

| Option | Description | Selected |
|--------|-------------|----------|
| Gunicorn | Python 生态最流行的 WSGI 服务器，配置简单，性能稳定，社区活跃 | ✓ |
| uWSGI | 功能丰富，支持多种协议，配置复杂度较高 | |
| Waitress | 纯 Python 实现，Windows 兼容性好，但性能略逊于 Gunicorn | |
| Gunicorn + Gevent | Gevent 异步 worker，适合高并发 I/O 场景 | |

**User's choice:** Gunicorn
**Notes:** 推荐，Python 生态最成熟的选择

---

## 进程配置 - Worker 数量

| Option | Description | Selected |
|--------|-------------|----------|
| 自动（2-4 个 worker） | Gunicorn 推荐公式：(2 × CPU核心数) + 1。适合大多数场景 | ✓ |
| 单 worker | 固定数量，适合单核服务器或资源受限环境 | |
| 多 worker（5+） | 更高并发，适合多核服务器，但需要更多内存 | |

**User's choice:** 自动（2-4 个 worker）
**Notes:** 遵循 Gunicorn 推荐公式

---

## 进程配置 - Worker 类型

| Option | Description | Selected |
|--------|-------------|----------|
| Sync（同步） | 默认同步 worker，简单可靠，适合 CPU 密集型或低并发场景 | ✓ |
| Gevent（异步） | 异步 worker，适合 I/O 密集型应用，需要安装 gevent | |
| gthread（线程） | 基于线程，适合轻量 I/O 等待场景 | |

**User's choice:** Sync（同步）
**Notes:** 简单可靠，适合当前场景

---

## 进程配置 - 端口绑定

| Option | Description | Selected |
|--------|-------------|----------|
| 0.0.0.0:5000 | 监听所有网络接口，可通过外部访问（当前配置） | ✓ |
| 127.0.0.1:5000 | 仅本机访问，需要 Nginx 反向代理 | |
| Unix socket | Unix socket，适合 Nginx 本地代理，性能更好 | |

**User's choice:** 0.0.0.0:5000
**Notes:** 保持当前可访问性

---

## 进程配置 - 请求超时

| Option | Description | Selected |
|--------|-------------|----------|
| 30 秒 | Gunicorn 默认值，适合大多数 Web 应用 | ✓ |
| 10 秒 | 更短的超时，适合快速响应场景 | |
| 60 秒 | 允许较长的请求处理时间，适合有导出操作的周报系统 | |

**User's choice:** 30 秒
**Notes:** Gunicorn 默认值

---

## 进程管理方式

| Option | Description | Selected |
|--------|-------------|----------|
| systemd 服务 | Ubuntu 原生服务管理，自动启动、崩溃重启、日志集成 | ✓ |
| Supervisor | 独立进程管理器，支持多应用，Web UI 监控 | |
| 手动启动 | 最简单，但没有自动重启，需要手动管理 | |

**User's choice:** systemd 服务
**Notes:** Ubuntu 原生，无需额外安装

---

## 进程管理 - 重启策略

| Option | Description | Selected |
|--------|-------------|----------|
| 自动重启 | 崩溃后自动重启，保证服务可用性 | ✓ |
| 手动重启 | 需要手动启动，适合调试阶段 | |

**User's choice:** 自动重启
**Notes:** 保证服务可用性

---

## 日志配置 - 范围

| Option | Description | Selected |
|--------|-------------|----------|
| 添加日志 | 添加基本日志，帮助排查问题 | ✓ |
| 跳过日志 | 延后到其他阶段，专注 WSGI 服务器替换 | |

**User's choice:** 添加日志
**Notes:** 帮助排查问题

---

## 日志配置 - 位置

| Option | Description | Selected |
|--------|-------------|----------|
| systemd journal | systemd 自动管理日志轮转，可通过 journalctl 查看 | |
| 文件日志 | 独立文件，需要配置轮转，但更直观 | ✓ |
| 两者都要 | 双重记录，更完整但需要更多配置 | |

**User's choice:** 文件日志
**Notes:** 更直观，便于问题排查

---

## 日志配置 - 级别

| Option | Description | Selected |
|--------|-------------|----------|
| INFO | 平衡信息量和日志大小，适合生产环境 | ✓ |
| WARNING | 仅记录错误，日志量小，但可能漏掉重要信息 | |
| DEBUG | 详细日志，适合调试，但文件增长快 | |

**User's choice:** INFO
**Notes:** 适合生产环境

---

## Claude's Discretion

- 日志文件轮转配置（可使用 logrotate）
- 具体的 systemd service 文件路径和命名
- Gunicorn 配置文件格式（gunicorn.conf.py 或命令行参数）

## Deferred Ideas

None — discussion stayed within phase scope