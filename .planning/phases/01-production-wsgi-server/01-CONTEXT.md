# Phase 1: Production WSGI Server - Context

**Gathered:** 2026-03-23
**Status:** Ready for planning

<domain>
## Phase Boundary

将 Flask 开发服务器替换为生产级 WSGI 服务器（Gunicorn），解决 Flask 开发服务器在生产环境导致的 IO 过载问题。应用使用 systemd 管理，支持自动重启和日志记录。

</domain>

<decisions>
## Implementation Decisions

### WSGI 服务器选择
- **D-01:** 使用 Gunicorn 作为 WSGI 服务器
- **D-02:** Worker 类型使用 Sync（同步）模式，简单可靠

### 进程配置
- **D-03:** Worker 数量使用自动配置（2-4 个 worker，遵循 Gunicorn 推荐公式）
- **D-04:** 端口绑定 0.0.0.0:5000，保持当前可访问性
- **D-05:** 请求超时 30 秒（Gunicorn 默认值）

### 进程管理
- **D-06:** 使用 systemd 服务管理进程
- **D-07:** 配置自动重启策略，崩溃后自动恢复

### 日志配置
- **D-08:** 添加文件日志，日志级别 INFO
- **D-09:** 日志文件存放于标准位置（如 /var/log/weekly/）

### Claude's Discretion
- 日志文件轮转配置（可使用 logrotate）
- 具体的 systemd service 文件路径和命名
- Gunicorn 配置文件格式（gunicorn.conf.py 或命令行参数）

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### 现有代码分析
- `.planning/codebase/STACK.md` — 技术栈信息，Python 3.10 + Flask 3.0.3
- `.planning/codebase/ARCHITECTURE.md` — 应用架构，入口点 app.py:743-747
- `.planning/codebase/CONCERNS.md` — 已知问题，debug=True 问题在 line 747

### 需求文档
- `.planning/REQUIREMENTS.md` — STAB-01: 应用使用生产级 WSGI 服务器运行
- `.planning/ROADMAP.md` — Phase 1 目标和成功标准

</canonical_refs>

<code_context>
## Existing Code Insights

### 当前部署方式
- `app.py:743-747` — 当前使用 `app.run(host='0.0.0.0', debug=True)`
- 需要修改为生产环境启动方式
- `app` 对象已导出，可供 WSGI 服务器使用

### 已有配置
- 数据库连接池已配置 (`app.py:31-36`)
- 环境变量支持 `DATABASE_URL`, `SECRET_KEY` 等
- requirements.txt 存在，需要添加 gunicorn

### 集成点
- `app.py` 底部的 `if __name__ == '__main__'` 块需要修改
- 需要创建 gunicorn 配置或启动脚本
- 需要创建 systemd service 文件

</code_context>

<specifics>
## Specific Ideas

- 保持简单，Gunicorn 是 Python 生态最成熟的选择
- systemd 是 Ubuntu 原生服务管理器，无需额外安装
- 文件日志便于问题排查，配合 logrotate 自动轮转

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 01-production-wsgi-server*
*Context gathered: 2026-03-23*