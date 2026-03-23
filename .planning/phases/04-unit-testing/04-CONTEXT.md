# Phase 4: Unit Testing - Context

**Gathered:** 2026-03-23
**Status:** Ready for planning

<domain>
## Phase Boundary

添加核心功能单元测试覆盖，验证稳定性修复有效性。测试应覆盖认证、CRUD 操作、工具函数和权限逻辑。

</domain>

<decisions>
## Implementation Decisions

### 测试框架
- **D-01:** 使用 pytest 作为测试框架
- **D-02:** 配置 pytest fixtures 用于测试客户端和数据库设置

### 测试范围
- **D-03:** Full Coverage — 测试所有路由、所有模型、所有工具函数
- **D-04:** 必须覆盖的核心功能（成功标准）:
  - 用户认证函数 (login, register, logout)
  - Record CRUD 操作 (create, read, update, delete)
- **D-05:** 额外覆盖:
  - DateRange 工具类 (`utils.py:6-93`)
  - html_to_text 函数 (`utils.py:102-141`)
  - User 权限方法 (`app.py:106-161`)
  - 路由授权函数 (can_edit_record, get_allowed_usernames, build_record_query)

### 测试数据库策略
- **D-06:** 使用 in-memory SQLite 数据库 (`sqlite:///:memory:`)
- **D-07:** 每个测试函数独立的数据库状态（create_all/drop_all）
- **D-08:** 使用 pytest fixture 提供测试客户端和认证状态

### 覆盖率目标
- **D-09:** 不设置最低覆盖率百分比要求
- **D-10:** 重点验证核心路径正常工作，而非追求数字

### Claude's Discretion
- 测试文件组织结构 (单文件 vs 按模块分)
- 具体测试用例命名和边界条件
- fixture 的具体实现细节

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### 现有代码分析
- `.planning/codebase/TESTING.md` — 测试框架推荐，fixture 模板示例
- `.planning/codebase/ARCHITECTURE.md` — 模型和路由位置，数据流
- `.planning/codebase/CONVENTIONS.md` — 错误处理模式

### 需求文档
- `.planning/REQUIREMENTS.md` — TEST-01
- `.planning/ROADMAP.md` — Phase 4 目标和成功标准

### 现有代码
- `utils.py:6-93` — DateRange 类
- `utils.py:102-141` — html_to_text 函数
- `app.py:106-161` — User 模型和权限方法
- `app.py:379-681` — 路由定义

</canonical_refs>

<code_context>
## Existing Code Insights

### 可复用测试模式
- TESTING.md 已提供 pytest fixture 模板
- `static/db_table_data.json` — 可参考的种子数据格式

### 关键测试目标
**认证流程:**
- `app.py:431-441` — login 路由
- `app.py:409-429` — register 路由
- Flask-Security 的 verify_password

**CRUD 操作:**
- `app.py:476-495` — create_records
- `app.py:498-520` — edit_record
- `app.py:571-632` — manage_records (query)
- `app.py:654-678` — delete_record

**工具函数:**
- `utils.py:6-93` — DateRange 静态方法
- `utils.py:102-141` — html_to_text

**权限逻辑:**
- `app.py:106-161` — User.is_admin, all_permissions(), can_view_group()
- `app.py:331-359` — can_edit_record(), get_allowed_usernames()
- `app.py:361-377` — build_record_query()

### 集成点
- 需要添加 pytest, pytest-cov 到 requirements.txt
- 创建 tests/ 目录结构
- 配置 pytest (pyproject.toml 或 pytest.ini)

</code_context>

<specifics>
## Specific Ideas

- 测试应该验证 Phase 1-3 的稳定性修复有效（Gunicorn 部署、session 管理、WAL 模式）
- 使用 Flask test_client 进行集成测试
- 工具函数测试应该是纯单元测试（无数据库依赖）

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 04-unit-testing*
*Context gathered: 2026-03-23*