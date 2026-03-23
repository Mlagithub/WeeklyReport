# Phase 5: Code Refactoring - Context

**Gathered:** 2026-03-23
**Status:** Ready for planning

<domain>
## Phase Boundary

代码结构更清晰易维护。将 monolithic app.py 拆分为独立模块，集中管理配置，保持所有现有功能正常运行。

</domain>

<decisions>
## Implementation Decisions

### 模块拆分策略
- **D-01:** 使用简单拆分方式，不使用 Flask Blueprints
- **D-02:** 将 app.py 拆分为以下模块：
  - `config.py` — 配置类和环境变量
  - `extensions.py` — Flask 扩展初始化 (db, security, admin, ckeditor)
  - `models.py` — 数据库模型 (Record, Role, User, Group, 关联表)
  - `forms.py` — WTForms 表单类
  - `routes.py` — 路由处理函数
  - `app.py` — 应用工厂和入口点

### 配置管理
- **D-03:** 创建基于类的配置 (Development, Production)
- **D-04:** 所有敏感配置从环境变量读取
- **D-05:** 保留本地开发默认值，生产环境必须设置环境变量
- **D-06:** 保持 SECRET_KEY 和 SECURITY_PASSWORD_SALT 当前值不变（否则密码失效）

### 重构范围
- **D-07:** 最小范围：文件拆分 + 配置集中 + 确保测试通过
- **D-08:** 不进行大规模逻辑修改
- **D-09:** 所有 62 个测试必须在重构后继续通过

### 小改进
- **D-10:** Record.date 列添加 index=True，优化日期查询性能
- **D-11:** 文件上传使用 UUID 生成唯一文件名，防止文件覆盖

### Claude's Discretion
- 具体文件拆分顺序
- 导入语句组织
- 配置类中的具体配置项列表

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### 现有代码分析
- `.planning/codebase/ARCHITECTURE.md` — 应用架构，模块边界
- `.planning/codebase/STRUCTURE.md` — 文件结构，关键代码位置
- `.planning/codebase/CONCERNS.md` — 已知问题，Monolithic Structure 问题
- `.planning/codebase/CONVENTIONS.md` — 编码约定

### 需求文档
- `.planning/REQUIREMENTS.md` — REFAC-01
- `.planning/ROADMAP.md` — Phase 5 目标和成功标准

### 现有代码
- `app.py` — 当前单体应用（748 行）
- `utils.py` — 工具类（保持不变）
- `tests/` — 测试文件（重构后必须通过）

</canonical_refs>

<code_context>
## Existing Code Insights

### app.py 当前结构
- Lines 27-55: 配置
- Lines 60-71: Schema migration helper
- Lines 73-86: 关联表定义
- Lines 89-183: 模型定义 (Record, Role, User, Group)
- Lines 184-213: Flask-Admin 视图
- Lines 215-310: WTForms 表单
- Lines 311-377: 辅助函数
- Lines 379-681: 路由处理
- Lines 683-747: 初始化和启动

### 拆分后导入关系
```
app.py
  ├── from config import Config
  ├── from extensions import db, security, admin, ckeditor
  ├── from models import Record, Role, User, Group, user_records, roles_users, users_groups
  ├── from forms import RecordForm, RecordFilterForm, ...
  └── from routes import * (or register blueprint)

extensions.py
  └── db = SQLAlchemy()
      security = Security()
      admin = Admin()
      ckeditor = CKEditor()

models.py
  ├── from extensions import db
  └── from flask_security import FsUserMixin, FsRoleMixin

forms.py
  ├── from extensions import db
  └── from flask_wtf import FlaskForm

routes.py
  ├── from flask import render_template, redirect, ...
  ├── from extensions import db, security
  ├── from models import Record, User, ...
  └── from forms import RecordForm, ...
```

### 配置敏感项
- SECRET_KEY — 当前硬编码，改为 os.environ.get('SECRET_KEY', '默认值')
- SECURITY_PASSWORD_SALT — 当前硬编码，改为 os.environ.get('SECURITY_PASSWORD_SALT', '默认值')
- DATABASE_URL — 已支持环境变量
- 注意：这两个值不能改变，否则所有现有密码失效

### 集成点
- 测试文件 tests/conftest.py 需要更新导入
- systemd 服务文件不受影响
- requirements.txt 不需要修改

</code_context>

<specifics>
## Specific Ideas

- 参考 Flask 官方大型应用结构建议
- 使用应用工厂模式创建 app
- 配置类使用 DevelopmentConfig 和 ProductionConfig
- Record.date 添加索引：`date = db.Column(db.Date(), index=True)`
- 上传文件名：`f"{uuid.uuid4().hex}_{filename}"`

</specifics>

<deferred>
## Deferred Ideas

### 不包含在本次重构中
- Flask Blueprints 重构 — 更复杂，当前简单拆分足够
- CSRF for CKEditor — 需要额外配置，留作后续
- XSS fix for build_edit_buttons — 需要模板修改，留作后续
- 迁移到 PostgreSQL — 超出当前范围
- Flask-Migrate/Alembic — 需要更多时间规划

</deferred>

---

*Phase: 05-code-refactoring*
*Context gathered: 2026-03-23*