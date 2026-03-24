# 周报管理系统

一个基于 Flask 的周报管理系统，用于软件开发团队的周报提交、管理和导出。

## 功能特性

- **用户认证** - 注册、登录、登出、密码重置
- **周报管理** - 创建、编辑、删除周报，支持富文本编辑（CKEditor）
- **权限控制** - 基于角色的访问控制（view_self/view_group/view_all/edit_database）
- **分组管理** - 用户分组，组长可查看组员周报
- **Excel 导出** - 批量导出周报到 Excel 文件
- **主题切换** - 支持 Bootstrap Bootswatch 主题
- **文件上传** - CKEditor 图片上传支持
- **后台管理** - Flask-Admin 管理界面

## 技术栈

- **后端**: Python 3.10+, Flask 3.0.3
- **数据库**: SQLite（支持 WAL 模式）
- **ORM**: SQLAlchemy, Flask-SQLAlchemy
- **认证**: Flask-Security
- **前端**: Bootstrap 5, CKEditor 4
- **WSGI 服务器**: Gunicorn
- **测试**: pytest

## 项目结构

```
weekly/
├── app.py              # 应用入口，创建 Flask 实例
├── config.py           # 配置类
├── extensions.py       # Flask 扩展初始化
├── models.py           # 数据库模型
├── forms.py            # WTForms 表单
├── routes.py           # 路由处理器
├── utils.py            # 工具函数
├── instance/           # 数据库文件目录
│   └── app.db
├── templates/          # Jinja2 模板
├── static/             # 静态文件
├── tests/              # 单元测试
├── gunicorn.conf.py    # Gunicorn 配置
├── weekly.service      # systemd 服务配置
└── requirements.txt    # Python 依赖
```

## 快速开始

### 环境要求

- Python 3.10+
- pip

### 安装步骤

```bash
# 1. 克隆项目
git clone <repository-url>
cd weekly

# 2. 创建虚拟环境
python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS
# 或 .venv\Scripts\activate  # Windows

# 3. 安装依赖
pip install -r requirements.txt

# 4. 设置环境变量
export SECRET_KEY="your-secret-key"
export SECURITY_PASSWORD_SALT="your-salt"

# 5. 运行应用
python app.py
```

访问 http://localhost:5000

### 生产部署

```bash
# 使用 Gunicorn
gunicorn --config gunicorn.conf.py app:app

# 或配置为 systemd 服务
sudo cp weekly.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable weekly
sudo systemctl start weekly
```

详细部署指南请参考 [DEPLOY-OFFLINE.md](DEPLOY-OFFLINE.md)。

## 配置

### 环境变量

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `SECRET_KEY` | Flask 密钥 | 内置值（生产环境必须更改） |
| `SECURITY_PASSWORD_SALT` | 密码加密盐值 | 内置值（生产环境必须更改） |
| `DATABASE_URL` | 数据库 URL | `sqlite:///instance/app.db` |
| `FLASK_DEBUG` | 调试模式 | `false` |
| `PORT` | 监听端口 | `5000` |

### 数据库配置

应用启动时会自动创建数据库表。SQLite WAL 模式默认启用，优化并发性能。

## 权限系统

系统支持以下权限：

| 权限 | 说明 |
|------|------|
| `view_self` | 查看自己的周报 |
| `view_group` | 查看所在组的周报 |
| `view_all` | 查看所有周报 |
| `edit_database` | 编辑数据库（管理员权限） |

## API 路由

| 路由 | 方法 | 说明 |
|------|------|------|
| `/` | GET | 首页 |
| `/login` | GET, POST | 登录 |
| `/logout` | GET | 登出 |
| `/register` | GET, POST | 注册 |
| `/create_records` | GET, POST | 创建周报 |
| `/edit_record/<id>` | GET, POST | 编辑周报 |
| `/delete_record/<id>` | POST | 删除周报 |
| `/manage_records` | GET | 周报列表 |
| `/download_records` | POST | 导出 Excel |
| `/config` | GET, POST | 用户设置 |
| `/admin` | GET | 管理后台 |

## 测试

```bash
# 运行所有测试
pytest

# 带覆盖率报告
pytest --cov=app --cov=models --cov=routes --cov=utils

# 详细输出
pytest -v
```

## 日志

生产环境日志位于：
- `/var/log/weekly/app.log` - 应用日志
- `/var/log/weekly/gunicorn-access.log` - 访问日志
- `/var/log/weekly/gunicorn-error.log` - 错误日志

日志自动轮转，保留 14 天。

## 开发

### 代码风格

- Python 代码遵循 PEP 8
- 使用 UTF-8 编码
- 模块顶部添加编码声明：`# -*- coding: utf-8 -*-`

### 添加新功能

1. 在 `models.py` 添加数据模型
2. 在 `forms.py` 添加表单类
3. 在 `routes.py` 添加路由处理
4. 在 `templates/` 添加模板
5. 编写测试用例

## 许可证

MIT License

## 更新日志

### v1.0 (2026-03-24)

- 生产级 WSGI 服务器部署（Gunicorn + systemd）
- 数据库会话管理与错误处理
- SQLite WAL 模式优化并发性能
- 单元测试覆盖（62 测试，68% 覆盖率）
- 代码模块化重构