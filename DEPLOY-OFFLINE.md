# 离线部署指南

本文档说明如何在无法访问互联网的服务器上部署周报管理系统。

## 前置条件

目标服务器需要：
- Ubuntu 22.04 LTS（或类似 Linux 发行版）
- Python 3.10+ 已安装
- 有足够的磁盘空间（约 500MB）

---

## 步骤 1：在有网络的机器上准备安装包

### 1.1 下载 Python 依赖包

```bash
# 进入项目目录
cd /home/one/weekly

# 创建 wheel 包目录
mkdir -p offline_packages

# 下载所有依赖的 wheel 包
pip download -r requirements.txt -d offline_packages/

# 查看下载的包
ls offline_packages/
```

### 1.2 打包项目代码

```bash
# 创建部署包目录
mkdir -p deploy_package

# 复制项目文件（排除虚拟环境和缓存）
cp -r app.py config.py extensions.py models.py forms.py routes.py utils.py deploy_package/
cp -r templates static instance deploy_package/ 2>/dev/null || true
cp requirements.txt gunicorn.conf.py weekly.service logrotate.weekly deploy_package/
cp -r tests deploy_package/  # 可选：测试文件

# 复制依赖包
cp -r offline_packages deploy_package/

# 打包
tar -czvf weekly-offline.tar.gz deploy_package/
```

---

## 步骤 2：传输到目标服务器

使用 U 盘、内网传输或其他方式将 `weekly-offline.tar.gz` 复制到目标服务器。

```bash
# 例如使用 scp（如果内网可通）
scp weekly-offline.tar.gz user@target-server:/home/user/
```

---

## 步骤 3：在目标服务器上安装

### 3.1 解压部署包

```bash
cd /home/user
tar -xzvf weekly-offline.tar.gz
cd deploy_package
```

### 3.2 创建虚拟环境

```bash
# 确保 Python 3 已安装
python3 --version

# 创建虚拟环境
python3 -m venv .venv

# 激活虚拟环境
source .venv/bin/activate
```

### 3.3 离线安装依赖

```bash
# 从本地 wheel 包安装
pip install --no-index --find-links=offline_packages/ -r requirements.txt
```

### 3.4 创建必要的目录

```bash
# 创建日志目录
sudo mkdir -p /var/log/weekly
sudo chown $USER:$USER /var/log/weekly

# 创建上传目录（如果不存在）
mkdir -p uploads

# 创建数据库目录
mkdir -p instance
```

### 3.5 设置环境变量（可选但推荐）

```bash
# 创建环境变量文件
cat > .env << 'EOF'
SECRET_KEY=your-secret-key-here-change-me
SECURITY_PASSWORD_SALT=your-salt-here-change-me
DATABASE_URL=sqlite:///instance/app.db
EOF

# 或直接设置系统环境变量
export SECRET_KEY="your-secret-key-here"
export SECURITY_PASSWORD_SALT="your-salt-here"
```

### 3.6 测试运行

```bash
# 初始化数据库并测试启动
python app.py

# 或使用 Gunicorn 测试
.venv/bin/gunicorn --config gunicorn.conf.py app:app
```

访问 `http://服务器IP:5000` 验证应用正常运行。

---

## 步骤 4：配置系统服务（生产环境）

### 4.1 安装用户级 systemd 服务（推荐，无需 sudo）

```bash
# 运行安装脚本并配置服务
./install.sh --service

# 启动服务
systemctl --user start weekly

# 查看状态
systemctl --user status weekly

# 开机自启（用户未登录也运行）
loginctl enable-linger $USER
```

**用户级服务管理命令：**

| 操作 | 命令 |
|------|------|
| 启动 | `systemctl --user start weekly` |
| 停止 | `systemctl --user stop weekly` |
| 重启 | `systemctl --user restart weekly` |
| 状态 | `systemctl --user status weekly` |
| 查看日志 | `tail -f logs/gunicorn-error.log` |

### 4.2 安装系统级 systemd 服务（需要 sudo）

如果需要系统级服务（所有用户可用）：

```bash
# 复制服务文件
sudo cp weekly.service /etc/systemd/system/

# 修改服务文件中的路径
sudo nano /etc/systemd/system/weekly.service

# 重新加载并启动
sudo systemctl daemon-reload
sudo systemctl enable weekly
sudo systemctl start weekly
```

### 4.2 配置日志轮转

```bash
# 复制 logrotate 配置
sudo cp logrotate.weekly /etc/logrotate.d/weekly

# 测试配置
sudo logrotate -d /etc/logrotate.d/weekly
```

---

## 步骤 5：验证部署

```bash
# 检查服务状态
sudo systemctl status weekly

# 检查日志
tail -f /var/log/weekly/app.log
tail -f /var/log/weekly/gunicorn-error.log

# 检查数据库
sqlite3 instance/app.db ".tables"

# 检查 WAL 模式
sqlite3 instance/app.db "PRAGMA journal_mode;"
# 应返回 "wal"
```

---

## 常见问题

### Q1: pip install 报错找不到某些包

某些包可能需要编译依赖。在有网络的机器上确保下载了所有依赖：

```bash
# 包括依赖的依赖
pip download -r requirements.txt -d offline_packages/ --no-deps
pip download -r requirements.txt -d offline_packages/
```

### Q2: 数据库初始化失败

手动初始化数据库：

```bash
source .venv/bin/activate
python -c "from app import app, db; app.app_context().push(); db.create_all()"
```

### Q3: 权限问题

```bash
# 确保目录权限正确
chown -R $USER:$USER /home/user/weekly
chown -R $USER:$USER /var/log/weekly
```

### Q4: 端口被占用

```bash
# 检查端口占用
sudo lsof -i :5000

# 修改 gunicorn.conf.py 中的端口
bind = "0.0.0.0:5001"
```

---

## 部署检查清单

- [ ] Python 3.10+ 已安装
- [ ] 虚拟环境已创建
- [ ] 所有依赖已离线安装
- [ ] 数据库已初始化
- [ ] 日志目录已创建
- [ ] 环境变量已设置（SECRET_KEY 等）
- [ ] systemd 服务已配置
- [ ] 应用可通过浏览器访问
- [ ] 日志正常写入

---

## 更新应用

当需要更新应用时：

1. 在有网络的机器上准备新的部署包
2. 传输到目标服务器
3. 停止服务：`sudo systemctl stop weekly`
4. 备份数据库：`cp instance/app.db instance/app.db.backup`
5. 替换代码文件
6. 如果有新依赖：`pip install --no-index --find-links=offline_packages/ -r requirements.txt`
7. 启动服务：`sudo systemctl start weekly`