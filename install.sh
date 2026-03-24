#!/bin/bash
# 离线安装脚本
# 使用方法:
#   ./install.sh          # 基础安装
#   ./install.sh --service # 安装并配置用户级 systemd 服务

set -e

INSTALL_SERVICE=false
if [ "$1" = "--service" ]; then
    INSTALL_SERVICE=true
fi

echo "========================================="
echo "  周报管理系统 离线安装脚本"
echo "========================================="

# 检查 Python 版本
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "检测到 Python 版本: $PYTHON_VERSION"

# 获取当前目录
APP_DIR=$(pwd)
APP_USER=$(whoami)

echo "安装目录: $APP_DIR"
echo "运行用户: $APP_USER"
echo ""

# [1/5] 创建虚拟环境
if [ ! -d ".venv" ]; then
    echo "[1/5] 创建虚拟环境..."
    python3 -m venv .venv
else
    echo "[1/5] 虚拟环境已存在，跳过"
fi

# [2/5] 激活虚拟环境并安装依赖
echo "[2/5] 激活虚拟环境..."
source .venv/bin/activate

echo "[3/5] 离线安装依赖包..."
pip install --no-index --find-links=offline_packages/ -r requirements.txt

# [4/5] 创建必要的目录
echo "[4/5] 创建应用目录..."
mkdir -p uploads instance logs

# 创建 gunicorn 日志配置（使用本地目录）
cat > gunicorn.conf.local.py << 'GUNICORN_CONF'
# gunicorn.conf.local.py
# 用户级部署配置（日志存放在本地目录）

import multiprocessing

bind = "0.0.0.0:5000"
backlog = 2048

workers = min(multiprocessing.cpu_count() * 2 + 1, 4)
worker_class = "sync"

timeout = 30
keepalive = 2
graceful_timeout = 30

# 使用本地日志目录
accesslog = "logs/gunicorn-access.log"
errorlog = "logs/gunicorn-error.log"
loglevel = "info"

proc_name = "weekly"

limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190
GUNICORN_CONF

# [5/5] 配置用户级 systemd 服务
echo "[5/5] 配置系统服务..."
if [ "$INSTALL_SERVICE" = true ]; then
    # 创建 systemd 用户目录
    mkdir -p ~/.config/systemd/user

    # 创建用户级 service 文件
    cat > ~/.config/systemd/user/weekly.service << SERVICE_EOF
[Unit]
Description=Weekly Report Management System
After=network.target

[Service]
Type=exec
WorkingDirectory=$APP_DIR

Environment="PATH=$APP_DIR/.venv/bin:/usr/local/bin:/usr/bin:/bin"
Environment="FLASK_DEBUG=0"

ExecStart=$APP_DIR/.venv/bin/gunicorn \\
    --config gunicorn.conf.local.py \\
    app:app

ExecReload=/bin/kill -s HUP \$MAINPID
KillMode=mixed
TimeoutStopSec=30
PrivateTmp=true

Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
SERVICE_EOF

    # 重新加载 systemd
    systemctl --user daemon-reload

    # 启用服务
    systemctl --user enable weekly

    echo "  → 用户级 systemd 服务已配置"
    echo "  → 服务文件: ~/.config/systemd/user/weekly.service"

    # 检查是否需要启用 lingering
    if [ ! -f "/var/lib/systemd/linger/$APP_USER" ]; then
        echo ""
        echo "  【提示】启用 lingering 以在用户未登录时也运行服务："
        echo "  loginctl enable-linger $APP_USER"
    fi
else
    echo "  → 跳过服务配置（使用 --service 参数启用）"
fi

echo ""
echo "========================================="
echo "  安装完成！"
echo "========================================="
echo ""

# 提示设置环境变量
echo "【重要】请设置环境变量："
echo ""
echo "  export SECRET_KEY='your-secret-key-here'"
echo "  export SECURITY_PASSWORD_SALT='your-salt-here'"
echo ""
echo "或添加到 ~/.bashrc："
echo ""
echo "  echo 'export SECRET_KEY=\"your-secret-key\"' >> ~/.bashrc"
echo "  echo 'export SECURITY_PASSWORD_SALT=\"your-salt-here\"' >> ~/.bashrc"
echo "  source ~/.bashrc"
echo ""

if [ "$INSTALL_SERVICE" = true ]; then
    echo "【管理服务】"
    echo ""
    echo "  启动:   systemctl --user start weekly"
    echo "  停止:   systemctl --user stop weekly"
    echo "  状态:   systemctl --user status weekly"
    echo "  重启:   systemctl --user restart weekly"
    echo "  查看日志: tail -f logs/gunicorn-error.log"
    echo ""
    echo "【开机自启】"
    echo ""
    echo "  启用 lingering（用户未登录也运行服务）："
    echo "  loginctl enable-linger \$USER"
    echo ""
else
    echo "【测试运行】"
    echo ""
    echo "  source .venv/bin/activate"
    echo "  python app.py"
    echo ""
    echo "【生产运行】"
    echo ""
    echo "  .venv/bin/gunicorn --config gunicorn.conf.local.py app:app"
    echo ""
    echo "【配置服务】"
    echo ""
    echo "  ./install.sh --service"
    echo ""
fi

echo "详细说明请参考 DEPLOY-OFFLINE.md"
echo ""
