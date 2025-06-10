#!/bin/bash
# run_server.sh
# 启动 Shadowsocks 服务器的脚本
# 确保在 server/ 目录下运行此脚本

# 获取脚本所在的目录
SCRIPT_DIR=$(dirname "$0")

# 切换到脚本所在的目录 (即 server/ 目录)
cd "$SCRIPT_DIR" || { echo "无法切换到目录 $SCRIPT_DIR"; exit 1; }

echo "正在启动 Shadowsocks 服务器..."
python shadowsocks_core/server.py

# 可选: 添加错误处理或日志记录
if [ $? -ne 0 ]; then
    echo "Shadowsocks 服务器启动失败。"
    exit 1
fi
echo "Shadowsocks 服务器已启动。"

# 如果想让服务在前台运行以便调试，则移除 '&'。
# 否则，使用 'nohup ./run_server.sh &' 在后台运行。