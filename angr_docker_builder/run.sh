#!/bin/bash
echo "=== 运行容器 ==="

CONTAINER_NAME="angr-ctf"
IMAGE_NAME="angr-ctf:latest"

# 选择运行时
if command -v podman >/dev/null 2>&1; then
  echo "使用 Podman..."
  RUNTIME="podman"
elif command -v docker >/dev/null 2>&1; then
  echo "使用 Docker..."
  RUNTIME="docker"
else
  echo "未找到 podman 或 docker，请先安装其中之一。"
  exit 1
fi

# 停止并删除可能存在的同名容器
echo "清理旧容器..."
$RUNTIME stop $CONTAINER_NAME 2>/dev/null || true
$RUNTIME rm $CONTAINER_NAME 2>/dev/null || true

# 运行新容器
echo "启动新容器..."
$RUNTIME run -it --platform=linux/amd64 --rm \
    --name $CONTAINER_NAME \
    -v "$(pwd)":/workspace \
    --workdir /workspace \
    $IMAGE_NAME

