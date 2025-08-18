#!/bin/bash

# Dockerfile
MYLOC="$(dirname "$0")"
if [ '/' != "$(echo "${MYLOC}" | cut -c1)" ]; then
  if [ '.' = "${MYLOC}" ]; then
    MYLOC="$PWD"
  else
    MYLOC="$PWD/${MYLOC}"
  fi
fi
DOCKERFILE="${MYLOC}/Dockerfile"

# 构建和运行增强版angr容器的脚本

set -e  # 如果任何命令失败就退出

IMAGE_NAME="angr-ctf:latest"

echo "=== 构建增强版angr镜像 ==="

# 检查是否有Dockerfile
if [ ! -f "${DOCKERFILE}" ]; then
    echo "错误: 未找到Dockerfile，请确保Dockerfile在当前目录"
    exit 1
fi

# 构建镜像
echo "开始构建镜像..."
if command -v podman &> /dev/null; then
    echo "使用Podman构建..."
    podman build -f "${DOCKERFILE}" --platform=linux/amd64 -t $IMAGE_NAME .
    BUILD_CMD="podman"
elif command -v docker &> /dev/null; then
    echo "使用Docker构建..."
    docker build -f "${DOCKERFILE}" --platform=linux/amd64 -t $IMAGE_NAME .
    BUILD_CMD="docker"
else
    echo "错误: 未找到podman或docker命令"
    exit 1
fi

echo "镜像构建完成!"

echo ""
