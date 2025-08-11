# 基于官方angr镜像
FROM angr/angr:latest

# 切换到root用户来安装包
USER root

# 更新包管理器并安装编译工具和依赖
RUN apt-get update && apt-get install -y \
    # 核心编译工具链
    gcc \
    g++ \
    libc6-dev \
    # 32位支持（用于你的脚本中的-m32选项）
    gcc-multilib \
    g++-multilib \
    libc6-dev-i386 \
    # 构建工具
    make \
    cmake \
    build-essential \
    # 调试工具
    gdb \
    gdb-multiarch \
    # 其他有用的工具
    binutils \
    file \
    strace \
    ltrace \
    bsdmainutils \
    util-linux \
    # 网络和下载工具
    curl \
    wget \
    git \
    # 文本处理工具
    vim \
    nano \
    less \
    # 权限管理
    sudo \
    # Python开发工具
    python3-dev \
    python3-pip \
    # 清理apt缓存以减小镜像大小
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 切换回angr用户
USER angr

# 激活angr虚拟环境并安装必要的Python包
# 使用正确的虚拟境路径 /home/angr/.venv
RUN bash -c "source /home/angr/.venv/bin/activate && \
    pip install --upgrade pip && \
    pip install --no-cache-dir jinja2 && \
    echo 'jinja2 installed successfully'"

# 尝试安装其他包（如果失败不会中断构建）
RUN bash -c "source /home/angr/.venv/bin/activate && \
    (pip install --no-cache-dir requests flask || echo 'requests/flask installation failed') && \
    (pip install --no-cache-dir pwntools || echo 'pwntools installation failed')"

# 确保angr用户可以使用sudo（对于需要权限的操作）
USER root
RUN echo "angr ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# 创建工作目录
RUN mkdir -p /workspace && chown angr:angr /workspace

# 切换回angr用户
USER angr

# 设置工作目录
WORKDIR /workspace

# 创建一个激活angr环境的别名和测试脚本
RUN echo 'alias angr-env="source /home/angr/.venv/bin/activate"' >> /home/angr/.bashrc && \
    echo 'source /home/angr/.venv/bin/activate' >> /home/angr/.bashrc

# 创建一个方便的脚本来测试编译环境
RUN echo '#!/bin/bash\n\
source /home/angr/.venv/bin/activate\n\
echo "=== Testing compilation environment ==="\n\
echo "Virtual environment: $VIRTUAL_ENV"\n\
echo "Python path: $(which python)"\n\
echo "Pip path: $(which pip)"\n\
echo ""\n\
echo "GCC version:"\n\
gcc --version\n\
echo ""\n\
echo "Python and packages:"\n\
python --version\n\
python -c "import angr; print(f\"angr: {angr.__version__}\")" 2>/dev/null || echo "angr import failed"\n\
python -c "import jinja2; print(f\"jinja2: {jinja2.__version__}\")" 2>/dev/null || echo "jinja2 not installed"\n\
echo ""\n\
echo "Testing compilation:"\n\
echo "int main(){return 0;}" > /tmp/test.c\n\
gcc -m32 -o /tmp/test32 /tmp/test.c 2>/dev/null && echo "✓ 32-bit compilation: OK" || echo "✗ 32-bit compilation: FAILED"\n\
gcc -o /tmp/test64 /tmp/test.c 2>/dev/null && echo "✓ 64-bit compilation: OK" || echo "✗ 64-bit compilation: FAILED"\n\
rm -f /tmp/test.c /tmp/test32 /tmp/test64\n\
echo ""\n\
echo "=== Environment ready! ==="\n\
echo "Virtual environment is automatically activated"' > /home/angr/test-env.sh

RUN chmod +x /home/angr/test-env.sh

# 默认启动bash并激活angr环境
CMD ["/bin/bash", "-c", "source /home/angr/.venv/bin/activate && /bin/bash"]
