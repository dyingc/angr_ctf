# 基于官方angr镜像构建RE+MCP沙盒环境
FROM angr/angr:latest

# 设置环境变量
ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# 切换到root用户来安装包
USER root

# 更新包管理器并安装系统依赖
RUN apt-get update && apt-get install -y \
    # 核心编译工具链
    gcc \
    g++ \
    libc6-dev \
    # 32位支持
    gcc-multilib \
    g++-multilib \
    libc6-dev-i386 \
    # 构建工具（添加meson和ninja-build用于Rizin）
    make \
    cmake \
    build-essential \
    meson \
    ninja-build \
    pkg-config \
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
    jq \
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
    # Rizin/RE工具依赖
    libffi-dev \
    libssl-dev \
    libgomp1 \
    zlib1g-dev \
    libbz2-dev \
    liblzma-dev \
    busybox-static \
    # 清理apt缓存以减小镜像大小
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /bin/busybox /usr/local/bin/grep

# 方案1：使用预编译的radare2包（推荐）
RUN apt-get update && apt-get install -y radare2 && apt-get clean && rm -rf /var/lib/apt/lists/*

# 方案2：如果需要最新版本，使用静态二进制安装
# RUN curl -L https://github.com/radareorg/radare2/releases/download/5.9.0/radare2_5.9.0_amd64.deb -o /tmp/radare2.deb \
#     && dpkg -i /tmp/radare2.deb || apt-get install -f -y \
#     && rm /tmp/radare2.deb

# 方案3：从源码编译（如果确实需要最新版本）
# 先设置更安全的编译环境
# RUN git clone --depth 1 https://github.com/radareorg/radare2.git /tmp/radare2 \
#     && cd /tmp/radare2 \
#     && export CC=gcc \
#     && export CXX=g++ \
#     && sys/user.sh \
#     && make install \
#     && cd / && rm -rf /tmp/radare2

# 安装Rizin v0.8.1（保持原有方式，通常不会有问题）
RUN git clone --depth 1 --branch v0.8.1 https://github.com/rizinorg/rizin.git /tmp/rizin \
    && cd /tmp/rizin \
    && meson setup build \
    && meson compile -C build \
    && meson install -C build \
    && cd / && rm -rf /tmp/rizin

# 安装rz-ghidra插件
RUN git clone --depth 1 --recurse-submodules https://github.com/rizinorg/rz-ghidra.git /tmp/rz-ghidra \
    && cmake -S /tmp/rz-ghidra -B /tmp/rz-ghidra/build -DCMAKE_INSTALL_PREFIX=/usr/local \
    && cmake --build /tmp/rz-ghidra/build -- -j$(nproc) \
    && cmake --install /tmp/rz-ghidra/build \
    && rm -rf /tmp/rz-ghidra \
    && ldconfig

# 确保angr用户可以使用sudo
RUN echo "angr ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# 创建工作目录
RUN mkdir -p /workspace && chown angr:angr /workspace

# 切换回angr用户
USER angr

# 安装 uv 包管理器（MCP推荐的包管理器），并设置正确的PATH
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/home/angr/.local/bin:$PATH"

# 激活angr虚拟环境并升级基础包
RUN bash -c "source /home/angr/.venv/bin/activate && \
    pip install --upgrade pip setuptools wheel"

# 安装MCP相关依赖
RUN bash -c "source /home/angr/.venv/bin/activate && \
    pip install --no-cache-dir \
        'mcp[cli]>=1.11.0' \
        'ipython>=8.37.0' \
        'langchain-core>=0.3.68' \
        'pydantic>=2.11.7' \
        'pyyaml>=6.0.2' \
        'pytest>=8.0.0'"

# 安装RE相关Python包（包括r2pipe和rzpipe）
RUN bash -c "source /home/angr/.venv/bin/activate && \
    pip install --no-cache-dir \
        'pwntools>=4.14.1' \
        'r2pipe' \
        'rzpipe>=0.6.2' \
        'capstone' \
        requests \
        flask \
        jinja2"

# 尝试安装其他可选包（如果失败不会中断构建）
RUN bash -c "source /home/angr/.venv/bin/activate && \
    (pip install --no-cache-dir z3-solver || echo 'z3-solver installation failed') && \
    (pip install --no-cache-dir keystone-engine || echo 'keystone-engine installation failed') && \
    (pip install --no-cache-dir unicorn || echo 'unicorn installation failed')"

# 设置工作目录
WORKDIR /workspace

# 创建激活angr环境的别名和环境设置
RUN echo 'alias angr-env="source /home/angr/.venv/bin/activate"' >> /home/angr/.bashrc && \
    echo 'source /home/angr/.venv/bin/activate' >> /home/angr/.bashrc && \
    echo 'export PATH="/home/angr/.local/bin:$PATH"' >> /home/angr/.bashrc

# 创建环境测试脚本
RUN echo '#!/bin/bash\n\
source /home/angr/.venv/bin/activate\n\
echo "=== MCP + RE + Angr Environment Test ==="\n\
echo "Virtual environment: $VIRTUAL_ENV"\n\
echo "Python path: $(which python)"\n\
echo "UV path: $(which uv)"\n\
echo ""\n\
echo "Python version:"\n\
python --version\n\
echo ""\n\
echo "=== Testing Core RE Packages ==="\n\
python -c "import angr; print(f\"✓ angr: {angr.__version__}\")" 2>/dev/null || echo "✗ angr import failed"\n\
python -c "import pwn; print(f\"✓ pwntools: {pwn.version}\")" 2>/dev/null || echo "✗ pwntools import failed"\n\
python -c "import r2pipe; print(f\"✓ r2pipe: {r2pipe.version()}\")" 2>/dev/null || echo "✗ r2pipe import failed"\n\
python -c "import rzpipe; print(f\"✓ rzpipe: {rzpipe.version()}\")" 2>/dev/null || echo "✗ rzpipe import failed"\n\
python -c "import capstone; print(f\"✓ capstone: {capstone.__version__}\")" 2>/dev/null || echo "✗ capstone import failed"\n\
echo ""\n\
echo "=== Testing MCP Packages ==="\n\
python -c "import mcp; print(\"✓ mcp package: available\")" 2>/dev/null || echo "✗ mcp import failed"\n\
echo "✓ MCP CLI: $(mcp version | awk '\''{print $NF}'\'')" 2>/dev/null || echo "✗ mcp is not available"\n\
python -c "import pydantic; print(f\"✓ pydantic: {pydantic.__version__}\")" 2>/dev/null || echo "✗ pydantic import failed"\n\
python -c "import yaml; print(f\"✓ pyyaml: {yaml.__version__}\")" 2>/dev/null || echo "✗ pyyaml import failed"\n\
python -c "import langchain_core as lc; print(f\"✓ langchain-core: {lc.__version__}\")" 2>/dev/null || echo "✗ langchain-core import failed"\n\
echo ""\n\
echo "=== Testing RE Tools ==="\n\
which r2 >/dev/null && echo "✓ radare2: $(r2 -v | head -n1)" || echo "✗ radare2: not found"\n\
which rizin >/dev/null && echo "✓ rizin: $(rizin -version | head -n1)" || echo "✗ rizin: not found"\n\
which gdb >/dev/null && echo "✓ gdb: $(gdb --version | head -1 | awk '\''{print $NF}'\'')" || echo "✗ gdb: not found"\n\
which objdump >/dev/null && echo "✓ objdump: $(objdump --version | head -1 | awk '\''{print $NF}'\'')" || echo "✗ objdump: not found"\n\
echo ""\n\
echo "=== Testing rz-ghidra Plugin ==="\n\
rizin -q -c "Lc" /bin/ls | grep -q ghidra && echo "✓ rz-ghidra: loaded" || echo "✗ rz-ghidra: not loaded"\n\
echo ""\n\
echo "=== Testing Compilation Environment ==="\n\
echo "int main(){return 0;}" > /tmp/test.c\n\
gcc -m32 -o /tmp/test32 /tmp/test.c 2>/dev/null && echo "✓ 32-bit compilation: OK" || echo "✗ 32-bit compilation: FAILED"\n\
gcc -o /tmp/test64 /tmp/test.c 2>/dev/null && echo "✓ 64-bit compilation: OK" || echo "✗ 64-bit compilation: FAILED"\n\
rm -f /tmp/test.c /tmp/test32 /tmp/test64\n\
echo ""\n\
echo "=== Environment Ready! ==="\n\
echo "Available tools:"\n\
echo "• Angr for symbolic execution"\n\
echo "• Radare2 with r2pipe for RE analysis"\n\
echo "• Rizin with rzpipe and rz-ghidra for decompilation"\n\
echo "• Pwntools for exploitation"\n\
echo "• MCP framework for AI integration"\n\
echo "• uv for modern Python package management"\n\
echo "Virtual environment is automatically activated"' > /home/angr/test-env.sh

RUN chmod +x /home/angr/test-env.sh

# 默认启动bash并激活angr环境
CMD ["/bin/bash", "-c", "source /home/angr/.venv/bin/activate && echo 'RE + MCP + Angr 环境已就绪！运行 /home/angr/test-env.sh 来测试环境' && /bin/bash"]
