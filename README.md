# angr CTF 完整安装和使用指南

## 概述

angr CTF 是一个专门设计的 Capture The Flag 挑战集，用于学习 angr 二进制分析框架的符号执行功能。本指南将详细介绍如何在 macOS 和 Linux 系统上构建、安装和游玩 angr CTF 挑战。

## 系统要求

### 通用要求
- Python 3.8 或更高版本
- Git
- 至少 4GB 内存（推荐 8GB+）
- 10GB 可用磁盘空间

### macOS 特定要求
- macOS 10.14 或更高版本
- Xcode 命令行工具或完整 Xcode
- Homebrew（推荐）

### Linux 特定要求
- Ubuntu 18.04+、Debian 10+、CentOS 7+ 或其他主流发行版
- GCC 编译工具链
- Make 和 CMake

## 环境准备

### macOS 环境设置

#### 1. 安装 Xcode 命令行工具
```bash
# 安装命令行工具
xcode-select --install

# 验证安装
gcc --version
```

#### 2. 安装 Homebrew（如果尚未安装）
```bash
# 安装 Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 安装必要工具
brew install python3 git cmake
```

#### 3. 设置 Python 环境
```bash
# 验证 Python 版本
python3 --version

# 创建虚拟环境（推荐）
python3 -m venv angr_ctf_env
source angr_ctf_env/bin/activate

# 升级 pip
pip install --upgrade pip
```

### Linux 环境设置

#### Ubuntu/Debian 系统
```bash
# 更新软件包列表
sudo apt update
sudo apt upgrade -y

# 安装必要依赖
sudo apt install -y python3 python3-pip python3-venv git build-essential cmake
sudo apt install -y libffi-dev libssl-dev libtool pkg-config

# 创建虚拟环境
python3 -m venv angr_ctf_env
source angr_ctf_env/bin/activate

# 升级 pip
pip install --upgrade pip
```

#### CentOS/RHEL 系统
```bash
# 安装 EPEL 仓库
sudo yum install -y epel-release

# 安装必要依赖
sudo yum groupinstall -y "Development Tools"
sudo yum install -y python3 python3-pip python3-devel git cmake
sudo yum install -y libffi-devel openssl-devel

# 创建虚拟环境
python3 -m venv angr_ctf_env
source angr_ctf_env/bin/activate

# 升级 pip
pip install --upgrade pip
```

#### Arch Linux 系统
```bash
# 更新系统
sudo pacman -Syu

# 安装必要依赖
sudo pacman -S python python-pip git base-devel cmake

# 创建虚拟环境
python -m venv angr_ctf_env
source angr_ctf_env/bin/activate

# 升级 pip
pip install --upgrade pip
```

## 安装 angr

### 方法一：通过 PyPI 安装（推荐）
```bash
# 激活虚拟环境
source angr_ctf_env/bin/activate

# 安装 angr
pip install angr

# 验证安装
python -c "import angr; print('angr version:', angr.__version__)"
```

### 方法二：从源码安装
```bash
# 克隆 angr 仓库
git clone https://github.com/angr/angr.git
cd angr

# 安装开发版本
pip install -e .
```

### 方法三：使用 Docker（跨平台）
```bash
# 拉取 angr Docker 镜像
docker pull angr/angr

# 运行容器（替代本地安装）
docker run -it -v $(pwd):/workspace angr/angr

# 在容器内工作
cd /workspace
```

## 获取和构建 angr CTF

### 1. 克隆 angr CTF 仓库
```bash
# 克隆项目
git clone https://github.com/jakespringer/angr_ctf.git
cd angr_ctf

# 查看可用挑战
ls -la
```

### 2. 理解项目结构
```
angr_ctf/
├── 00_angr_find/                 # 第一个挑战：基础查找
├── 01_angr_avoid/                # 第二个挑战：避免条件
├── 02_angr_find_condition/       # 第三个挑战：条件判断
├── ...                           # 更多挑战
├── dist/                         # 预构建的二进制文件
├── package.py                    # 批量构建脚本
├── Makefile                      # 自动化构建
└── README                        # 项目说明
```

### 3. 构建单个挑战
```bash
# 进入第一个挑战目录
cd 00_angr_find

# 查看文件结构
ls -la
# 输出：
# 00_angr_find.c.jinja     # C 源码模板
# generate.py              # 生成脚本
# scaffold00.py            # 解题模板
# description.txt          # 挑战描述

# 生成二进制文件
python generate.py 1234 00_angr_find

# 验证生成的文件
file 00_angr_find
chmod +x 00_angr_find
```

### 4. 批量构建所有挑战
```bash
# 返回主目录
cd ..

# 使用 package.py 批量构建
python package.py

# 或使用 Makefile（如果可用）
make USERS='player' local
```

## 解题流程

### 1. 分析挑战结构
```bash
# 进入挑战目录
cd 00_angr_find

# 查看挑战描述
cat description.txt

# 分析二进制文件
file 00_angr_find
objdump -d 00_angr_find | head -50

# 运行程序了解行为
./00_angr_find
# 输入一些测试数据观察输出
```

### 2. 编写解题脚本
```python
# 基于 scaffold00.py 修改
import angr
import sys

def main(argv):
    # 1. 创建 angr 项目
    path_to_binary = './00_angr_find'
    project = angr.Project(path_to_binary, auto_load_libs=False)

    # 2. 创建初始状态
    initial_state = project.factory.entry_state(
        args=[path_to_binary],
        add_options=angr.options.unicorn
    )

    # 3. 创建模拟管理器
    simulation = project.factory.simgr(initial_state)

    # 4. 定义目标和避免地址
    # 通过静态分析或动态调试找到这些地址
    print_good_address = 0x8048678  # "Good Job!" 输出位置
    print_bad_address = 0x8048695   # "Try again." 输出位置

    # 5. 执行符号探索
    simulation.explore(find=print_good_address, avoid=print_bad_address)

    # 6. 提取解决方案
    if simulation.found:
        solution_state = simulation.found[0]

        # 获取标准输入的符号解
        solution = solution_state.posix.dumps(sys.stdin.fileno())
        print("[+] Success! Solution is: {}".format(solution.decode("utf-8")))
        return solution
    else:
        raise Exception('Could not find the solution')

if __name__ == '__main__':
    main(sys.argv)
```

### 3. 运行解题脚本
```bash
# 激活虚拟环境
source ../angr_ctf_env/bin/activate

# 运行解题脚本
python3 scaffold00.py

# 或运行自定义脚本
python3 solve.py
```

### 4. 验证解决方案
```bash
# 使用找到的解决方案测试程序
echo "JXWVXRKX" | ./00_angr_find
# 应该输出 "Good Job!"
```

## 挑战级别详解

### 入门级别（00-02）

#### 00_angr_find
- **学习目标**：基础符号执行和路径查找
- **关键技术**：`project.factory.entry_state()`, `simulation.explore(find=address)`
- **核心概念**：理解 angr 项目结构和基本工作流程

#### 01_angr_avoid
- **学习目标**：使用避免条件优化路径探索
- **关键技术**：`simulation.explore(find=good_addr, avoid=bad_addr)`
- **核心概念**：路径剪枝和状态空间管理

#### 02_angr_find_condition
- **学习目标**：基于运行时条件的动态路径判断
- **关键技术**：回调函数 `simulation.explore(find=find_condition)`
- **核心概念**：动态条件判断而非静态地址

### 中级级别（03-06）

#### 03_angr_symbolic_registers
- **学习目标**：符号寄存器操作
- **关键技术**：`state.regs.eax = claripy.BVS('symbolic_reg', 32)`
- **核心概念**：寄存器级符号化

#### 04_angr_symbolic_stack
- **学习目标**：符号栈操作
- **关键技术**：栈内存符号化和约束设置
- **核心概念**：栈内存模型

#### 05_angr_symbolic_memory
- **学习目标**：符号内存操作
- **关键技术**：`state.memory.store(address, symbolic_value)`
- **核心概念**：内存符号化

#### 06_angr_symbolic_dynamic_memory
- **学习目标**：动态内存（堆）符号化
- **关键技术**：堆内存管理和符号化
- **核心概念**：动态内存分析

### 高级级别（07+）

#### 07_angr_symbolic_file
- **学习目标**：文件系统符号化
- **关键技术**：SimFile 和文件系统模拟
- **核心概念**：I/O 符号化

#### 08_angr_constraints
- **学习目标**：复杂约束处理
- **关键技术**：约束求解器优化
- **核心概念**：约束系统

## 调试和故障排除

### 常见问题及解决方案

#### 1. 编译错误
```bash
# macOS 上缺少编译工具
xcode-select --install

# Linux 上缺少依赖
sudo apt install build-essential  # Ubuntu/Debian
sudo yum groupinstall "Development Tools"  # CentOS/RHEL
```

#### 2. Python 版本问题
```bash
# 确保使用正确的 Python 版本
python3 --version
which python3

# 重新创建虚拟环境
rm -rf angr_ctf_env
python3 -m venv angr_ctf_env
source angr_ctf_env/bin/activate
pip install angr
```

#### 3. angr 安装失败
```bash
# 清理 pip 缓存
pip cache purge

# 使用镜像源安装（国内用户）
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple angr

# 分步安装依赖
pip install unicorn-engine
pip install angr
```

#### 4. 内存不足
```bash
# 限制 angr 的内存使用
export ANGR_MAX_MEMORY=2G

# 使用精简模式
import angr
project = angr.Project(binary, auto_load_libs=False, use_sim_procedures=True)
```

#### 5. 性能优化
```python
# 启用 Unicorn 引擎加速
initial_state = project.factory.entry_state(add_options=angr.options.unicorn)

# 禁用不必要的分析
project = angr.Project(binary,
                      auto_load_libs=False,
                      use_sim_procedures=True)
```

### 调试技巧

#### 1. 启用详细日志
```python
import logging
logging.getLogger('angr').setLevel(logging.DEBUG)
```

#### 2. 状态检查
```python
# 检查模拟管理器状态
print("Active states:", len(simulation.active))
print("Dead states:", len(simulation.deadended))
print("Error states:", len(simulation.errored))
```

#### 3. 交互式调试
```python
# 使用 IPython 进行交互式调试
import IPython; IPython.embed()
```

## 进阶技巧

### 1. 自定义 Hook
```python
# Hook 函数实现自定义行为
@project.hook(0x40abcd, length=5)
def custom_hook(state):
    print("Hit custom hook!")
    # 自定义逻辑
    pass
```

### 2. 状态合并
```python
# 合并相似状态减少状态爆炸
simulation.use_technique(angr.exploration_techniques.Veritesting())
```

### 3. 路径优先级
```python
# 自定义探索策略
class CustomExploration(angr.ExplorationTechnique):
    def step(self, simgr, stash='active', **kwargs):
        # 自定义步进逻辑
        return simgr.step(stash=stash, **kwargs)

simulation.use_technique(CustomExploration())
```

## 学习资源

### 官方资源
- [angr 官方文档](https://docs.angr.io/)
- [angr GitHub 仓库](https://github.com/angr/angr)
- [angr CTF 仓库](https://github.com/jakespringer/angr_ctf)

### 社区资源
- [angr Discord 服务器](http://discord.angr.io)
- [angr 学术论文](https://www.cs.ucsb.edu/~vigna/publications/2016_SP_angrSoK.pdf)
- [angr 策略备忘单](https://github.com/bordig-f/angr-strategies)

### 相关CTF平台
- [picoCTF](https://picoctf.org/)
- [OverTheWire](https://overthewire.org/)
- [Crackmes.one](https://crackmes.one/)

## 总结

angr CTF 是学习二进制分析和符号执行的优秀平台。通过逐步完成挑战，您将：

1. **掌握 angr 核心概念**：项目、状态、模拟管理器
2. **学习符号执行技术**：路径探索、约束求解
3. **理解二进制分析**：静态分析与动态分析结合
4. **提升逆向工程技能**：自动化分析复杂程序

无论在 macOS 还是 Linux 上，都可以顺利运行 angr CTF。建议从简单挑战开始，逐步深入学习高级技术。遇到问题时，善用社区资源和官方文档，持续练习是掌握这项技术的关键。