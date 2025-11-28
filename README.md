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

## 安装 angr 和必要依赖

### 方法一：通过 PyPI 安装（推荐）
```bash
# 激活虚拟环境
source angr_ctf_env/bin/activate

# 安装 angr 和 angr CTF 必要依赖
pip install angr jinja2

# 可选：安装其他有用的工具
pip install ipython pwntools

# 验证安装
python -c "import angr, jinja2; print('angr version:', angr.__version__); print('jinja2 installed successfully')"
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
# 00_angr_find.c.jinja     # C 源码模板（注意是.jinja不是.templite）
# generate.py              # 生成脚本（需要jinja2依赖）
# scaffold00.py            # 解题模板
# __init__.py              # Python包文件

# 确保已安装jinja2
pip install jinja2

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

# 查看实际文件结构
ls -la
# 实际文件：
# - 00_angr_find.c.jinja   (C源码模板)
# - generate.py            (生成脚本)
# - scaffold00.py          (解题模板，包含挑战说明)
# - __init__.py            (Python包文件)

# 查看解题模板了解挑战要求
cat scaffold00.py

# 查看源码模板了解程序逻辑
cat 00_angr_find.c.jinja

# 生成二进制文件
python generate.py 1234 00_angr_find

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

本套 CTF 一共包含 00–17 共 18 个主线关卡，外加 1 个特殊关卡 `xx_angr_segfault`。建议按序通关，避免跨越过大难度梯度。

- 快速索引
  - 00_angr_find / 01_angr_avoid / 02_angr_find_condition
  - 03_angr_symbolic_registers / 04_angr_symbolic_stack / 05_angr_symbolic_memory / 06_angr_symbolic_dynamic_memory
  - 07_angr_symbolic_file / 08_angr_constraints
  - 09_angr_hooks / 10_angr_simprocedures / 11_angr_sim_scanf / 12_angr_veritesting
  - 13_angr_static_binary / 14_angr_shared_library
  - 15_angr_arbitrary_read / 16_angr_arbitrary_write / 17_angr_arbitrary_jump
  - xx_angr_segfault

### 入门（00–02）

#### 00_angr_find
- 学习目标：基础符号执行与路径查找
- 关键技术：`Project(...)`、`project.factory.entry_state()`、`simgr.explore(find=addr)`
- 核心概念：状态、路径、约束的最简闭环；如何定位 “Good job” 的打印位置或目标地址

#### 01_angr_avoid
- 学习目标：在探索时避开坏路径
- 关键技术：`simgr.explore(find=good, avoid=bad)`、多 find/avoid 组合
- 核心概念：路径剪枝与搜索空间控制，减少无效分支

#### 02_angr_find_condition
- 学习目标：用动态条件代替固定地址
- 关键技术：`find=lambda s: ...`、对输出/内存/寄存器做条件判断
- 核心概念：更贴近真实场景的“目标态”判定思路

### 基础进阶（03–08）

#### 03_angr_symbolic_registers
- 学习目标：寄存器符号化与求解
- 关键技术：`claripy.BVS(...)` 赋值给 `state.regs.*`，约束添加与求解
- 核心概念：从指令级视角理解符号执行的数据流

#### 04_angr_symbolic_stack
- 学习目标：栈变量/返回地址的建模与约束
- 关键技术：通过 `state.mem`/`state.stack_push/stack_pop` 操作栈
- 核心概念：调用约定、栈帧布局与符号化交互

#### 05_angr_symbolic_memory
- 学习目标：通用内存读写符号化
- 关键技术：`state.memory.store/load`、别名/指针寻址
- 核心概念：内存模型与地址可达性；避免过度符号化

#### 06_angr_symbolic_dynamic_memory
- 学习目标：堆与动态分配场景
- 关键技术：模拟 `malloc/free` 行为、堆块边界与越界约束
- 核心概念：动态内存管理与符号化对象生命周期

#### 07_angr_symbolic_file
- 学习目标：文件 I/O 的符号化
- 关键技术：`angr.storage.SimFile`、向 `state.posix` 挂载虚拟文件
- 核心概念：将外部输入建模为文件系统事件与字节流

#### 08_angr_constraints
- 学习目标：约束管理与求解器交互
- 关键技术：`state.solver.add/exactly_n_bits_set/...`、检查可满足性与最小解
- 核心概念：约束冗余、冲突定位与性能权衡

### 实战技巧（09–12）

#### 09_angr_hooks
- 学习目标：在指定地址/函数上打 Hook 改写语义
- 关键技术：`@project.hook(addr, length=...)`、`project.hook_symbol('puts', ...)`
- 核心概念：把难以模拟或无关逻辑“替换”为受控语义以加速探索

#### 10_angr_simprocedures
- 学习目标：用 SimProcedure 模拟库函数/系统调用
- 关键技术：自定义 `SimProcedure`、重定向 PLT/GOT、`use_sim_procedures=True`
- 核心概念：在静态或缺失依赖环境中恢复高层行为

#### 11_angr_sim_scanf
- 学习目标：处理 scanf 家族及格式化输入
- 关键技术：格式串解析、按格式构建/约束输入、`state.posix.stdin`
- 核心概念：I/O 与约束间的桥接，避免无界输入导致的状态爆炸

#### 12_angr_veritesting
- 学习目标：使用 Veritesting 缓解路径爆炸
- 关键技术：`angr.exploration_techniques.Veritesting()`、区域性路径合并
- 核心概念：在基本块区域内将多分支“总结”为单一大步

### 系统与链接（13–14）

#### 13_angr_static_binary
- 学习目标：分析静态链接二进制
- 关键技术：无外部依赖、更多 SimProcedures 介入、`auto_load_libs=False`
- 核心概念：当库函数不可动态解析时的替代策略与入口点选择

#### 14_angr_shared_library
- 学习目标：分析共享库（.so/.dylib）
- 关键技术：指定入口导出符号作为起点、PLT/GOT Hook、`main_opts` 配置
- 核心概念：非可执行主程序的建模；对导出 API 的单元级探索

### 内存与控制流（15–17）

#### 15_angr_arbitrary_read
- 学习目标：任意地址读原语的分析与利用建模
- 关键技术：约束地址范围、`state.memory.load(ptr, size)` 的可满足性检查
- 核心概念：读原语可导致信息泄露；通过约束使读到预期数据

#### 16_angr_arbitrary_write
- 学习目标：任意地址写原语的分析与利用建模
- 关键技术：`state.memory.store(ptr, value)`、写前/后状态对比与不变式
- 核心概念：控制关键指针/函数指针/返回地址以构造进一步劫持

#### 17_angr_arbitrary_jump
- 学习目标：控制流劫持（间接跳转/调用）
- 关键技术：约束 `state.regs.ip/eip/rip` 指向可控/可执行地址，避免坏区域
- 核心概念：从数据面（写原语）过渡到控制面（执行流）的一体化推演

### 特殊关卡

#### xx_angr_segfault
- 学习目标：处理崩溃/段错误情形下的探索与调试
- 关键技术：
  - 使用 `simgr` 的 `errored`/`unconstrained` 等分支检查崩溃原因
  - 通过 Hook/SimProcedure 仿真导致崩溃的指令/调用以继续探索
  - 利用 `state.inspect`/`breakpoint` 捕获非法读写并定位根因
- 核心概念：把“崩溃”作为线索而非终点，将错误路径转化为可控的分析上下文

提示与建议
- 按序闯关：每关引入新概念，后续题目往往复用前面技巧
- 控制搜索空间：合理使用 `avoid`、Hook 和 Veritesting
- 优先建模外部输入：stdin/argv/file/socket 都是常见数据面
- 记录关键地址：目标打印点、错误分支、间接跳转点、函数指针位置等

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

#### 3. jinja2 依赖问题
```bash
# 错误信息：ModuleNotFoundError: No module named 'jinja2'
# 解决方案：
pip install jinja2

# 或重新安装完整环境
pip install angr jinja2 ipython

# 验证安装
python -c "import jinja2; print('jinja2 version:', jinja2.__version__)"
```
```bash
# 清理 pip 缓存
pip cache purge

# 使用镜像源安装（国内用户）
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple angr

# 分步安装依赖
pip install unicorn-engine
pip install angr
```

#### 4. angr 安装失败
```bash
# 限制 angr 的内存使用
export ANGR_MAX_MEMORY=2G

# 使用精简模式
import angr
project = angr.Project(binary, auto_load_libs=False, use_sim_procedures=True)
```

#### 5. 内存不足
```python
# 启用 Unicorn 引擎加速
initial_state = project.factory.entry_state(add_options=angr.options.unicorn)

# 禁用不必要的分析
project = angr.Project(binary,
                      auto_load_libs=False,
                      use_sim_procedures=True)
```

#### 6. 性能优化

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
