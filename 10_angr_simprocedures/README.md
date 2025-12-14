# 10_angr_simprocedures：用 SimProcedure 一次性替换高频校验函数（并与普通 hook / 后置约束做对比）

适用人群：刚入门 angr 的你，或未来的你（忘了细节时快速捡起来）。

本关的核心目标：当目标函数（如 `check_equals_*`）被调用“非常多次”时，不再在每个调用点做 hook，而是用 angr 的 SimProcedure 直接“替换整个函数”的行为，让每次调用都走你的 Python 实现。

与第 08 关“后置约束（post-hoc constraints）”的对比是本关理解的关键：何时改“函数语义”（SimProcedure），何时不改语义而仅在“检查点状态”上加约束（post-constraints）。


## TL;DR（要点速记）

- SimProcedure = 用 Python 写的“替身函数”，由 angr 统一处理参数传递、返回值、栈/寄存器细节。
- 当某函数被“多次调用”且逻辑明确可复现（无复杂副作用），用 SimProcedure 一劳永逸。
- 与“普通 hook”相比，SimProcedure更稳：不用手写 `esp/eax/ip` 操作；与“后置约束”相比，SimProcedure是“改语义”的方案，适合广泛替换重复调用。
- 当你需要直接重塑控制流（禁用检查、强制跳转等），普通 hook 更灵活；SimProcedure 更适合“等价替换函数语义”。
- 读取缓冲区要记得：`state.memory.load(ptr, size=...)` 的 `size` 通常应为“具体整数”；若参数来自函数形参，可用 `state.solver.eval(length)` 得到 Python int。
- 返回值位宽要对齐架构（本仓库 x86 → 32 位）：`claripy.BVV(1, 32)` / `claripy.BVV(0, 32)`。


## 1. 场景与动机

- 早先（第 09 关）你可能在某个地址 `project.hook(addr, ...)` 手写 Python 逻辑取栈上的参数、设 `eax`、手工“跳过 ret”。如果该函数只被调用一次或少数几次，这样做可以；但当它被调用“很多次”，维护与正确性就变差了。
- SimProcedure 让你只写一个 Python 类，替换同名符号，所有调用自动走你的实现，避免反复 hook 调用点或自己处理 calling convention 的琐碎细节。


## 2. 最小可用示例（结合 scaffold10.py）

下面摘自本关 scaffold（并加入更安全的 `size` 求值）：

```python
import angr
import claripy
import sys

def main(argv):
    path_to_binary = argv[1] if len(argv) > 1 else './binary/x32/10_angr_simprocedures'
    project = angr.Project(path_to_binary)

    initial_state = project.factory.entry_state(
        add_options={
            angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
        }
    )

    class ReplacementCheckEquals(angr.SimProcedure):
        # C 原型（从逆向得知，示意）：int check_equals(char* buf, int len)
        # run 的形参位置和数量要与被替换函数一致
        def run(self, to_check, length):
            # 注意：length 通常是具体参数（具体整数），但形态是 bitvector
            n = self.state.solver.eval(length)  # 将 BVV 求成 python int

            user_input_string = self.state.memory.load(to_check, size=n)

            # 目标字符串地址来自 scaffold10 的分析（全局只读数据区）
            check_against_string = self.state.memory.load(0x0804e02c, size=n)

            return claripy.If(
                user_input_string == check_against_string,
                claripy.BVV(1, 32),
                claripy.BVV(0, 32),
            )

    # 通过“符号名”统一替换整个函数
    # 说明：scaffold10 已经知道具体符号名（每次构建会不同）
    sym = project.loader.find_symbol('check_equals_ANBHYDCNMNRPQWPX').name
    project.hook_symbol(sym, ReplacementCheckEquals())

    simgr = project.factory.simgr(initial_state)

    def is_successful(state):
        return b'Good Job.' in state.posix.dumps(sys.stdout.fileno())

    def should_abort(state):
        return b'Try again.' in state.posix.dumps(sys.stdout.fileno())

    simgr.explore(find=is_successful, avoid=should_abort)

    if simgr.found:
        solution_state = simgr.found[0]
        print(solution_state.posix.dumps(sys.stdin.fileno()))
    else:
        raise Exception('Could not find the solution')
```

要点：
- `run(self, to_check, length)` 的参数对应 C 函数形参，angr 会按默认调用约定传入 bitvector 形式的实参。
- 内存读取使用 `self.state.memory.load(ptr, size=n)`；`size` 建议用 `state.solver.eval(length)` 求具体整数，避免意外的符号大小。
- 返回值用 `claripy.If(...)` 产生 0/1 的 32 位 BVV，angr 会放入 `eax` 并处理返回。


## 3. 与“普通 hook（手写函数覆盖）”的对比

- 普通 hook（第 09 关的思路）：
  - 优点：灵活，能在任意地址“插入/覆盖”逻辑，可直接改变控制流（例如跳过某条件检查、强制跳转）。
  - 缺点：需要手动从栈/寄存器取参、设置返回值、移动栈指针或修改 `ip`，容易出错；若函数被多次调用，你要重复 hook 或自己确保覆盖的是“函数本体”而非“某次调用点”。
- SimProcedure（本关）：
  - 优点：一次替换，所有调用生效；参数传递/返回值由 angr 代管；可与 angr 自身的类型系统、调用规约更好地协作。
  - 缺点：本质上在“改变目标函数语义”（以你的 Python 实现为准），若原函数有副作用（写文件、修改全局状态、触发异常路径），需要你在 `run()` 中忠实复现这些副作用。

### 3.1 直接 hook 函数本体 vs SimProcedure 的“等价性”与取舍

- 等价性判断：
  - 如果你在“函数入口地址”上 hook，并且在 hook 中完整地：
    - 正确读取形参（从栈/寄存器，取决于调用约定）；
    - 计算返回表达式；
    - 将返回值放入返回寄存器（x86 的 `eax`），并阻止继续执行原函数体；
  - 那么效果等价于“把该函数替换成你的实现”。这也正是 scaffold10 注释强调的点：本质上你已“手搓了一个 SimProcedure”。

- 何时仍推荐 SimProcedure：
  - 显式化原型/调用规约，按符号名 `hook_symbol`，地址变化更稳；
  - 复用现成过程（如 `memcmp`）并可 `inline_call` 组合；减少手动管理 `esp/eax/ip` 的出错面。

- 何时更适合直接 hook：
  - 你要“重塑控制流”而非“等价替换语义”，如：临时禁用某个检查、强制走成功路径、在函数中途（非入口）打桩或跳转到自定义落点。
  - 这些需要对当前指令地址、栈帧、落点更细粒度控制，普通 hook 自由度更高。

- 小结：
  - “hook 函数本体 ≈ 自写 SimProcedure”在语义上成立；SimProcedure 是其规范化形态。等价替换优先选 SimProcedure；需强控制流操纵时选普通 hook。


## 4. 与第 08 关“后置约束（post-hoc constraints）”的对比（重要）

- 第 08 关技巧回顾：不直接找“Good Job.”，而是“先到达对比函数入口（检查点）”，再在该状态上添加“变换后缓冲区的字节必须逐个等于目标串”的约束，一次性交给 SMT 求解器解出“原始输入”。不改程序语义，只在“时机合适的状态”上加约束，能避免路径爆炸。
- 本关 SimProcedure：直接把“对比函数”的语义改成“按我们想要的行为返回 0/1”（仍保持可符号化），对所有调用都生效。

何时选择哪个？
- 用后置约束（08）：
  - 你不想改变程序语义，只想“在最佳时机绑定条件”。
  - 目标函数只调用少量次或你能稳定抵达检查点。
  - 需要最大兼容性（比如后续还有代码依赖该函数的边效果）。
- 用 SimProcedure（10）：
  - 目标函数“被调用很多次”，你希望“一次替换到位”。
  - 目标函数逻辑明确、无特殊副作用，容易在 `run()` 重现。
  - 你希望减少分支并保持执行流自然前进（而非跳到检查点再加约束）。

两者都能显著缓解路径爆炸，但“代价/边界”不同：后置约束“保留语义”，SimProcedure“替换语义”。选择时先想清楚有没有副作用和后续依赖。


## 5. 常见易错点（踩坑提示）

- memory.load 的 size：
  - 建议：`n = state.solver.eval(length)`，然后 `load(ptr, size=n)`。
  - 千万别把“真正符号”的 bitvector 当作 `size`，很多 API 需要具体整数。
- 返回值位宽：
  - 在 x86 下请用 32 位：`claripy.BVV(1, 32)` / `claripy.BVV(0, 32)`。
- BVV 与 BVS：
  - BVV = 具体值；BVS = 符号。比较时位宽要一致；必要时 `ZeroExt/SignExt`。
- hook_symbol vs hook：
  - `project.hook_symbol('symbol_name', Proc())`：按**符号名**替换一次，所有调用生效。
  - `project.hook(addr, HookObj)`：按**地址**替换，需要你确保这个地址是“函数开始处”（而不是某个 call 点）。
- 地址/原型来源：
  - 本关示例的目标字符串地址 `0x0804e02c` 来自 scaffold10 的逆向；若你换了随机种子或平台，要先用 r2/Ghidra 等重新确认。
  - 查符号名示例（r2）：`r2 -q -c 'aaa; afl~check_equals' binary/x32/10_angr_simprocedures`
- 挂钩时机：
  - 一般“创建 state 前 hook”语义最直观；如需在执行中途 hook，要确保没有已缓存的 CFG/已解析的旧符号行为干扰。


## 6. 进阶思考（给出可验证方向，避免幻觉）

- 复用现有 SimProcedure：`self.inline_call(...)`
  - 在自定义 SimProcedure 的 `run()` 中，你可以调用 angr 已有的 SimProcedure，例如复用 `memcmp`/`strcmp` 的实现，再在结果上加你的逻辑。
  - 典型用法（伪示例）：
    ```python
    class MyProc(angr.SimProcedure):
        def run(self, a, b, n):
            memcmp_cls = angr.SIM_PROCEDURES['libc']['memcmp'] # 获取类(不是实例)
            res = self.inline_call(memcmp_cls, a, b, n) # 这个会调用 memcmp_cls 那个 SimProcedure 类的 run() 方法
            # res 对象提供返回值表达式（通常命名为 ret_expr），具体字段名以当前 angr 版本为准（可用`dir(res)`来查看所有可用属性
            return claripy.If(res.ret_expr == 0, claripy.BVV(1, 32), claripy.BVV(0, 32))
    ```
- 自定义调用约定（Calling Convention）
  - 若目标函数采用非常规 CC，你需要显式声明函数原型与 CC，确保 angr 正确把参数传递给 `run()`。
  - 典型做法是为被 hook 的函数提供一个 `prototype`（`SimTypeFunction([...], ...)`），并使用与架构匹配的 `SimCC`（如 cdecl/stdcall 等）。具体 API 在 angr “Calling Conventions” 文档中有说明；不同版本用法略有变动，编写前请以当前 docs 为准。
  示例：
  ```python
  from angr.calling_conventions import default_cc
  from angr.sim_type import SimTypeFunction, SimTypeInt

  # 获取默认调用约定
  cc_cls = default_cc(project.arch.name, platform=project.simos.name)
  my_cc = cc_cls(project.arch)

  # 单独定义 prototype
  my_proto = SimTypeFunction([SimTypeInt()], SimTypeInt())

  # 分别传递给 SimProcedure
  project.hook(addr, MyProc(cc=my_cc, prototype=my_proto))
  ```
- 快速跳过未知库函数（Stubs）
  - 对无关紧要、又可能产生大量状态分叉的外部函数，可用现成的存根（如 `angr.procedures.stubs.ReturnUnconstrained`）做“无副作用返回”的替代，集中精力在核心逻辑上。
- 在 SimProcedure 中添加约束
  - 你可以在 `run()` 内直接 `self.state.solver.add(...)` 施加额外约束（比如限制输入字符范围），这相当于将剪枝逻辑与函数语义绑定在一起；但要注意别与真实语义冲突。


## 7. 与第 08 关的“后置约束”代码片段对照

假设我们仍然到达 `check_equals_*` 入口（与 08 关做法一致），在“该状态（found_state）”上添加逐字节相等约束：

```python
found_state = simgr.found[0]
# to_check 指针与 length 可从 calling convention 获取或直接从已知全局/栈偏移定位
buf_ptr   = ...  # from stack or symbol
buf_len   = ...  # concrete int
target    = found_state.memory.load(0x0804e02c, size=buf_len)
mutated   = found_state.memory.load(buf_ptr,       size=buf_len)

for i in range(buf_len):
    found_state.solver.add(mutated.get_byte(i) == target.get_byte(i))
```

- 该方法“不改变程序语义”，仅在“恰当的时机”把两串字节绑定为相等。
- 与 SimProcedure 的差异：这里你仍需探索到“对比函数入口”的检查点；SimProcedure 则是从源头“定义函数如何返回”，所有调用都统一按你的语义执行。


## 8. 调试与验证

- 观察输出：
  - `state.posix.dumps(fd)`，典型地用 `sys.stdout.fileno()`/`sys.stdin.fileno()`。
- 观测路径：
  - `simgr.explore(find=..., avoid=...)`，同时打印 `len(simgr.active)`、`len(simgr.deadended)` 了解状态数量变化。
- REPL 检查：
  - 在断点/异常处 `dir(obj)` 看对象字段，如 `inline_call` 的返回对象属性名（不同版本有差异时，这招很稳）。


## 9. 参考链接（建议按当前 angr 版本核对）

- SimProcedures（核心概念与示例）
  https://docs.angr.io/ (搜索 “SimProcedure” 章节)
- Calling Conventions（声明函数原型与 CC）
  https://docs.angr.io/ (搜索 “Calling Conventions”)
- Claripy（BitVectors/约束）
  https://docs.angr.io/advanced-topics/claripy
- Veritesting（路径合并，与后置约束互补）
  https://docs.angr.io/advanced-topics/veritesting

> 注：angr 文档随版本演进偶有 API 细节与命名调整。上文示例均为“在语义上”保持稳定的用法；实现时若遇到属性名不匹配，优先以当前版本的官方文档/源码为准（或在 REPL 中用 `dir()`/`help()` 实查）。


---

附：如何定位本关的 `check_equals_*` 符号与字符串地址（以 r2 为例）：

```bash
r2 -q -c 'aaa; afl~check_equals'  binary/x32/10_angr_simprocedures
r2 -q -c 'aaa; iz~Good; axt @ str.Good_Job.' binary/x32/10_angr_simprocedures
```

若你的二进制是重新生成的（符号后缀变化），请先更新这些信息，再运行解题脚本。
