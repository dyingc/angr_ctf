# 15_angr_arbitrary_read：任意读 + 可控性判定两解法对比

本关模拟一个“读任意内存→打印秘密”的经典利用模型。程序读取两个参数（`scanf("%u %20s")`）：一个整数 `key` 与一个长度上限为 20 的字符串；随后在某分支内调用 `puts(locals.to_print)`。若我们能让 `locals.to_print` 指向 .rodata 中的 "Good Job."，就能打印目标字符串。

本关提供两条可行策略：
- 解法 A（solution.py）：在上游关键点直接施加约束，将 `locals.to_print`（位于 EBP-0xC）约束为 .rodata 上 "Good Job." 的真实地址。属于“已知利用点 → 快速构造 payload”的路线。
- 解法 B（模板 scaffold 思路）：在 `puts` 函数入口检测参数可控性（symbolic），试探性添加“使其等于目标地址”的约束（satisfiable 预判），判定该 `puts` 调用点是否可利用。属于“发现性/自动化审计”路线。

下面分别阐述两解法细节、优缺点以及选择建议。


## 1. 关键技术前置

- scanf 需要 Hook（多输出参数）：
  - `%u` → 32-bit 符号整数，写入时必须指定 endness=`state.arch.memory_endness`
  - `%20s` → 20 字节符号串，逐字节写入（无需 endness）
  - 可选对字符串前若干字节施加“可打印 ASCII”约束，便于人工输入与验证
  - 将两份符号量保存到 `state.globals`，收尾时直接 eval（对多次调用可改为容器形式）

- .rodata 的真实地址 vs .data 符号指针：
  - good_job 符号在 .data 中保存“指向 .rodata 字符串”的指针
  - 利用时应读取 .data 中“该指针的值”，而不是与 .data 的符号地址比较
  - 例如：
    ```python
    good_job_symbol = project.loader.find_symbol('good_job')
    good_job_symbol_addr = good_job_symbol.rebased_addr           # .data 中的符号地址
    good_job_addr = state.memory.load(good_job_symbol_addr, 4,
                                      endness=state.arch.memory_endness).concrete_value  # .rodata 实地址
    ```

- “任意读”的角色：
  - 通过读取 .data 的指针，从而拿到 .rodata 的真实地址，达成参数重定向
  - 在模板解法中同样要用到该地址，才能做 satisfiable 预判


## 2. 解法 A：上游强约束（solution.py）

思路流程：
1) Hook `__isoc99_scanf` 生成并写入两个符号变量：
   - key_value: 32-bit；用 endness 存到 key 的地址
   - user_input_2_value: 20 字节；可选对前 16 字节加“可打印 ASCII”约束
   - 保存 globals：`state.globals['key_value']` 与 `['user_input_2_value']`
2) 在到达关键地址时（示例：`addr == 0x080491f9` 输出“可控 try_again“（下面的 another_try_again）的 CFG 块的首条指令地址）：
    ```c
    int main(int argc,char **argv)

    {
    char *user_input_2;
    char *another_try_again;
    int *not_used;

    not_used = &argc;
    another_try_again = try_again;
    printf("Enter the password: ");
                        /* 需要覆盖前面的 another_try_again 使其指向 good_job */
    __isoc99_scanf("%u %20s",&key,&user_input_2);
    if (key == 0x7365ba) {
        puts(try_again);
    }
    else if (key == 0x3f91343) {
                        /* flow 需要落到这里，而且，another_try_again 需要被覆盖成
                        good_job */
        puts(another_try_again);
    }
    else {
        puts(try_again);
    }
    return 0;
    }
    ```
   - 从 .data 读取 good_job 符号的指针值→`good_job_addr`
   - 读取 `locals.to_print`：`another_try_again_addr = s.regs.ebp - 0xc`，按 endness 读 4 字节
   - 添加约束：`another_try_again_value == good_job_addr`
   - 返回 True 作为 find 条件
3) 收尾 eval：
   - 从 globals 中 eval 出 key 与第二个参数字符串，打印/保存 payload

关键代码片段（节选）：
```python
class ScanfHook(SimProcedure):
    def run(self, fmt_ptr, key_ptr, str_ptr):
        key_value = claripy.BVS('key_value', 32)
        user_s = claripy.BVS('user_input_2_value', 20*8)
        # 可打印约束（示例：前 16 字节）
        for i in range(16):
            self.state.solver.add(user_s.get_byte(i) > 0x20)
            self.state.solver.add(user_s.get_byte(i) < 0x7e)
        self.state.memory.store(key_ptr, key_value, endness=self.arch.memory_endness)
        self.state.memory.store(str_ptr, user_s)
        self.state.globals['key_value'] = key_value
        self.state.globals['user_input_2_value'] = user_s

project.hook_symbol('__isoc99_scanf', ScanfHook())

def is_successful(s):
    if s.addr != 0x080491f9:  # 关键落点
        return False
    good_job_sym = project.loader.find_symbol('good_job')
    good_job_addr = s.memory.load(good_job_sym.rebased_addr, 4,
                                  endness=s.arch.memory_endness).concrete_value
    to_print_addr = s.regs.ebp - 0xc
    to_print_val = s.memory.load(to_print_addr, 4, endness=s.arch.memory_endness)
    s.solver.add(to_print_val == good_job_addr)
    return True
```

优点：
- 路径短、约束直接，通常更快
- 一旦掌握结构体布局（EBP-0xC）与关键分支位置，payload 生成简单

缺点：
- 对特定编译版耦合较强（关键地址/偏移变化需更新）
- 强约束易误伤其他路径（不经预判，直接污染 solver）——虽然这里是有意为之


## 3. 解法 B：在 puts 入口做可控性判定（模板）

思路流程：
1) 以 puts 的函数入口地址为 find（必须是入口第一条指令）
2) 在 `check_puts(state)` 中按 cdecl 栈布局读取 puts 的首个参数（字符串指针）：
   - 注意读取时使用正确 endness
   - 例如 `puts_parameter = state.memory.load(esp+4, 4, endness=...)`
3) 判定是否“可控/符号化”：`state.solver.symbolic(puts_parameter)`
4) 构造“可打印 Good Job.” 的约束表达式，先用 satisfiable 试探：
   - `state.satisfiable(extra_constraints=(puts_parameter == good_job_addr,))`
   - 可满足则再 add_constraints 生效，并返回 True 作为 find

示意代码（伪化补全）：
```python
def check_puts(state):
    esp = state.regs.esp
    puts_param = state.memory.load(esp + 4, 4, endness=project.arch.memory_endness)
    if state.solver.symbolic(puts_param):
        good_job_sym = project.loader.find_symbol('good_job')
        good_job_addr = state.memory.load(good_job_sym.rebased_addr, 4,
                                          endness=state.arch.memory_endness).concrete_value
        expr = (puts_param == claripy.BVV(good_job_addr, 32))
        if state.satisfiable(extra_constraints=(expr,)):
            state.add_constraints(expr)
            return True
    return False

def is_successful(state):
    puts_addr = project.loader.find_symbol('puts').rebased_addr  # 推荐符号查找
    if state.addr == puts_addr:
        return check_puts(state)
    return False
```

优点：
- 更通用：无需提前知道具体分支/局部布局，只要到达 puts 就可检查
- “先试后加”的习惯（satisfiable 预判）更安全，便于批量审计多个切入点 - 更像“自动化审计/验证”套路，具有发现性与可解释性（为什么可控）

缺点：
- 要命中 puts 入口（早一条/晚一条可能破坏栈图假设）
- 可能会多次命中 puts，需要多次 satisfiable 测试，整体略慢
- 仍需做“任意读”：从 .data 读出 rodata 的真实地址


## 4. 选择建议

- 快速构造 payload、路径已知：选解法 A（solution.py）
- 自动化审计/发现可控点、样本未知：选解法 B（模板）
- 实战往往组合使用：先用 B 粗筛“哪个 puts 可控”，后对该路径在上游用 A 早期强约束，减少搜索空间与求解时间


## 5. 常见坑位

- 读取 .rodata 真实地址：从 .data 的符号地址处读“值”，不是拿符号地址去比
- scanf hook 的 endness：整数用 endness；字符串逐字节无需 endness
- puts 入口地址一定要对（强依赖栈图）：推荐 `project.loader.find_symbol('puts').rebased_addr`
- 多次输入/多调用点：`state.globals` 用容器（列表/字典+索引）而非固定键，避免覆盖
- 尽量用符号查找（find_symbol）替代硬编码常量，保留注释以便核对


## 6. 复现实验

- 用 `r2 -q -c 'aaa; iz~Good; axt @ str.Good_Job.' binary/x32/15_angr_arbitrary_read` 定位 "Good Job."，并确认 .data 的 `good_job` 指针位置
- 跑解法 A（你的 solution.py）：应直接给出 “key 和第二个字符串” 输入
- 跑模板思路的脚本（自行补完 scaffold）：find 命中 puts 入口，并在 check_puts 中判定可控 → 约束 → 输出

——

本关 takeaway：任意读（从 .data 读取 .rodata 真实地址）是“重定向参数指针”的关键；两条路线分别强调“快速构造利用”与“自动化可控性检测”。根据目的选择或结合使用，能在更复杂样本中稳健扩展。
