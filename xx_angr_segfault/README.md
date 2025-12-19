# xx_angr_segfault：避开段错误（Segmentation Fault）与分支求解

本关二进制与 scaffoldxx.py 里示例不同，二者不是同一个程序。该二进制仅包含如下可见字符串：
- Enter the password:
- Try again.
- %u %20s

注意：当 key 不正确时，程序会在解引用被覆盖指针时直接崩溃（Segmentation fault），通常不会打印 “Try again.”。因此本关的“成功”判据不依赖任何成功提示字符串，而是“到达安全收尾地址（正常返回）”。

请勿参考 scaffoldxx.py 的题解逻辑（其对应另一份二进制）。

---

## 1. 关卡目标

- 通过 angr 找到一组输入 `(key, buf)`：
  - 避免走到会对“被覆盖指针”解引用的路径（否则段错误）；
  - 让程序能走到函数收尾正常返回（例如 `leave; ret` 位置）。
- 我们在符号执行中采用 “find/avoid”：
  - find：到达安全地址（函数尾部或安全分支起点）
  - avoid：到达会触发被覆盖指针解引用的指令地址

---

## 2. 逆向速览（核心行为）

从你提供的汇编与 P-code 可归纳出主流程（伪代码）：
```
buf[16] 清零
local_18 = buf + 0x14      // 指向 buf 之后的一片区域（越界）
print_msg();
printf("Enter the password: ");
scanf("%u %20s", &key, buf);

if (key == 0x01d6fd86) {
    // 路径 A：读取 *local_18 的一个字节 → 极易段错误
    local_13 = *(local_18);
} else if (key == 0x0354e615) {
    // 路径 B：从 local_14 取一个字节（不解引用指针）→ 安全
    local_13 = local_14[0];
} else {
    // 默认：同样读取 *local_18 的一个字节 → 极易段错误
    local_13 = *(local_18);
}

return 0;
```

关键点：
- 栈上 `buf` 只有 16 字节，但 `scanf("%20s")` 允许写入最多 20 字节数据，并在末尾追加 `\x00` 终止（共 21 字节）。因此它会覆盖紧邻的栈变量，其中就包括保存 `local_18`（指针）的 4 个字节。
- 如果走“路径 A”或“默认路径”，代码会解引用 `local_18`；由于它被覆盖为不可用地址（或仍为 `buf+0x14` 这种越界地址），典型结局是段错误，**不会**出现“Try again.” 的输出。
- 唯一“天然安全”的分支是当 `key == 0x0354e615`（即“路径 B”），因为该分支不解引用指针。

在你给出的样本里，常用的关键地址（不同 seed/构建可能有轻微变化）：
- 两个可能触发解引用（易崩溃）的起点：`0x08048529`、`0x0804853d`（`0x08048540` 为紧跟指令）
- 安全分支 B 起点：`0x08048534`
- 函数收尾处（安全落点）：`0x08048546`（`leave; ret`）

---

## 3. angr 解题思路

思路总览：
1) Hook `__isoc99_scanf`：构造两个符号变量（`key` 为 32 位无符号整数；`buf` 为 21 字节，含末尾 `\x00` 终止），并写入对应地址。
2) 为 `buf` 加“可打印字符 + 末字节为 0”的约束，贴近真实 `%s` 行为。
3) `simgr.explore(find, avoid)`：
   - `find`：函数收尾 `0x08048546` 或安全分支起点 `0x08048534`
   - `avoid`：会触发对被覆盖指针解引用的地址，如 `0x08048529`、`0x0804853d`、`0x08048540`
4) 找到 `found` 状态后，从 state 中 `eval` 出输入（Flag1 = key，Flag2 = buf）。

极简参考代码（可与本目录 `avoid_segfault.py` 对照）：
```python
import angr, claripy

class MyScanf(angr.SimProcedure):
    def run(self, fmt_ptr, key_ptr, buf_ptr):
        # %u
        input1 = claripy.BVS("input1", 32)  # key: 4 bytes

        # %20s + '\x00'
        buf_len = 21
        input2 = claripy.BVS("input2", buf_len * 8)
        self.state.add_constraints(input2.get_byte(buf_len - 1) == 0)
        for i in range(buf_len - 1):
            ch = input2.get_byte(i)
            self.state.add_constraints(ch >= 0x20, ch <= 0x7e)

        # 写入内存（注意 endianness）
        self.state.memory.store(key_ptr, input1, endness=self.state.arch.memory_endness)
        self.state.memory.store(buf_ptr, input2)

        # 便于后续取值
        self.state.globals["input1"] = input1
        self.state.globals["input2"] = input2
        return 2

proj = angr.Project("./binary/x32/xx_angr_segfault", auto_load_libs=False)
proj.hook_symbol("__isoc99_scanf", MyScanf())

state = proj.factory.full_init_state()
simgr = proj.factory.simulation_manager(state)

# 参考地址（请按本地实际二进制适配）
FIND   = [0x08048546]                 # 或使用 0x08048534（安全分支 B 的起点）
AVOID  = [0x08048529, 0x0804853d, 0x08048540]

simgr.explore(find=lambda s: s.addr in FIND, avoid=lambda s: s.addr in AVOID)

if simgr.found:
    s = simgr.found[0]
    flag1 = s.solver.eval(s.globals["input1"], cast_to=int)     # key
    flag2 = s.solver.eval(s.globals["input2"], cast_to=bytes)   # buf（含 \x00）
    print("Flag1:", flag1)
    print("Flag2:", flag2)
else:
    print("No solution found")
```

可选优化：
- 直接约束 `key == 0x0354e615`，可显著收敛搜索空间（等价于强行走安全分支 B）。
- 若要尝试“让指针解引用也不崩溃”，可令 `buf` 覆写出的 `local_18` 指向一个可读地址，但这在实际求解中更脆弱，且不如直接约束 key 稳定。

---

## 4. 运行步骤

1) 环境准备
   - Python 3
   - 安装 angr 依赖（仓库根目录有 requirements.txt；或按你本地环境）

2) 执行脚本
```bash
python3 xx_angr_segfault/avoid_segfault.py ./binary/x32/xx_angr_segfault
```

3) 期望输出（示例）
```
Flag1: 55826037
Flag2: b'AAA...\\x00'
```
- 实际数值依赖求解结果与随机种子；
- 不会依赖打印 “Try again.” 作成功判据。

---

## 5. 常见坑位

- 忘记 Hook scanf：否则从真实 stdin 读入，状态不可控或爆炸。
- 字符串终止符：`%20s` 末尾会追加 `\x00`，建议在符号字符串末字节显式约束为 0。
- Endianness：写 32 位整数（key）要使用 `endness=self.state.arch.memory_endness`。
- 地址偏移：不同编译/seed 下地址可能变化，需用 r2/objdump 实测后替换 `find/avoid`。
- “Try again.”：存在于 .rodata，但错误 key 走到指针解引用即崩溃，通常不会到达打印点；不要以该字符串的出现作为成功判据。

---

## 6. 附：关键地址速查（样本）

- 可能触发解引用（易崩溃）：
  - `0x08048529`（路径 A）
  - `0x0804853d` / `0x08048540`（默认路径）
- 安全分支 B 起点：`0x08048534`
- 函数收尾（安全落点）：`0x08048546`（`leave; ret`）

---

## 7. 参考

- angr 文档：Path exploration / SimProcedure / 探索策略（find/avoid）
- C 标准库 `scanf("%s")` 的写入行为（最大长度与空终止）
- 可参考第 16、17 关的 README 排版风格，但请注意本关没有“成功字符串”，需要以“到达安全地址”作为成功判据
