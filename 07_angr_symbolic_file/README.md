# 07_angr_symbolic_file CTF 挑战：符号化 **文件系统** 与两种解题思路

> 本关首次接触 **文件 I/O** 场景：程序并非直接从 stdin/内存读取密码，而是
> 先把用户输入写入磁盘，再通过 `fopen + fread` 重新加载。
> 我们将学习两种思路：
> 1. 构造 **符号文件 (SimFile)**，让 `fread` 读取符号化内容。
> 2. 直接跳过文件 I/O，手动把符号变量写到全局 `buffer`。

---

## 1 程序概览

1. `memset(buffer, 0, 0x40)`
2. `scanf("%64s", buffer)`
3. `ignore_me(buffer)` → 将输入写入 **"IFCONZGB.txt"**（无关逻辑）
4. 清空 buffer，再 `fread(buffer, 0x40, fp)` 读取文件内容
5. 删除文件 → 8 字节循环 `complex_function`
6. `strcmp(buffer, "TIIBWILE")`
7. 正确输出 *Good Job.*，否则 *Try again.* 并 `exit(1)`

### 关键地址

| 功能 | 地址 |
|------|------|
| 跳过 fread 之前 | **`0x80493fd`** |
| Good Job. | **`0x80494be`** |
| Try again. | **`0x80494a4`** |
| 全局缓冲区 `buffer` | 符号表 `is~buffer` |

---

## 2 angr 文件系统基础

```python
password_bvv = claripy.BVS('password', 0x40*8)
sym_file = angr.storage.SimFile('IFCONZGB.txt', content=password_bvv)
state.fs.insert(sym_file.name, sym_file)
```

* `SimFile` 可传入 `content=BitVector` 作为文件内容；大小由 BVS 位宽决定
* fread 会把符号数据复制到目标缓冲区，约束自动传播
* 若程序用 `rb` 打开，权限默认 OK；若需要写权限，`file_opts=angr.SIM_FILE_DEFAULT` 可调整

---

## 3 方案 A：符号文件（`solution.py`）

1. `blank_state(addr=0x80493fd)` 跳过 scanf/ignore_me
2. 插入符号文件，大小 0x40
3. `explore(find=0x80494be, avoid=0x80494a4)`
4. 求解 `password`，注意剪掉尾部 `\x00`
5. 输出 64 字节字符串（真实答案仅 8 字节，其余可为任意可打印字符）

---

## 4 方案 B：无需符号文件（`solution_no_sym_file.py`）

1. 起跳 **unlink 之后** (`0x804944f`) —— 文件已删，不再触发 fread
2. 直接 `state.memory.store(buffer_addr, sym_input)` 写 0x40 符号字节
3. 同样设置 find/avoid 地址求解
4. 脚本更短，但错过了学习符号文件的机会

---

## 5 实践步骤

```bash
# 1. 生成二进制
cd 07_angr_symbolic_file
python generate.py 2025 07_angr_symbolic_file

# 2. 定位符号与地址
r2 -q -c 'aaa; is~buffer' binary/x32/07_angr_symbolic_file
r2 -q -c 'aaa; iz~Good; axt @ str.Good_Job.' binary/x32/07_angr_symbolic_file
```

3. 运行两份脚本，比较输出
4. 将解（8 字节大写 A-Z）输入程序，得到 *Good Job.*

---

## 6 常见坑

| 问题 | 解决办法 |
|------|----------|
| `fread` 没读取数据 | 文件名或大小不匹配；确认 `content` 至少 0x40 字节 |
| 路径不符 `open("path/IFCONZGB.txt")` | angr 仅匹配文件名；若带路径需使用相同字符串 |
| 约束含大量无关字节 | 可在求解后 `split('\x00')[0]` 截断 |

---

## 7 延伸阅读

* angr 文档 – **Filesystem & SimFile**
  <https://docs.angr.io/en/latest/core-concepts/filesystem.html>
* SimProcedure `fread/fopen` 源码：`angr/procedures/libc/`
* 下一关 **08_angr_constraints**：手动添加/分析约束
