import angr  # 导入 angr 库，用于符号执行
from angr import SimFileStream
import claripy  # 导入 claripy 库，用于符号变量和约束
import sys  # 导入 sys 库，用于访问命令行参数（尽管在此代码中未使用）

executable = '00_angr_find/00_angr_find'  # 指定要分析的二进制文件路径
suc_addr = 0x080492c5  # 成功地址，表示找到的目标地址，注意，这里的地址是rebased地址
executable = '00_angr_find/learning/simple'  # 指定要分析的二进制文件路径
suc_addr = 0x0040114f  # 成功地址，表示找到的目标地址，注意，这里的地址是rebased地址，0x0040113b
executable = './crackme100'  # 指定要分析的二进制文件路径
suc_addr = 0x00401382  # 成功地址，表示找到的目标地址，注意，这里的地址是rebased地址，0x0040113b
def normal():
    """
    执行一个基本的 angr 符号执行，寻找特定地址并打印找到的解决方案。
    这是一个 angr 的入门示例，展示了如何加载二进制文件，创建初始状态，
    并使用 explore() 方法来寻找目标地址。
    """
    # 指定要分析的二进制文件的路径
    path_to_binary = executable
    # 创建一个 angr 项目，加载二进制文件
    project = angr.Project(path_to_binary)

    # 创建符号执行的初始状态
    # project.factory.entry_state() 创建一个从程序入口点开始的状态
    # add_options 用于配置符号执行的行为：
    # angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY: 当访问未初始化的内存时，用符号值填充
    # angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS: 当访问未初始化的寄存器时，用符号值填充
    initial_state = project.factory.entry_state(
        add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
    )

    # 创建一个状态管理器 (SimulationManager)
    # 它负责管理一组符号执行状态，并提供探索方法
    simulation = project.factory.simgr(initial_state)

    # 打印初始状态的数量，通常只有一个（入口状态）
    print(f"初始状态数量: {len(simulation.active)}")

    # 执行探索，寻找目标地址
    # simulation.explore() 是 angr 中一个强大的探索函数
    # find=suc_addr 指定了我们想要找到的目标地址
    # 当找到目标地址时，该状态会被移动到 simulation.found 列表中
    simulation.explore(find=suc_addr)

    # 探索完成后，打印各种状态的数量
    print("\n=== 探索结果统计 ===")
    # simulation.found: 包含成功到达目标地址的状态列表
    print(f"找到的状态 (found): {len(simulation.found)}")
    # simulation.active: 仍然在进行符号执行的活跃状态列表
    print(f"活跃状态 (active): {len(simulation.active)}")
    # simulation.deadended: 已经终止（例如，到达程序结束或发生错误）但未找到目标的状态列表
    print(f"死锁状态 (deadended): {len(simulation.deadended)}")
    # simulation.errored: 在执行过程中遇到错误的（例如，未处理的指令）状态列表
    print(f"错误状态 (errored): {len(simulation.errored)}")
    # simulation.unconstrained: 未受约束的状态（可能导致路径爆炸）
    print(f"未约束状态 (unconstrained): {len(simulation.unconstrained)}")

    # 如果找到了状态，则打印解决方案
    if simulation.found:
        # 获取找到的第一个状态
        solution_state = simulation.found[0]
        # solution_state.posix.dumps(0) 将标准输入（文件描述符 0）的内容转换为字节串
        # .decode() 将字节串解码为字符串
        print(f"\n解决方案: {solution_state.posix.dumps(0).decode()}")
        # 打印解决方案状态所在的地址
        print(f"解决方案状态地址: 0x{solution_state.addr:x}")

def detailed_exploration():
    """
    展示了如何逐步执行符号执行，并实时查看状态变化。
    这对于理解 angr 的执行流程和调试非常有用。
    """
    path_to_binary = executable
    project = angr.Project(path_to_binary)
    initial_state = project.factory.entry_state(
        add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
    )
    simulation = project.factory.simgr(initial_state)

    # 手动创建found stash
    simulation.stashes['found'] = []  # 创建一个空的 found stash，用于存储找到的状态

    # 定义目标地址
    target_address = suc_addr
    step_count = 0  # 初始化步数计数器
    print("开始逐步探索...")

    # 循环执行，直到没有活跃状态或找到目标
    while simulation.active and not simulation.found:
        print(f"\n--- 第 {step_count} 步 ---")
        print(f"活跃状态数量: {len(simulation.active)}")

        # 执行一步符号执行
        # simulation.step() 会处理所有活跃状态中的下一个block
        simulation.step()

        # 显示当前所有活跃状态的内存地址
        for i, state in enumerate(simulation.active):
            block = state.block()  # 获取当前状态的基本块
            instruction_addrs = block.instruction_addrs
            print(f"  状态 {i}，块起始地址: 0x{state.addr:x}")
            for insn in block.capstone.insns:
                print(f"    指令: 0x{insn.address:x} - {insn.mnemonic} {insn.op_str}")

            # 检查是否有任何活跃状态到达了目标地址
            if any(insn.address == target_address for insn in block.capstone.insns):
                print(f"  状态 {i} 到达目标地址 0x{target_address:x}!")
                # 将找到目标地址的状态移动到 found 列表中
                simulation.found.append(state)
                simulation.active.remove(state)  # 从活跃状态中移除
                break  # 只处理第一个找到的状态

        step_count += 1
        # 设置一个步数限制，防止无限循环
        if step_count > 100:
            print("达到最大步数限制")
            break

    print(f"\n探索完成，总共 {step_count} 步")
    print(f"找到的状态: {len(simulation.found)}")
    print(f"死锁状态: {len(simulation.deadended)}")

def path_analysis():
    """
    演示如何使用 angr 的探索技术 (Explorer) 并分析找到状态的执行路径历史。
    路径历史记录对于理解程序执行流程至关重要。
    """
    path_to_binary = executable
    project = angr.Project(path_to_binary)
    initial_state = project.factory.entry_state(
        add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
    )
    simulation = project.factory.simgr(initial_state)

    # 启用路径历史记录功能，并指定目标地址
    # simulation.use_technique() 用于添加探索技术
    # angr.exploration_techniques.Explorer 是一个默认的探索器，可以指定 find/avoid 地址
    simulation.use_technique(angr.exploration_techniques.Explorer(find=suc_addr))

    print("开始探索...")
    # simulation.run() 会持续执行探索，直到没有活跃状态为止
    simulation.run()

    # 如果找到解决方案
    if simulation.found:
        solution_state = simulation.found[0]
        print(f"解决方案: {solution_state.posix.dumps(0).decode()}")

        # 获取并打印路径历史记录
        # solution_state.history.bbl_addrs 包含执行过的基本块的地址列表
        print("\n执行路径历史:")
        for i, addr in enumerate(solution_state.history.bbl_addrs):
            print(f"  {i}: 0x{addr:x}")

        # 获取并打印跳转历史记录
        # solution_state.history.jump_targets 包含程序跳转到的目标地址列表
        print("\n跳转历史:")
        for i, jump_target in enumerate(solution_state.history.jump_targets):
            print(f"  跳转 {i}: 0x{jump_target:x}")

def search_input_password():
    project = angr.Project(executable, load_options={'auto_load_libs': False})

    password_size = 50
    symbolic_password = claripy.BVS("password", password_size * 8)

    initial_state = project.factory.entry_state(
        stdin=SimFileStream(name='stdin', content=symbolic_password, has_end=False),
        add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
    )

    # 为每个字节添加可见字符约束
    for byte in symbolic_password.chop(8):
        initial_state.add_constraints(byte >= ord(' '))  # 0x20 空格
        initial_state.add_constraints(byte <= ord('~'))  # 0x7e 波浪号
        # initial_state.add_constraints(byte != ord('\x00'))  # 排除空字符

    simulation = project.factory.simgr(initial_state)
    simulation.use_technique(angr.exploration_techniques.DFS())

    print("使用输出判断进行破解...")

    # 基于程序输出进行判断
    simulation.explore(
        find=lambda s: b"SUCCESS" in s.posix.dumps(1),
        avoid=lambda s: b"FAILED" in s.posix.dumps(1)
    )

    if simulation.found:
        solution_state = simulation.found[0]

        # 查找多个解决方案
        try:
            n = 10  # 获取最多n个解决方案
            solutions = solution_state.solver.eval_upto(
                symbolic_password,
                n,
                cast_to=bytes)

            result_file = '/tmp/password.txt'
            with open(result_file, 'w') as f:
                for i, password_bytes in enumerate(solutions):
                    print(f"解决方案 {i+1}: {password_bytes}")
                    # 将每个解决方案写入文件
                    f.write(password_bytes.decode() + '\n')
            print(f"破解成功！密码文件: {result_file}")
            print(f"请使用：`cat {result_file} | while IFS= read -r l; do echo " + '"${l}"' + f" | {executable}; done` 来验证密码。")

        except Exception as e:
            print(f"查找解决方案时出错: {e}")
            return None

        return '/tmp/password.dat'
    else:
        print("基于输出的方法也失败了")
        return None

def comprehensive_analysis(argv):
    """
    一个更全面的分析示例，结合了探索、结果统计以及对死锁和错误状态的分析。
    还演示了如何从找到的状态中提取解决方案和路径信息。
    """
    path_to_binary = executable
    project = angr.Project(path_to_binary)
    initial_state = project.factory.entry_state(
        add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
    )
    simulation = project.factory.simgr(initial_state)
    target_address = suc_addr
    print("=== 开始符号执行分析 ===")
    print(f"目标地址: 0x{target_address:x}")
    print(f"初始状态数量: {len(simulation.active)}")

    # 执行探索，寻找目标地址
    simulation.explore(find=target_address)

    # 打印探索结果统计
    print("\n=== 探索结果统计 ===")
    print(f"找到的状态数量: {len(simulation.found)}")
    print(f"活跃状态数量: {len(simulation.active)}")
    print(f"死锁状态数量: {len(simulation.deadended)}")
    print(f"错误状态数量: {len(simulation.errored)}")

    # 分析死锁状态（如果存在）
    if simulation.deadended:
        print("\n=== 死锁状态分析 ===")
        # 打印前5个死锁状态的地址
        for i, state in enumerate(simulation.deadended[:5]):
            print(f"死锁状态 {i}: 0x{state.addr:x}")

    # 分析错误状态（如果存在）
    if simulation.errored:
        print("\n=== 错误状态分析 ===")
        # 打印前3个错误状态的错误信息
        for i, errored in enumerate(simulation.errored[:3]):
            print(f"错误状态 {i}: {errored.error}")

    # 分析找到的解决方案（如果存在）
    if simulation.found:
        solution_state = simulation.found[0]
        # 获取解决方案（标准输入）
        solution = solution_state.posix.dumps(0).decode()
        print(f"\n=== 解决方案 ===")
        print(f"密码: {solution}")
        print(f"密码长度: {len(solution)}")
        print(f"最终地址: 0x{solution_state.addr:x}")

        # 分析路径信息
        print(f"\n=== 路径分析 ===")
        # 打印执行过的基本块数量
        print(f"执行的基本块数量: {len(solution_state.history.bbl_addrs)}")
        print("关键地址:")
        # 打印最后10个执行过的基本块地址
        for i, addr in enumerate(solution_state.history.bbl_addrs[-10:]):
            print(f"  {i}: 0x{addr:x}")
    else:
        # 如果未找到解决方案，提供一些可能的原因
        print("\n未找到解决方案")
        print("可能的原因:")
        print("1. 目标地址不正确")
        print("2. 探索深度不够")
        print("3. 存在无法处理的约束")

def debug_execution():
    executable = '00_angr_find/learning/simple'
    suc_addr = 0x0040114f  # mov dword [var_4h], 5
    # suc_addr = 0x0040113b # The first instruction of the printf "block"

    path_to_binary = executable
    project = angr.Project(path_to_binary)

    print(f"程序入口地址: 0x{project.entry:x}")
    print(f"目标地址: 0x{suc_addr:x}")

    initial_state = project.factory.entry_state()
    simulation = project.factory.simgr(initial_state)

    print(f"初始状态数量: {len(simulation.active)}")
    print(f"初始状态地址: 0x{simulation.active[0].addr:x}")

    # 手动创建found stash
    simulation.stashes['found'] = []

    # 逐步执行并观察每一步
    step_count = 0
    while simulation.active and step_count < 30:
        current_state = simulation.active[0]
        current_addr = current_state.addr
        current_block = current_state.block()
        current_instruction_addrs = current_block.instruction_addrs

        print(f"步骤 {step_count}: block起始地址： 0x{current_addr:x}")
        for i, addr in enumerate(current_instruction_addrs):
            print(f"  指令 {i:02d}: 0x{addr:x}")

        # 检查是否到达目标地址
        if suc_addr in current_instruction_addrs:
            print(f"*** 找到目标地址块，起始地址：0x{current_instruction_addrs[0]:x}，终止地址：0x{current_instruction_addrs[-1]:x} ***")
            simulation.found.append(current_state)
            simulation.active.remove(current_state)
            break

        # 执行一步
        simulation.step()
        step_count += 1

        print(f"  执行后: active={len(simulation.active)}, deadended={len(simulation.deadended)}, errored={len(simulation.errored)}")

        # 如果没有活跃状态了，检查原因
        if not simulation.active:
            print("没有活跃状态了")
            if simulation.deadended:
                dead_state = simulation.deadended[-1]
                print(f"死锁状态最终地址: 0x{dead_state.addr:x}")
            if simulation.errored:
                error_state = simulation.errored[-1]
                print(f"错误状态: {error_state}")
            break

    print("\n=== 最终结果 ===")
    print(f"找到的状态 (found): {len(simulation.found)}")
    print(f"死锁状态 (deadended): {len(simulation.deadended)}")
    print(f"错误状态 (errored): {len(simulation.errored)}")

if __name__ == "__main__":
    # debug_execution()
    # normal()
    # detailed_exploration()
    # path_analysis()
    search_input_password()
# # 程序的主入口点
# if __name__ == '__main__':
#     # 调用 normal() 函数来执行基本的符号执行示例
#     normal()
