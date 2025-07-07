#!/usr/bin/env python3
"""
深入理解angr中AST的寄存器和内存存储机制
演示"any bitvector-typed AST can be stored in registers or memory"的含义
本代码可用于加深对：https://docs.angr.io/en/latest/core-concepts/solver.html#working-with-bitvectors 的理解
"""

import warnings
warnings.filterwarnings("ignore", message="pkg_resources is deprecated")

import angr
import claripy

def demonstrate_ast_tree_structure():
    """演示AST的树状结构"""
    print("=== AST树状结构分析 ===")
    print()

    # 创建符号变量
    x = claripy.BVS("x", 32)
    y = claripy.BVS("y", 32)

    # 构建复杂的AST表达式
    expr = (x + 10) * (y - 5) + 0x100

    print(f"复杂表达式: {expr}")
    print(f"根节点操作: {expr.op}")
    print()

    def print_ast_tree(node, depth=0):
        """递归打印AST树结构"""
        indent = "  " * depth
        print(f"{indent}操作: {node.op}")

        if hasattr(node, 'args') and node.args:
            print(f"{indent}参数数量: {len(node.args)}")
            for i, arg in enumerate(node.args):
                print(f"{indent}参数 {i}:")
                if hasattr(arg, 'op'):
                    print_ast_tree(arg, depth + 1)
                else:
                    print(f"{indent}  值: {arg}")
        print()

    print("AST树结构:")
    print_ast_tree(expr)

def demonstrate_storage_equivalence():
    """演示AST在不同存储位置的等价性"""
    print("=== AST存储等价性演示 ===")
    print()

    proj = angr.Project('/bin/ls')
    state = proj.factory.entry_state()

    # 创建各种类型的AST
    concrete_ast = claripy.BVV(0xdeadbeef, 32)
    symbolic_ast = claripy.BVS("input", 32)
    complex_ast = symbolic_ast * 2 + concrete_ast

    print("1. 原始AST:")
    print(f"   具体值AST: {concrete_ast}")
    print(f"   符号AST: {symbolic_ast}")
    print(f"   复合AST: {complex_ast}")
    print()

    # 存储到不同位置
    print("2. 存储到寄存器:")
    state.regs.eax = concrete_ast
    state.regs.ebx = symbolic_ast
    state.regs.ecx = complex_ast

    print(f"   EAX中的AST: {state.regs.eax}")
    print(f"   EBX中的AST: {state.regs.ebx}")
    print(f"   ECX中的AST: {state.regs.ecx}")
    print()

    print("3. 存储到内存:")
    addr1, addr2, addr3 = 0x10000, 0x10004, 0x10008

    state.mem[addr1].uint32_t = concrete_ast
    state.mem[addr2].uint32_t = symbolic_ast
    state.mem[addr3].uint32_t = complex_ast

    print(f"   内存[0x{addr1:x}]: {state.mem[addr1].uint32_t.resolved}")
    print(f"   内存[0x{addr2:x}]: {state.mem[addr2].uint32_t.resolved}")
    print(f"   内存[0x{addr3:x}]: {state.mem[addr3].uint32_t.resolved}")
    print()

    print("4. 验证等价性:")
    # 从寄存器读取并比较
    eax_value = state.regs.eax
    mem_value = state.mem[addr1].uint32_t.resolved
    print(f"   EAX == 内存[0x{addr1:x}]: {eax_value is concrete_ast}")
    print(f"   AST结构相同: {str(eax_value) == str(mem_value)}")

def demonstrate_ast_operations_storage():
    """演示对存储的AST进行操作"""
    print("\n=== 对存储的AST进行操作 ===")
    print()

    proj = angr.Project('/bin/ls')
    state = proj.factory.entry_state()

    # 创建符号输入
    user_input = claripy.BVS("user_input", 32)

    # 存储到内存
    input_addr = 0x20000
    state.mem[input_addr].uint32_t = user_input
    print(f"1. 存储用户输入到内存[0x{input_addr:x}]: {state.mem[input_addr].uint32_t.resolved}")

    # 从内存读取并进行操作
    loaded_value = state.mem[input_addr].uint32_t.resolved
    processed_value = loaded_value * 2 + 0x100

    # 存储处理结果
    result_addr = 0x20004
    state.mem[result_addr].uint32_t = processed_value
    print(f"2. 处理后存储到内存[0x{result_addr:x}]: {state.mem[result_addr].uint32_t.resolved}")

    # 进一步操作
    final_result = state.mem[result_addr].uint32_t.resolved ^ 0xffffffff
    state.regs.eax = final_result
    print(f"3. 最终结果存储到EAX: {state.regs.eax}")

    # 显示完整的AST链
    print(f"\n完整的AST转换链:")
    print(f"   输入: {user_input}")
    print(f"   处理: ({user_input}) * 2 + 0x100")
    print(f"   最终: (({user_input}) * 2 + 0x100) ^ 0xffffffff")

def demonstrate_constraint_solving():
    """演示约束求解与AST"""
    print("\n=== 约束求解与AST ===")
    print()

    proj = angr.Project('/bin/ls')
    state = proj.factory.entry_state()

    # 创建符号变量
    password = claripy.BVS("password", 32)

    # 模拟一个简单的密码检查
    # password * 1337 + 42 == 0x13371337
    check_expr = password * 1337 + 42
    target_value = 0x13371337

    # 存储到寄存器进行"计算"
    state.regs.eax = password
    state.regs.ebx = check_expr

    print(f"密码变量: {state.regs.eax}")
    print(f"检查表达式: {state.regs.ebx}")
    print(f"目标值: 0x{target_value:x}")

    # 添加约束
    constraint = state.regs.ebx == target_value
    state.solver.add(constraint)

    print(f"约束: {constraint}")

    # 求解
    if state.solver.satisfiable():
        solution = state.solver.eval(password)
        print(f"✓ 找到解: password = 0x{solution:x} ({solution})")

        # 验证解
        verification = solution * 1337 + 42
        print(f"验证: {solution} * 1337 + 42 = 0x{verification:x}")
        print(f"正确: {verification == target_value}")
    else:
        print("✗ 无解")

def demonstrate_memory_layout():
    """演示内存中AST的布局"""
    print("\n=== 内存中的AST布局 ===")
    print()

    proj = angr.Project('/bin/ls')
    state = proj.factory.entry_state()

    # 创建一组相关的AST
    base = claripy.BVS("base", 32)
    asts = {
        'original': base,
        'doubled': base * 2,
        'plus_offset': base + 0x100,
        'complex': (base * 3 + 0x200) ^ 0xaaaaaaaa
    }

    # 连续存储到内存
    base_addr = 0x30000
    print("存储AST到连续内存:")

    for i, (name, ast) in enumerate(asts.items()):
        addr = base_addr + i * 4
        state.mem[addr].uint32_t = ast
        print(f"  0x{addr:x}: {name:<12} = {ast}")

    print(f"\n从内存读取并组合:")

    # 从内存读取AST并进行新的组合
    ast1 = state.mem[base_addr].uint32_t.resolved
    ast2 = state.mem[base_addr + 4].uint32_t.resolved
    ast3 = state.mem[base_addr + 8].uint32_t.resolved

    combined = ast1 + ast2 - ast3
    state.mem[base_addr + 16].uint32_t = combined

    print(f"  组合结果: {combined}")
    print(f"  存储位置: 0x{base_addr + 16:x}")

def main():
    """主函数"""
    print("=== 深入理解angr AST存储机制 ===")
    print("'any bitvector-typed AST can be stored in registers or memory'")
    print("=" * 60)

    demonstrate_ast_tree_structure()
    demonstrate_storage_equivalence()
    demonstrate_ast_operations_storage()
    demonstrate_constraint_solving()
    demonstrate_memory_layout()

    print("\n=== 关键要点总结 ===")
    print("1. AST是计算的抽象表示，可以任意复杂")
    print("2. 任何bitvector类型的AST都可以存储在寄存器或内存中")
    print("3. 存储位置不影响AST的语义 - 它们保持相同的符号意义")
    print("4. 可以从存储位置读取AST并进行进一步操作")
    print("5. 这使得符号执行能够跟踪程序中的复杂数据流")
    print("6. 约束求解器可以处理这些存储的符号表达式")

if __name__ == "__main__":
    main()