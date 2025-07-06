#!/usr/bin/env python3
"""
安全的angr AST和bitvector示例（避免循环导入）
"""

def safe_import():
    """安全的模块导入"""
    try:
        # 按特定顺序导入
        import sys

        # 清理可能有问题的模块缓存
        modules_to_clean = []
        for module_name in list(sys.modules.keys()):
            if any(name in module_name for name in ['angr', 'claripy', 'inspect']):
                modules_to_clean.append(module_name)

        for mod in modules_to_clean:
            if mod in sys.modules:
                del sys.modules[mod]

        # 重新导入
        import angr
        import claripy

        return angr, claripy

    except ImportError as e:
        print(f"导入错误: {e}")
        print("\n解决方案:")
        print("1. 检查是否有inspect.py文件在当前目录（删除它）")
        print("2. 检查是否有angr.py文件在当前目录（重命名它）")
        print("3. 重启Python解释器")
        print("4. 考虑重新安装angr: pip install --force-reinstall angr")
        return None, None
    except Exception as e:
        print(f"其他错误: {e}")
        return None, None

def demonstrate_ast_storage():
    """演示AST存储的简化版本"""
    print("=== angr AST和bitvector存储概念演示 ===\n")

    angr_module, claripy_module = safe_import()

    if not angr_module or not claripy_module:
        print("模块导入失败，显示概念性说明：")
        show_conceptual_explanation()
        return

    try:
        print("1. AST基础概念")
        print("-" * 30)

        # 创建bitvector
        concrete = claripy_module.BVV(0x1234, 32)
        symbolic = claripy_module.BVS("x", 32)

        print(f"具体值: {concrete}")
        print(f"符号值: {symbolic}")

        # AST操作
        complex_ast = symbolic + concrete
        print(f"复合AST: {complex_ast}")
        print(f"AST操作: {complex_ast.op}")

        print("\n2. 创建状态并存储AST")
        print("-" * 30)

        # 使用一个简单的二进制文件创建项目
        # 注意：你需要有一个有效的二进制文件
        try:
            proj = angr_module.Project('/bin/ls')  # Linux系统
        except:
            try:
                proj = angr_module.Project('/bin/cat')  # 备选
            except:
                print("找不到合适的二进制文件，使用模拟状态")
                proj = None

        if proj:
            state = proj.factory.entry_state()

            # 存储到寄存器
            state.regs.eax = concrete
            state.regs.ebx = symbolic
            state.regs.ecx = complex_ast

            print(f"EAX (具体): {state.regs.eax}")
            print(f"EBX (符号): {state.regs.ebx}")
            print(f"ECX (复合): {state.regs.ecx}")

            # 存储到内存
            state.mem[0x1000].int = concrete
            state.mem[0x1004].int = symbolic

            print(f"内存[0x1000]: {state.mem[0x1000].int.resolved}")
            print(f"内存[0x1004]: {state.mem[0x1004].int.resolved}")

        print("\n3. AST操作示例")
        print("-" * 30)

        a = claripy_module.BVS("a", 32)
        b = claripy_module.BVS("b", 32)

        operations = {
            "加法": a + b,
            "减法": a - b,
            "乘法": a * b,
            "按位与": a & b,
            "按位或": a | b,
            "按位异或": a ^ b
        }

        for name, ast in operations.items():
            print(f"{name}: {ast}")

        print("\n✓ AST演示完成")

    except Exception as e:
        print(f"执行过程中出错: {e}")
        import traceback
        traceback.print_exc()

def show_conceptual_explanation():
    """显示概念性说明"""
    print("\n=== AST和bitvector存储概念说明 ===")
    print()
    print("在angr中，AST（抽象语法树）是核心概念：")
    print()
    print("1. **什么是AST？**")
    print("   - AST表示计算操作的树状结构")
    print("   - 即使是简单的值也是AST（单节点树）")
    print("   - 例: BVV(0x1234, 32) 是一个AST节点")
    print()
    print("2. **bitvector类型的AST包括：**")
    print("   - 具体值: claripy.BVV(0x1234, 32)")
    print("   - 符号变量: claripy.BVS('x', 32)")
    print("   - 复合表达式: x + y, (a * 2) ^ 0xdead")
    print()
    print("3. **存储位置：**")
    print("   寄存器:")
    print("     state.regs.eax = some_ast")
    print("     state.regs.ebx = x + y")
    print()
    print("   内存:")
    print("     state.mem[0x1000].int = some_ast")
    print("     state.memory.store(addr, ast)")
    print()
    print("4. **关键理解：**")
    print("   - 任何bitvector AST都可以存储在寄存器/内存中")
    print("   - 这使得符号执行能跟踪复杂的符号表达式")
    print("   - angr自动处理AST与存储的转换")
    print()
    print("5. **实际意义：**")
    print("   这让angr能够分析程序在所有可能输入下的行为，")
    print("   而不仅仅是特定的测试用例。")

def troubleshooting_guide():
    """故障排除指南"""
    print("\n=== 故障排除指南 ===")
    print()
    print("如果遇到'inspect'模块错误，请尝试：")
    print()
    print("1. **检查文件命名冲突：**")
    print("   - 删除当前目录下的 inspect.py")
    print("   - 删除当前目录下的 angr.py")
    print("   - 删除任何与标准库同名的文件")
    print()
    print("2. **清理Python缓存：**")
    print("   - 删除 __pycache__ 目录")
    print("   - 删除 .pyc 文件")
    print()
    print("3. **重新安装angr：**")
    print("   pip uninstall angr")
    print("   pip install angr")
    print()
    print("4. **使用虚拟环境：**")
    print("   python -m venv angr_env")
    print("   source angr_env/bin/activate  # Linux/Mac")
    print("   angr_env\\Scripts\\activate    # Windows")
    print("   pip install angr")
    print()
    print("5. **检查Python版本：**")
    print("   angr需要Python 3.8+")

if __name__ == "__main__":
    demonstrate_ast_storage()
    troubleshooting_guide()