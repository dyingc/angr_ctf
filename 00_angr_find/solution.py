# 在开始之前，请注意以下关于这些 CTF (Capture The Flag) 挑战的几点说明。
#
# 每个二进制文件在运行时都会要求输入密码，密码可以通过标准输入 (在控制台中键入) 提交。
# 许多关卡会接受多种不同的密码。你的目标是找到一个适用于每个二进制文件的密码。
#
# 如果输入错误的密码，程序会打印 "Try again."。如果输入正确的密码，程序会打印 "Good Job."。
#
# 每个挑战都会附带一个类似这样的文件，名为 "scaffoldXX.py"。它会提供指导以及一个可能的解决方案的骨架。
# 你需要编辑每个文件。在某些情况下，你可能需要进行大幅修改。虽然推荐使用这些文件，
# 但如果你发现它们过于受限，也可以不依赖它们来编写解决方案。
#
# 在 scaffoldXX.py 中需要简单替换的地方会用三个问号 (???) 标记。
# 需要编写更多代码的地方会用省略号 (...) 标记。
# 注释会记录任何新的概念，但对于已经讲过的概念将省略 (你需要参考之前的 scaffoldXX.py 文件来解决挑战)。
# 如果注释记录了需要修改的代码部分，它会在末尾加上感叹号，并单独占一行 (!)。
import angr
import sys
def main(argv):
  # 创建一个 angr 项目。
  # 如果你想在命令行中指定二进制文件路径，可以将 argv[1] 作为参数。
  # 然后，你可以像这样从命令行运行脚本：
  # python ./scaffold00.py [二进制文件路径]
  # (!)
  path_to_binary = '00_angr_find/00_angr_find'  # :string (这里应填写二进制文件的路径)
  project = angr.Project(path_to_binary)
  # 告诉 angr 从哪里开始执行 (是从 main() 函数开始还是其他地方？)。
  # 目前，使用 entry_state 函数指示 angr 从 main() 函数开始。
  initial_state = project.factory.entry_state(
    # 添加这些选项是为了确保 angr 在处理未定义内存和寄存器时不会因为未初始化而崩溃。
    # SYMBOL_FILL_UNCONSTRAINED_MEMORY: 用符号值填充未约束的内存。
    # 这个选项告诉 angr，当遇到未被明确初始化的内存区域时，用符号值来填充它们。
    # 这样做是为了让 angr能够探索所有可能的内存使用情况，而不会因为遇到未定义值而过早终止。
    # SYMBOL_FILL_UNCONSTRAINED_REGISTERS: 用符号值填充未约束的寄存器。
    # 类似地，这个选项告诉 angr，当寄存器未被明确初始化时，也用符号值来填充。这允许 angr探索寄存器可以取的所有可能值。
    # 为什么需要填充？因为在符号执行中，我们希望探索所有可能的执行路径。如果内存或寄存器未被初始化，程序的行为可能是未定义的。
    # 通过用符号值填充，我们告诉 angr：“这里可能是什么值”，从而允许它继续探索，而不是因为“不知道”而停止。
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
  )
  # 创建一个用起始状态初始化的模拟管理器 (simulation manager)。
  # 它提供了许多有用的工具来搜索和执行二进制文件。
  simulation = project.factory.simgr(initial_state)
  # 探索二进制文件，尝试找到打印 "Good Job." 的地址。
  # 你需要找到目标地址并将其插入此处。
  # 这个函数会持续执行，直到找到解决方案或探索完可执行文件中的所有可能路径。
  # (!)
  print_good_address = 0x080492c5  # :integer (通常是十六进制格式的地址)
  # explore 方法是 angr 中用于进行符号执行搜索的核心方法。
  # 它会接受一个或多个“探测器”来指导搜索过程。
  # `find=print_good_address` 是一个探测器，它告诉 angr：“请找到一个能够到达 `print_good_address` 地址的执行路径。”
  # 当 angr 找到一个满足 `find` 条件的状态时，它会停止搜索，并将该状态放入 `simulation.found` 列表中。
  # `explore` 方法会管理一个状态的集合（称为“工作集”），并将它们进行符号执行。
  # 它会根据探测器的规则来决定哪些状态是“活的”（继续执行）、哪些是“找到的”（满足 `find` 条件）以及哪些是“死亡的”（无法继续执行或不满足条件）。
  simulation.explore(find=print_good_address)
  # 检查是否找到了解决方案。simulation.explore() 方法会将找到的、
  # 能够到达目标指令的状态列表赋值给 simulation.found。
  # 请记住，在 Python 中，空列表会被评估为 False，非空列表则为 True。
  if simulation.found:
    # explore 方法在找到一个到达目标地址的状态后就会停止。
    solution_state = simulation.found[0]
    # 打印 angr 在标准输入中写入的、用于遵循 solution_state 的字符串。这就是我们的解决方案。
    # solution_state.posix.dumps(sys.stdin.fileno()) 获取标准输入的文件内容。
    # 在符号执行中，标准输入被视为一个符号值。`dumps` 方法会根据 `solution_state` 的约束来具体化（求解）这个符号值，
    # 并将其表示为实际的字节串。`sys.stdin.fileno()` 指定了我们要获取标准输入的文件描述符。
    # .decode() 将字节串解码为字符串。
    print(solution_state.posix.dumps(sys.stdin.fileno()).decode())
  else:
    # 如果 angr 未能找到到达 print_good_address 的路径，则抛出异常。
    # 可能是你输入的 print_good_address 地址有误？
    raise Exception('未能找到解决方案')

if __name__ == '__main__':
  main(sys.argv)