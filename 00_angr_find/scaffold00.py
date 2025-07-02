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
  path_to_binary = ???  # :string (这里应填写二进制文件的路径)
  project = angr.Project(path_to_binary)

  # 告诉 angr 从哪里开始执行 (是从 main() 函数开始还是其他地方？)。
  # 目前，使用 entry_state 函数指示 angr 从 main() 函数开始。
  initial_state = project.factory.entry_state(
    # 添加这些选项是为了确保 angr 在处理未定义内存和寄存器时不会因为未初始化而崩溃。
    # SYMBOL_FILL_UNCONSTRAINED_MEMORY: 用符号值填充未约束的内存。
    # SYMBOL_FILL_UNCONSTRAINED_REGISTERS: 用符号值填充未约束的寄存器。
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
  print_good_address = ???  # :integer (通常是十六进制格式的地址)
  simulation.explore(find=print_good_address)

  # 检查是否找到了解决方案。simulation.explore() 方法会将找到的、
  # 能够到达目标指令的状态列表赋值给 simulation.found。
  # 请记住，在 Python 中，空列表会被评估为 False，非空列表则为 True。
  if simulation.found:
    # explore 方法在找到一个到达目标地址的状态后就会停止。
    solution_state = simulation.found[0]

    # 打印 angr 在标准输入中写入的、用于遵循 solution_state 的字符串。这就是我们的解决方案。
    # solution_state.posix.dumps(sys.stdin.fileno()) 获取标准输入的文件内容。
    # .decode() 将字节串解码为字符串。
    print(solution_state.posix.dumps(sys.stdin.fileno()).decode())
  else:
    # 如果 angr 未能找到到达 print_good_address 的路径，则抛出异常。
    # 可能是你输入的 print_good_address 地址有误？
    raise Exception('未能找到解决方案')

if __name__ == '__main__':
  # 这是一个标准的 Python 写法，确保只有当脚本作为主程序运行时，才会执行 main 函数。
  main(sys.argv)