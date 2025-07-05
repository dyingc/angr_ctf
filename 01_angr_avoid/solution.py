import angr
import sys
import time

def main(argv):
  # 定义目标二进制文件的路径。
  # 这个二进制文件是之前 `generate.py` 脚本生成的，它包含了一个需要被 Angr 解决的挑战。
  path_to_binary = '01_angr_avoid/01_angr_avoid'

  # 创建一个 Angr Project 对象。
  # Project 对象是 Angr 分析的基础，它加载并解析二进制文件，使其可以进行符号执行。
  project = angr.Project(path_to_binary, auto_load_libs=False)

  # 创建初始状态 (initial state)。
  # 这是符号执行的起点。
  # add_options 参数用于配置 Angr 如何处理未约束的内存和寄存器。
  # SYMBOL_FILL_UNCONSTRAINED_MEMORY: 当访问未初始化的内存时，Angr 会用符号值填充它，而不是引发错误。这对于探索未知输入非常有用。
  # SYMBOL_FILL_UNCONSTRAINED_REGISTERS: 类似地，对于未初始化的寄存器，Angr 会用符号值填充它们。
  initial_state = project.factory.entry_state(
      add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                      angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
  )

  # 创建一个模拟管理器 (Simulation Manager)。
  # Simgr 是 Angr 中用于管理和探索程序状态的核心组件。它维护着一个状态池（active、found、avoided 等），并根据探索策略进行状态转换。
  simulation = project.factory.simgr(initial_state, veritesting=True)

  # simulation.use_technique(angr.exploration_techniques.Spiller())

  # 探索二进制文件。
  # 这里的目标是找到一条路径，这条路径能够到达 `print_good_address`，同时避免到达 `will_not_succeed_address`。
  # `generate.py` 生成的挑战通常包含一个 `avoid_me()` 函数，当输入不正确时会跳转到该函数，
  # 而 `print_good_address` 可能是成功路径的末尾。

  # `print_good_address` 是一个在二进制文件中，当程序执行到这里时，表示找到了“好”路径（即正确的输入）。
  # 这个地址通常对应于 `maybe_good()` 函数的入口点或其内部的某个关键点。
  print_good_address = 0x08049230

  # `will_not_succeed_address` 是一个在二进制文件中，当程序执行到这里时，表示进入了“坏”路径（即错误的输入）。
  # 这个地址通常对应于 `avoid_me()` 函数的入口点或其内部的某个关键点。
  will_not_succeed_address = 0x08049223

  # 调用 `explore` 方法开始符号执行。
  # `find`: 指定 Angr 应该尝试到达的目标地址。一旦找到一个到达此地址的状态，它就会被放入 `simulation.found` 列表中。
  # `avoid`: 指定 Angr 应该避免到达的地址。任何到达这些地址的状态都会被标记为 `avoided`，并且不再继续探索。
  simulation.explore(find=print_good_address, avoid=will_not_succeed_address)

  # 检查是否找到了满足条件（到达 `find` 地址且未到达 `avoid` 地址）的状态。
  if simulation.found:
    # 如果找到了，取出第一个解决方案状态。
    solution_state = simulation.found[0]
    # 从解决方案状态中提取标准输入 (stdin) 的具体值。
    # `posix.dumps(sys.stdin.fileno())` 用于获取导致该状态的 stdin 输入。
    # `.decode()` 将字节串解码为字符串，以便打印。
    print(solution_state.posix.dumps(sys.stdin.fileno()).decode())
  else:
    # 如果没有找到解决方案，则抛出异常。
    raise Exception('Could not find the solution')


def format_time(seconds):
  """将秒数格式化为 xx days, hh:mm:ss.xx 的字符串."""
  if seconds < 0:
    return "Invalid time"

  days = int(seconds // (24 * 3600))
  seconds %= (24 * 3600)
  hours = int(seconds // 3600)
  seconds %= 3600
  minutes = int(seconds // 60)
  seconds = seconds % 60

  return f"{days} days, {hours:02}:{minutes:02}:{seconds:05.2f}"

if __name__ == '__main__':
  start_time = time.time()  # 记录开始时间
  main(sys.argv)
  end_time = time.time()    # 记录结束时间
  elapsed_time = end_time - start_time
  print(f"Execution time: {format_time(elapsed_time)}") # 打印执行时间