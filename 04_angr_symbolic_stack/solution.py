# 这个挑战将比你之前遇到的挑战更具挑战性。
# 由于本次 CTF 的目标是教授符号执行，而不是如何构建栈帧，
# 这些注释将引导你理解栈上的内容。
#   ! ! !
# 重要提示：此脚本中的任何地址不一定正确！请自行反汇编
#            二进制文件以确定正确的地址！
#   ! ! !

import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  # 对于这个挑战，我们希望在调用 scanf 之后开始。请注意，这
  # 是在一个函数的中间。
  #
  # 这个挑战需要处理栈，所以你必须格外
  # 小心你的起始位置，否则你将进入一个
  # 栈设置不正确的情况。为了确定在 scanf 之后从哪里开始，
  # 我们需要查看调用的反汇编以及紧随其后的指令：
  #   sub esp, 0x4
  #   lea eax, [ebp-0x10]
  #   push eax
  #   lea eax, [ebp-0xc]
  #   push eax
  #   push 0x80489c3
  #   call 0x8048370 ; __isoc99_scanf@plt
  #   add esp, 0x10
  # 现在，问题是：我们是在紧随 scanf 的指令 (add esp, 0x10) 处开始，
  # 还是在紧随其后的指令 (未显示) 处开始？
  # 考虑 'add esp, 0x10' 的作用。提示：它与在调用函数之前推送到栈上的
  # scanf 参数有关。
  # 鉴于我们不在 Angr 模拟中调用 scanf，我们应该从哪里开始？
  # (!)
  start_address = ???
  initial_state = project.factory.blank_state(
    addr=start_address,
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
  )

  # 我们正在跳入一个函数的中间！因此，我们需要考虑
  # 函数如何构建栈。函数的第二条指令是：
  #   mov ebp, esp
  # 此时它分配了我们计划定位的栈帧部分：
  #   sub esp, 0x18
  # 注意 esp 相对于 ebp 的值。它们之间的空间（通常）
  # 是栈空间。由于 esp 减少了 0x18
  #
  #        /-------- 栈 --------\
  # ebp -> |                     |
  #        |---------------------|
  #        |                     |
  #        |---------------------|
  #         . . . (总共 0x18 字节)
  #         . . . 某个地方是
  #         . . . 存储 scanf 结果的数据。
  # esp -> |                     |
  #        \---------------------/
  #
  # 由于我们是在 scanf 之后开始，我们跳过了这个栈构建
  # 步骤。为了弥补这一点，我们需要自己构建栈。让我们
  # 从以程序完全相同的方式初始化 ebp 开始。
  initial_state.regs.ebp = initial_state.regs.esp

  # scanf("%u %u") 需要通过注入两个位向量来替换。
  # 目前，如果 scanf 有多个输入参数，
  # Angr 不会自动注入符号。这意味着 Angr 可以
  # 处理 'scanf("%u")'，但不能处理 'scanf("%u %u")'。
  # 你可以复制粘贴下面的行或使用 Python 列表。
  # (!)
  password0 = claripy.BVS('password0', ???)
  ...

  # 这是困难的部分。我们需要弄清楚栈是什么样子的，至少
  # 要足够好地将我们的符号注入到我们想要的位置。为了做到
  # 这一点，让我们弄清楚 scanf 的参数是什么：
#   sub esp, 0x4
#   lea eax, [ebp-0x10]
#   push eax
#   lea eax, [ebp-0xc]
#   push eax
#   push 0x80489c3
#   call 0x8048370 ; __isoc99_scanf@plt
#   add esp, 0x10
  # 如你所见，对 scanf 的调用看起来像这样：
  # scanf(  0x80489c3,   ebp - 0xc,   ebp - 0x10  )
  #      format_string    password0    password1
  #  由此，我们可以构建我们新的、更准确的栈图：
  #
  #            /-------- 栈 --------\
  # ebp ->     |        填充        |
  #            |---------------------|
  # ebp - 0x01 |      更多填充       |
  #            |---------------------|
  # ebp - 0x02 |    甚至更多填充     |
  #            |---------------------|
  #                        . . .               <- 多少填充？提示：password0 有多少
  #            |---------------------|            字节？
  # ebp - 0x0b | password0, 第二字节 |
  #            |---------------------|
  # ebp - 0x0c | password0, 第一字节 |
  #            |---------------------|
  # ebp - 0x0d | password1, 最后一字节 |
  #            |---------------------|
  #                        . . .
  #            |---------------------|
  # ebp - 0x10 | password1, 第一字节 |
  #            |---------------------|
  #                        . . .
  #            |---------------------|
  # esp ->     |                     |
  #            \---------------------/
  #
  # 找出有多少空间，并通过在推送密码位向量之前减少 esp 来分配必要的填充到栈中。
  padding_length_in_bytes = ???  # :integer
  initial_state.regs.esp -= padding_length_in_bytes

  # 将变量推送到栈上。确保以正确的顺序推送它们！
  # 以下函数的语法是：
  #
  # initial_state.stack_push(bitvector)
  #
  # 这将把位向量推到栈上，并以正确的量增加 esp。
  # 你需要将多个位向量推到栈上。
  # (!)
  initial_state.stack_push(???)  # :bitvector (claripy.BVS, claripy.BVV, claripy.BV)
  ...

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return ???

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return ???

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    solution0 = solution_state.solver.eval(password0)
    ...

    solution = ???
    print(solution)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
