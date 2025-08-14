#!/usr/bin/env python3
import sys, random, os, tempfile, jinja2, platform

def randomly_modify(var):
  """
  生成一个随机的C语言赋值语句，用于修改指定的变量。
  这个函数旨在创建一些看似复杂但实际上是确定性操作的代码行，
  以增加生成的C程序的复杂性，挑战符号执行引擎。

  Args:
    var (str): 要修改的变量名，例如 'input'。

  Returns:
    str: 一个C语言赋值语句字符串，例如 "input += 12345;" 或 "input ^= 0xABCDEF;"。
  """
  # 随机选择一个操作符：加等于 (+=) 或 异或等于 (^=)。
  operator = random.choice(['+=', '^='])
  # 生成一个32位无符号整数范围内的随机整数 (0 到 0xFFFFFFFF)。
  random_int = random.randint(0, 0xFFFFFFFF)
  # 拼接成完整的C语言赋值语句并返回。
  return var + operator + str(random_int) + ';'

def generate(argv):
  """
  生成一个C语言程序，该程序包含多个对一个变量进行随机修改的函数。
  这个程序旨在创建一个对符号执行引擎来说具有挑战性的场景，
  因为它需要跟踪一个变量在多个随机操作序列后的最终值。
  通常用于 Angr 等符号执行工具的挑战，以测试其处理复杂算术和逻辑操作的能力。

  Args:
    argv (list): 命令行参数列表，预期包含脚本名称、种子和输出文件名。
  """
  # 检查命令行参数数量是否正确。
  if len(argv) != 3:
    print('Usage: ./generate.py [seed] [output_file]')
    sys.exit()

  # 从命令行参数中获取随机种子和输出文件路径。
  seed = argv[1]
  output_file = argv[2]
  # 使用提供的种子初始化随机数生成器，确保每次生成的可重现性。
  random.seed(seed)

  # 生成三段独立的C语言代码字符串，每段都包含对 'input' 变量的随机修改操作。
  # 每段代码的长度在16到48行之间随机选择。
  # 这些字符串将作为独立的函数体或代码块嵌入到最终的C程序中。

  # 第一个复杂函数/代码块的字符串
  complex_function_1_string = ''
  for i in range(0, random.randint(16, 48)):
    complex_function_1_string += randomly_modify('input') # 每次循环添加一行修改 'input' 的代码

  # 第二个复杂函数/代码块的字符串
  complex_function_2_string = ''
  for i in range(0, random.randint(16, 48)):
    complex_function_2_string += randomly_modify('input') # 每次循环添加一行修改 'input' 的代码

  # 第三个复杂函数/代码块的字符串
  complex_function_3_string = ''
  for i in range(0, random.randint(16, 48)):
    complex_function_3_string += randomly_modify('input') # 每次循环添加一行修改 'input' 的代码

  # 打开并读取 Jinja2 模板文件。
  # 模板文件 `03_angr_symbolic_registers.c.jinja` 包含了 C 语言代码的骨架，
  # 其中的占位符（如 {{ complex_function_1 }} 等）将被替换为动态生成的内容。
  template = open(os.path.join(os.path.dirname(os.path.realpath(__file__)), '03_angr_symbolic_registers.c.jinja'), 'r').read()
  # 创建 Jinja2 模板对象。
  t = jinja2.Template(template)
  # 渲染模板，将动态生成的代码片段填充到模板中。
  # `description` 是一个占位符，在此处为空。
  c_code = t.render(description = '', complex_function_1=complex_function_1_string, complex_function_2=complex_function_2_string, complex_function_3=complex_function_3_string)

  # 使用临时文件来编译生成的C代码。
  # `delete=False` 确保文件在关闭后不会立即删除，以便 `gcc` 可以访问。
  # `suffix='.c'` 指定文件后缀。
  # `mode='w'` 以写入模式打开。
  with tempfile.NamedTemporaryFile(delete=False, suffix='.c', mode='w') as temp:
    temp.write(c_code) # 将生成的C代码写入临时文件。
    temp.seek(0) # 将文件指针重置到开头，以防万一。

    # 根据架构选择合适的编译参数
    arch = platform.machine()
    if arch.startswith("x86"):
      # 适用于 x86_64 架构的编译命令
      # -fno-pie: 禁用位置无关代码生成（Piece）。
      # -no-pie: 禁用位置无关可执行文件生成。(radare2 / rizin 的`pdf`命令显示的是rebased地址)
      # -fcf-protection=none: 禁用控制流保护（如 CET (Control-flow Enforcement Technology)）
      # -fno-stack-protector: 禁用栈保护
      # -O0: 无优化，保持源码与汇编的完美对应关系
      # -g: 生成调试符号信息（DWARF格式），支持 GDB 源码级调试
      # -m32: 生成 32 位可执行文件。
      compile_cmd = 'gcc -fno-pie -no-pie -fcf-protection=none -fno-stack-protector -m32 -O0 -g -o ' + output_file + ' ' + temp.name
    elif arch == 'arm64':
      # 适用于 arm64 架构的编译命令 (Apple Silicon)
      compile_cmd = f'gcc -fno-stack-protector -O0 -g -o {output_file + "_arm"} {temp.name}'
    else:
      # 其他架构的默认编译命令
      compile_cmd = f'gcc -fno-stack-protector -O0 -g -o {output_file + "_other"} {temp.name}'

    # 使用 gcc 编译 C 代码。
    # -o output_file: 指定输出的可执行文件名。
    # temp.name: 指定要编译的源文件（临时 C 文件）。
    os.system(compile_cmd)

  # 编译完成后，临时文件不再需要。
  # 注意：由于 `delete=False`，这里没有显式地删除临时文件。
  # 在生产代码中，通常会使用 `try...finally` 块来确保文件被删除：
  # import os
  # try:
  #   # ... code ...
  # finally:
  #   if os.path.exists(temp.name):
  #     os.unlink(temp.name)

if __name__ == '__main__':
  # 当脚本作为主程序运行时，调用 `generate` 函数，传入命令行参数。
  generate(sys.argv)
