#!/usr/bin/env python3

# 导入所需的库：
# tempfile: 用于创建临时文件。
# jinja2: 一个 Python 的模板引擎，用于生成动态文本内容。
import sys, random, os, tempfile, jinja2, platform

def generate(argv):
  # 检查命令行参数的数量。脚本需要两个参数：种子和输出文件名。
  if len(argv) != 3:
    print('Usage: ./generate.py [seed] [output_file]')
    sys.exit()

  seed = argv[1]
  output_file = argv[2]

  # 使用提供的种子初始化随机数生成器。这确保了每次使用相同的种子时，生成的随机数序列是相同的。
  random.seed(seed)

  # 定义一个包含大写字母的字符串，作为生成随机字符串的字符集。
  userdef_charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

  # 生成一个长度为 8 的随机字符串。
  # random.choice(userdef_charset) 从字符集中随机选择一个字符。
  userdef = ''.join(random.choice(userdef_charset) for _ in range(8))

  # 打开并读取 Jinja2 模板文件。
  template = open(os.path.join(os.path.dirname(os.path.realpath(__file__)), '00_angr_find.c.jinja'), 'r').read()

  # 使用 Jinja2 的 Template 类加载模板内容。
  t = jinja2.Template(template)

  # 使用模板渲染 C 代码。
  # t.render() 方法将模板中的占位符替换为提供的值。
  # userdef: 替换模板中的 {{ userdef }}。
  # len_userdef: 替换模板中的 {{ len_userdef }}，即 userdef 的长度。
  c_code = t.render(userdef=userdef, len_userdef=len(userdef), description = '')

  # 创建一个临时的 C 源文件。
  # tempfile.NamedTemporaryFile 创建一个具有唯一名称的临时文件。
  # delete=False: 确保文件在关闭后不会被自动删除，因为我们需要稍后用 gcc 调用它。
  # suffix='.c': 指定文件的后缀为 .c。
  # mode='w': 以写入模式打开文件。
  with tempfile.NamedTemporaryFile(delete=False, suffix='.c', mode='w') as temp:
    # 将生成的 C 代码写入临时文件。
    temp.write(c_code)
    # 将文件指针移到文件开头，以便后续读取（虽然这里没有读取，但这是使用 temp.name 的常见做法，下面的代码会用到它）。
    temp.seek(0)

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

if __name__ == '__main__':
    generate(sys.argv)
