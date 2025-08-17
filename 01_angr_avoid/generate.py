#!/usr/bin/env python3

# 导入所需的库：
# sys: 提供对系统特定参数和函数的访问。
# random: 用于生成随机数。
# os: 提供使用操作系统依赖功能的方法。
# tempfile: 用于创建临时文件和目录。
# jinja2: 一个 Python 模板引擎，用于生成动态内容。
import sys, random, os, tempfile, jinja2, platform

def check_string_recursive(array0, array1, random_list, bit):
  # 这个函数递归地构建 C 语言代码，用于比较两个数组（或字符串）的特定位。
  # 它的目的是在生成的二进制文件中创建复杂的条件跳转逻辑，
  # 使得 Angr 在探索路径时，如果选择了错误的位比较结果，就会进入 `avoid_me()` 函数，
  # 从而引导 Angr 避开这些“坏”路径。

  # array0 和 array1: 代表在 C 代码中要比较的两个变量名（例如 'buffer' 和 'password'）。
  # random_list: 一个布尔值列表，决定了在当前位比较中，是期望相等还是不相等。
  # bit: 当前正在比较的位索引，从高位向低位递减。

  # 基本情况：如果 bit 小于 0，表示所有位都已比较完毕。
  # 此时返回 `maybe_good()` 函数的调用，这通常是 Angr 期望找到的“好”路径。
  if bit < 0:
    return f'maybe_good({array0}, {array1});'
  else:
    # 根据 random_list 的第一个布尔值，决定当前位的比较逻辑。
    # random_list[0] 为 True 意味着期望 `array0` 和 `array1` 的当前位相等。
    if random_list[0]:
      # 如果当前位相等，则递归调用 `check_string_recursive` 处理下一位。
      # 如果不相等，则插入 `avoid_me()` 调用，引导 Angr 避开此路径。
      ret_str = f'if (CHECK_BIT({array0}, {bit}) == CHECK_BIT({array1}, {bit}))' + '{' + check_string_recursive(array0, array1, random_list[1:], bit-1) + '} else { avoid_me(); ' + check_string_recursive(array0, array1, random_list[1:], bit-1) + '}'
    # random_list[0] 为 False 意味着期望 `array0` 和 `array1` 的当前位不相等。
    else:
      # 如果当前位不相等，则插入 `avoid_me()` 调用，引导 Angr 避开此路径。
      # 如果相等，则递归调用 `check_string_recursive` 处理下一位。
      ret_str = f'if (CHECK_BIT({array0}, {bit}) != CHECK_BIT({array1}, {bit}))' + '{ avoid_me();' + check_string_recursive(array0, array1, random_list[1:], bit-1) + '} else { ' + check_string_recursive(array0, array1, random_list[1:], bit-1) + '}'
    return ret_str

def generate(argv):
  # 检查命令行参数的数量。
  # 脚本需要两个参数：种子和输出文件名。
  if len(argv) != 3:
    print('Usage: ./generate.py [seed] [output_file]')
    sys.exit()

  # 从命令行参数中提取种子和输出文件名。
  seed = argv[1]
  output_file = argv[2]
  # 使用提供的种子初始化随机数生成器。
  # 这确保了每次使用相同的种子时，生成的随机数序列是相同的，从而保证了生成的二进制文件是可重现的。
  random.seed(seed)

  # 初始化一个空字符串用于描述。在当前脚本中，此变量未被实际使用，但保留以保持与模板的兼容性。
  description = ''

  # 生成一个包含 64 个随机布尔值（True/False）的列表。
  # 这个 `random_list` 是 `check_string_recursive` 函数的关键输入，
  # 它决定了在生成的 C 代码中，每个位比较的条件（是期望相等还是不相等）。
  # 这样可以动态地生成不同的“避免”逻辑。
  random_list = [random.choice([True, False]) for _ in range(64)]
  # 定义用于生成随机字符串的字符集。
  userdef_charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
  # 生成一个 8 个字符的随机字符串。
  # 这个 `userdef` 字符串会被嵌入到生成的 C 代码中，作为程序的一部分。
  userdef = ''.join(random.choice(userdef_charset) for _ in range(8))
  # 重新生成一个包含 64 个随机布尔值（这会覆盖之前的列表）。
  # 实际上，这里第二次生成 `random_list` ��多余的，因为第一次生成的列表没有被使用。
  # 最终 `check_string_recursive` 函数使用的是第二次生成的 `random_list`。
  random_list = [random.choice([True, False]) for _ in range(64)]
  # 调用 `check_string_recursive` 函数，生成用于 C 代码的条件字符串。
  # 'buffer' 和 'password' 是在 Jinja 模板中定义的变量名，它们代表程序中用户输入和目标密码。
  # 12 是起始位索引，表示从第 12 位开始比较。
  check_string = check_string_recursive('buffer', 'password', random_list, 12)

  # 打开并读取 Jinja2 模板文件。
  # 模板文件 `01_angr_avoid.c.jinja` 包含了 C 语言代码的骨架，
  # 其中的占位符（如 {{ userdef }} 和 {{ check_string }}）将被替换为动态生成的内容。
  template = open(os.path.join(os.path.dirname(os.path.realpath(__file__)), '01_angr_avoid.c.jinja'), 'r').read()
  # 使用 Jinja2 的 Template 类加载模板内容。
  t = jinja2.Template(template)
  # 使用模板渲染 C 代码，将占位符替换为提供的值。
  # userdef: 替换模板中的 {{ userdef }}。
  # len_userdef: 替换模板中的 {{ len_userdef }}，即 userdef 的长度。
  # description: 替换模板中的 {{ description }}（此处为空）。
  # check_string: 替换模板中的 {{ check_string }}，即生成的条件代码，这是本挑战的核心逻辑。
  c_code = t.render(userdef=userdef, len_userdef=len(userdef), description = '', check_string=check_string)

  # 创建一个临时的 C 源文件。
  # delete=False: 确保文件在关闭后不会被自动删除，因为我们需要用 gcc 编译它。
  # suffix='.c': 指定文件后缀为 .c。
  # mode='w': 以写入模式打开文件。
  with tempfile.NamedTemporaryFile(delete=False, suffix='.c', mode='w') as temp:
    # 将生成的 C 代码写入临时文件。
    temp.write(c_code)
    # 将文件指针移到文件开头（此处未直接使用，但通常用于后续读取）。
    temp.seek(0)

    # 根据架构选择合适的编译参数
    arch = platform.machine()
    if arch.startswith("x86"):
      # 适用于 x86_64 架构的编译命令
      compile_cmd = 'cc -m32 -O2 -g -fno-pie -no-pie -fstack-protector-strong -Wl,-z,relro -o ' + output_file + ' ' + temp.name
      compile_cmd = 'gcc -fno-pie -no-pie -m32 -o ' + output_file + ' ' + temp.name
      compile_cmd = 'gcc -fno-pie -no-pie -fcf-protection=none -fno-stack-protector -m32 -O0 -g -o ' + output_file + ' ' + temp.name
    elif arch == 'arm64':
      # 适用于 arm64 架构的编译命令 (Apple Silicon)
      compile_cmd = 'gcc -fno-stack-protector -O0 -g -o ' + output_file + '_arm' + ' ' + temp.name
    else:
      # 其他架构的默认编译命令
      compile_cmd = 'gcc -fno-stack-protector -O0 -g -o ' + output_file + '_other' + ' ' + temp.name

    # 使用 gcc 编译 C 代码。
    os.system(compile_cmd)

if __name__ == '__main__':
  generate(sys.argv)

