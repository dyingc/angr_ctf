#!/usr/bin/env python3
import sys, random, os, tempfile, jinja2, platform

def generate(argv):
  if len(argv) != 3:
    print('Usage: ./generate.py [seed] [output_file]')
    sys.exit()

  seed = argv[1]
  output_file = argv[2]
  random.seed(seed)

  userdef0 = random.randint(0, 0xFFFFFFFF)
  userdef1 = random.randint(0, 0xFFFFFFFF)
  complex_function0_string = ''.join([ (f'value ^= {random.randint(0,0xFFFFFFFF)};') for _ in range(32) ])
  complex_function1_string = ''.join([ (f'value ^= {random.randint(0,0xFFFFFFFF)};') for _ in range(32) ])

  template = open(os.path.join(os.path.dirname(os.path.realpath(__file__)), '04_angr_symbolic_stack.c.jinja'), 'r').read()
  t = jinja2.Template(template)
  c_code = t.render(description = '', complex_function0=complex_function0_string, complex_function1=complex_function1_string, userdef0=userdef0, userdef1=userdef1)

  with tempfile.NamedTemporaryFile(delete=False, suffix='.c', mode='w') as temp:
    temp.write(c_code)
    temp.seek(0)
    
    # 根据架构选择合适的编译参数
    arch = platform.machine()
    if arch.startswith("x86"):
      # 适用于 x86_64 架构的编译命令
      compile_cmd = 'gcc -fno-pie -no-pie -fcf-protection=none -fno-stack-protector -m32 -O0 -g -o ' + output_file + ' ' + temp.name + ' 2>/dev/null'
    elif arch == 'arm64':
      # 适用于 arm64 架构的编译命令 (Apple Silicon)
      compile_cmd = 'gcc -fno-stack-protector -O0 -g -o ' + output_file + '_arm' + ' ' + temp.name + ' 2>/dev/null'
    else:
      # 其他架构的默认编译命令
      compile_cmd = 'gcc -fno-stack-protector -O0 -g -o ' + output_file + '_other' + ' ' + temp.name + ' 2>/dev/null'

    # 使用 gcc 编译 C 代码。
    os.system(compile_cmd)

if __name__ == '__main__':
  generate(sys.argv)


