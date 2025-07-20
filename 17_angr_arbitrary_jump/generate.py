#!/usr/bin/env python3
import binascii, sys, random, os, tempfile, jinja2, platform

def generate(argv):
  if len(argv) != 3:
    print('Usage: ./generate.py [seed] [output_file]')
    sys.exit()

  seed = argv[1]
  output_file = argv[2]
  random.seed(seed)

# cs492
#  text_tail_modifier0 = 0x05
  text_tail_modifier0 = 0x30
  text_tail_modifier1 = 0x01
  text_parts = ''.join([ chr(random.randint(ord('A'), ord('Z'))) for _ in range(2) ]
    + [ chr(random.randint(ord('A') - text_tail_modifier1, ord('Z') - text_tail_modifier1)) ]
    + [ chr(random.randint(ord('A') - text_tail_modifier0, ord('Z') - text_tail_modifier0)) ])
  text_address = '0x' + binascii.hexlify(text_parts.encode('utf8')).decode('utf8')

  padding0 = random.randint(0, 32)
  padding1 = random.randint(0, 32)

  template = open(os.path.join(os.path.dirname(os.path.realpath(__file__)), '17_angr_arbitrary_jump.c.jinja'), 'r').read()
  t = jinja2.Template(template)
  c_code = t.render(description='', padding0=padding0, padding1=padding1)

  with tempfile.NamedTemporaryFile(delete=False, suffix='.c', mode='w') as temp:
    temp.write(c_code)
    temp.seek(0)
    
    # 根据��构选择合适的编译参数
    arch = platform.machine()
    if arch.startswith("x86"):
      # 适用于 x86_64 架构的编译命令
      compile_cmd = 'gcc -fno-pie -no-pie -fcf-protection=none -fno-stack-protector -m32 -O0 -g -Wl,--section-start=.text=' + text_address + ' -o ' + output_file + ' ' + temp.name
    elif arch == 'arm64':
      # 适用于 arm64 架构的编译命令 (Apple Silicon)
      compile_cmd = 'gcc -fno-stack-protector -O0 -g -Wl,--section-start=.text=' + text_address + ' -o ' + output_file + '_arm' + ' ' + temp.name
    else:
      # 其他架构的默认编译命令
      compile_cmd = 'gcc -fno-stack-protector -O0 -g -Wl,--section-start=.text=' + text_address + ' -o ' + output_file + '_other' + ' ' + temp.name

    # 使用 gcc 编译 C 代码。
    os.system(compile_cmd)

if __name__ == '__main__':
  generate(sys.argv)
