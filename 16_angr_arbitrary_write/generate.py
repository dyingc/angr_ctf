#!/usr/bin/env python3
import binascii, sys, random, os, tempfile, jinja2, platform

def expanded_switch_statement(variable, miss_statement, hit_statement, samples):
  target = random.choice(samples)

  ret_str = 'switch (%s) {' % (variable,)
  for sample in samples:
    ret_str += 'case %d: %s; break;' % (sample, hit_statement if sample == target else miss_statement)
  ret_str += 'default: %s; break; }' % (miss_statement,)
  return ret_str

def generate(argv):
  if len(argv) != 3:
    print('Usage: ./generate.py [seed] [output_file]')
    sys.exit()

  seed = argv[1]
  output_file = argv[2]
  random.seed(seed)

# cs492
#  rodata_tail_modifier = 0x15
#  rodata_tail_modifier = 0x10
#  rodata_parts = ''.join([ chr(random.randint(ord('A'), ord('Z'))) for _ in xrange(3) ] + [ chr(random.randint(0,4) + rodata_tail_modifier) ])
  rodata_tail_modifier = 0x2c
  rodata_parts = ''.join([ chr(random.randint(ord('A'), ord('Z'))) for _ in range(3) ]
    + [ chr(random.randint(ord('A') - rodata_tail_modifier, ord('Z') - rodata_tail_modifier)) ])
  rodata_address = '0x' + binascii.hexlify(rodata_parts.encode('utf8')).decode('utf8')

  userdef_charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
  userdef = ''.join(random.choice(userdef_charset) for _ in range(8))
  hit_statement = 'strncpy(locals.to_copy_to, locals.buffer, 16)'
  miss_statement = 'strncpy(unimportant_buffer, locals.buffer, 16)'
  expanded_switch_statement_string = expanded_switch_statement('key', miss_statement, hit_statement, random.sample(range(2**26-1), 2))

  template = open(os.path.join(os.path.dirname(os.path.realpath(__file__)), '16_angr_arbitrary_write.c.jinja'), 'r').read()
  t = jinja2.Template(template)
  c_code = t.render(description='', userdef=userdef, expanded_switch_statement=expanded_switch_statement_string)

  with tempfile.NamedTemporaryFile(delete=False, suffix='.c', mode='w') as temp:
    temp.write(c_code)
    temp.seek(0)
    
    # 根据架构选择合适的编译参数
    arch = platform.machine()
    if arch.startswith("x86"):
      # 适用于 x86_64 架构的编译命令
      compile_cmd = 'gcc -fno-pie -no-pie -fcf-protection=none -fno-stack-protector -m32 -O0 -g -Wl,--section-start=.data=' + rodata_address + ' -o ' + output_file + ' ' + temp.name
    elif arch == 'arm64':
      # 适用于 arm64 架构的编译命令 (Apple Silicon)
      compile_cmd = 'gcc -fno-stack-protector -O0 -g -Wl,--section-start=.data=' + rodata_address + ' -o ' + output_file + '_arm' + ' ' + temp.name
    else:
      # 其他架构的默认编译命令
      compile_cmd = 'gcc -fno-stack-protector -O0 -g -Wl,--section-start=.data=' + rodata_address + ' -o ' + output_file + '_other' + ' ' + temp.name

    # 使用 gcc 编译 C 代码。
    os.system(compile_cmd)

if __name__ == '__main__':
  generate(sys.argv)
