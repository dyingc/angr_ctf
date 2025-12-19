#!/usr/bin/env python3

import sys, random, os, tempfile
import re
import textwrap

class Templite:
    def __init__(self, text):
        self.text = text

    def render(self, **kwargs):
        result = []
        pos = 0
        text = self.text

        namespace = kwargs.copy()
        namespace['random'] = random
        namespace['os'] = os

        output_buffer = []
        def write(s):
            output_buffer.append(str(s))
        namespace['write'] = write

        pattern = r'\$\{(.*?)\}\$'

        for match in re.finditer(pattern, text, re.DOTALL):
            result.append(text[pos:match.start()])

            code = match.group(1)

            # 如果是简单变量（单行无换行）
            if code.strip() in kwargs and '\n' not in code:
                result.append(str(kwargs[code.strip()]))
            else:
                # 去除代码块的公共缩进
                code = textwrap.dedent(code)
                output_buffer.clear()
                exec(code, namespace)
                result.append(''.join(output_buffer))

            pos = match.end()

        result.append(text[pos:])
        return ''.join(result)

def generate(argv):
    if len(argv) != 3:
        print('Usage: ./generate.py [seed] [output_file]')
        sys.exit()

    seed = argv[1]
    output_file = argv[2]
    random.seed(seed)

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'description.txt'), 'r') as f:
        description = f.read()

    template = open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'xx_angr_segfault.c.templite'), 'r').read()
    c_code = Templite(template).render(description=description)

    with tempfile.NamedTemporaryFile(delete=False, suffix='.c', mode='w') as temp:
        temp.write(c_code)
        temp.seek(0)
        os.system('gcc -fno-pie -no-pie -m32 -fno-stack-protector -o ' + output_file + ' ' + temp.name)

if __name__ == '__main__':
    generate(sys.argv)