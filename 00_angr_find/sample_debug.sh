r2 -R 'stdio=input.txt' -c 'aaa 2>/dev/null; e asm.lines=true; e bin.relocs=false; s main; db main; db main+0x38; db main+0x3c; pd 16' -d ./00_angr_find_arm
