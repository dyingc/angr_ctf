def _handle_syscall_instruction(self, instruction: str) -> bool:
    """
    处理系统调用和中断指令的ESIL模拟
    支持跨平台常见系统调用的模拟（Linux x86/x64, macOS ARM64等）
    """
    # 获取当前架构的寄存器信息
    regs = self.arch_info["registers"]
    os_type = self.arch_info.get("os", "linux")
    arch = self.arch_info.get("arch", "x86")
    bits = self.arch_info.get("bits", 64)
    
    # 获取系统调用号和参数寄存器
    syscall_reg = self._get_syscall_number_register()
    arg_regs = regs.get("arg_regs", [])
    return_reg = regs.get("return_reg_name", "rax")
    
    try:
        # 获取当前系统调用号
        syscall_num = int(self.r2.cmd(f"aer {syscall_reg}").strip(), 0)
        
        # 获取参数值
        args = []
        for i, reg in enumerate(arg_regs[:6]):  # 最多6个参数
            try:
                arg_val = int(self.r2.cmd(f"aer {reg}").strip(), 0)
                args.append(arg_val)
            except:
                args.append(0)
        
        # 根据操作系统和架构处理系统调用
        if self._handle_platform_syscall(syscall_num, args, os_type, arch, bits):
            self.logger.debug(f"模拟系统调用: {syscall_num} (args: {args[:3]}...)")
        else:
            # 默认处理：设置返回值为0（成功）
            self.r2.cmd(f"aer {return_reg}=0")
            self.logger.warning(f"未知系统调用: {syscall_num}")
        
        # 执行ESIL步骤并检查是否中断
        result = self.r2.cmd("aes")
        return "ESIL BREAK" not in result
        
    except Exception as e:
        self.logger.error(f"系统调用模拟错误: {e}")
        # 设置默认返回值
        self.r2.cmd(f"aer {return_reg}=0")
        result = self.r2.cmd("aes")
        return "ESIL BREAK" not in result

def _get_syscall_number_register(self) -> str:
    """根据架构获取系统调用号寄存器"""
    arch = self.arch_info.get("arch", "x86")
    bits = self.arch_info.get("bits", 64)
    
    if arch == "arm" and bits == 64:
        return "x8"  # ARM64 系统调用号在x8
    elif arch == "x86" and bits == 64:
        return "rax"  # x86_64 系统调用号在rax
    elif arch == "x86" and bits == 32:
        return "eax"  # x86 系统调用号在eax
    else:
        return "rax"  # 默认

def _handle_platform_syscall(self, syscall_num: int, args: list, 
                           os_type: str, arch: str, bits: int) -> bool:
    """
    根据平台处理具体的系统调用
    返回True表示已处理，False表示未知系统调用
    """
    return_reg = self.arch_info["registers"].get("return_reg_name", "rax")
    
    if os_type == "linux":
        return self._handle_linux_syscalls(syscall_num, args, arch, bits, return_reg)
    elif os_type == "macos" or os_type == "darwin":
        return self._handle_macos_syscalls(syscall_num, args, arch, bits, return_reg)
    elif os_type == "windows":
        return self._handle_windows_syscalls(syscall_num, args, arch, bits, return_reg)
    else:
        return False

def _handle_linux_syscalls(self, syscall_num: int, args: list, 
                         arch: str, bits: int, return_reg: str) -> bool:
    """处理Linux系统调用"""
    
    # Linux x86_64 常见系统调用
    if arch == "x86" and bits == 64:
        linux_x64_syscalls = {
            0: self._sys_read,      # read
            1: self._sys_write,     # write
            2: self._sys_open,      # open
            3: self._sys_close,     # close
            9: self._sys_mmap,      # mmap
            10: self._sys_mprotect, # mprotect
            11: self._sys_munmap,   # munmap
            12: self._sys_brk,      # brk
            39: self._sys_getpid,   # getpid
            60: self._sys_exit,     # exit
            257: self._sys_openat,  # openat
        }
    # Linux ARM64 系统调用
    elif arch == "arm" and bits == 64:
        linux_arm64_syscalls = {
            63: self._sys_read,     # read
            64: self._sys_write,    # write
            56: self._sys_openat,   # openat
            57: self._sys_close,    # close
            222: self._sys_mmap,    # mmap
            226: self._sys_mprotect,# mprotect
            215: self._sys_munmap,  # munmap
            214: self._sys_brk,     # brk
            172: self._sys_getpid,  # getpid
            93: self._sys_exit,     # exit
        }
        linux_x64_syscalls = linux_arm64_syscalls
    else:
        return False
    
    if syscall_num in linux_x64_syscalls:
        linux_x64_syscalls[syscall_num](args, return_reg)
        return True
    return False

def _handle_macos_syscalls(self, syscall_num: int, args: list,
                         arch: str, bits: int, return_reg: str) -> bool:
    """处理macOS系统调用"""
    
    # macOS ARM64 系统调用 (通常加上0x2000000前缀)
    base_num = syscall_num & 0xFFFFFF  # 去掉类别前缀
    
    macos_syscalls = {
        1: self._sys_exit,      # exit
        3: self._sys_read,      # read
        4: self._sys_write,     # write
        5: self._sys_open,      # open
        6: self._sys_close,     # close
        20: self._sys_getpid,   # getpid
        197: self._sys_mmap,    # mmap
        74: self._sys_mprotect, # mprotect
        73: self._sys_munmap,   # munmap
        469: self._sys_openat,  # openat
    }
    
    if base_num in macos_syscalls:
        macos_syscalls[base_num](args, return_reg)
        return True
    return False

def _handle_windows_syscalls(self, syscall_num: int, args: list,
                           arch: str, bits: int, return_reg: str) -> bool:
    """处理Windows NT系统调用（简化版）"""
    # Windows系统调用号变化频繁，这里只处理一些通用的
    windows_syscalls = {
        # 这些是示例，实际Windows系统调用号需要根据版本确定
        0x1A: self._sys_exit,      # NtTerminateProcess
        0x3F: self._sys_read,      # NtReadFile
        0x8: self._sys_write,      # NtWriteFile
    }
    
    if syscall_num in windows_syscalls:
        windows_syscalls[syscall_num](args, return_reg)
        return True
    return False

# 具体的系统调用模拟函数
def _sys_read(self, args: list, return_reg: str):
    """模拟read系统调用"""
    fd, buf, count = args[0], args[1], args[2] if len(args) > 2 else 1024
    # 模拟成功读取
    read_bytes = min(count, 1024)  # 假设最多读取1024字节
    self.r2.cmd(f"aer {return_reg}={read_bytes}")

def _sys_write(self, args: list, return_reg: str):
    """模拟write系统调用"""
    fd, buf, count = args[0], args[1], args[2] if len(args) > 2 else 0
    # 模拟成功写入
    self.r2.cmd(f"aer {return_reg}={count}")

def _sys_open(self, args: list, return_reg: str):
    """模拟open系统调用"""
    # 模拟成功打开，返回文件描述符
    self.r2.cmd(f"aer {return_reg}=3")  # 假设fd=3

def _sys_openat(self, args: list, return_reg: str):
    """模拟openat系统调用"""
    # 模拟成功打开，返回文件描述符
    self.r2.cmd(f"aer {return_reg}=3")

def _sys_close(self, args: list, return_reg: str):
    """模拟close系统调用"""
    # 模拟成功关闭
    self.r2.cmd(f"aer {return_reg}=0")

def _sys_mmap(self, args: list, return_reg: str):
    """模拟mmap系统调用"""
    # 模拟成功映射，返回地址
    self.r2.cmd(f"aer {return_reg}=0x40000000")

def _sys_mprotect(self, args: list, return_reg: str):
    """模拟mprotect系统调用"""
    # 模拟成功保护
    self.r2.cmd(f"aer {return_reg}=0")

def _sys_munmap(self, args: list, return_reg: str):
    """模拟munmap系统调用"""
    # 模拟成功解映射
    self.r2.cmd(f"aer {return_reg}=0")

def _sys_brk(self, args: list, return_reg: str):
    """模拟brk系统调用"""
    # 模拟堆扩展
    new_brk = args[0] if args and args[0] != 0 else 0x40100000
    self.r2.cmd(f"aer {return_reg}={new_brk}")

def _sys_getpid(self, args: list, return_reg: str):
    """模拟getpid系统调用"""
    # 模拟进程ID
    self.r2.cmd(f"aer {return_reg}=1234")

def _sys_exit(self, args: list, return_reg: str):
    """模拟exit系统调用"""
    # 退出不设置返回值，但可以记录退出码
    exit_code = args[0] if args else 0
    self.logger.info(f"程序退出，退出码: {exit_code}")
    # 可以设置一个标志表示程序应该停止模拟
    self.should_exit = True
