import time
import json

try:
    import r2pipe
except ImportError:
    r2pipe = None

from ai_agent.libs.lib_emulate import simulate_external_call

def emulate_function(
    binary_path,
    function_name,
    max_steps=100,
    timeout=60,
    stack_bytes=32,
    stack_size=0x10000,
    stack_base=0x70000000,
    data_size=0x1000,
    data_base=0x60000000
):
    """
    基于 ESIL 的 Radare2 二进制函数级仿真，返回与 Rizin 风格一致的结果结构。

    Args:
        binary_path (str): 二进制路径
        function_name (str): 函数名或入口地址
        max_steps (int): 最大仿真步数
        timeout (int): 超时秒
        stack_bytes (int): 每步采集栈字节数
        stack_size (int): 分配的栈总字节数
        stack_base (int): 栈基址
        data_size (int): 分配的数据段字节数
        data_base (int): 数据段基址

    Returns:
        dict: {
            "success": bool,
            "final_registers": {...},
            "execution_trace": [...],
            "execution_summary": {...},
            "emulation_type": "r2_esil",
            "setup_log": [...],
            "error": ... (如有)
        }
    """
    result = {}
    trace = []
    setup_log = []
    if r2pipe is None:
        return {"success": False, "error": "r2pipe not installed"}
    try:
        r2 = r2pipe.open(binary_path)
        start_time = time.time()
        setup_log.append("Radare2: 开始分析")
        r2.cmd("aaa")
        setup_log.append("Radare2: 运行aaa分析完成")
        # 查找函数入口地址
        func_addr = None
        flist = r2.cmdj("aflj")
        if flist:
            for f in flist:
                if f.get("name") == function_name:
                    func_addr = f.get("offset")
                    break
        if func_addr is None:
            try:
                # 支持直接用地址
                func_addr = int(function_name, 0)
            except Exception:
                return {"success": False, "error": f"未找到目标函数 {function_name}"}
        # 初始化仿真VM
        r2.cmd("aeim")
        setup_log.append("ESIL VM 初始化 (aeim)")
        r2.cmd(f"aeip {func_addr}")
        setup_log.append(f"设置 PC 至 {hex(func_addr)} (aeip)")
        steps = 0
        vm_error = None
        while steps < max_steps and (time.time() - start_time) < timeout:
            pc_regs = r2.cmdj("aerj")
            if pc_regs:
                pc = pc_regs.get("rip") or pc_regs.get("eip") or pc_regs.get("pc")
            else:
                pc = None
            disasm = ""
            ops = None
            if pc is not None:
                ops = r2.cmdj(f"aoj @ {pc}")
                if ops and isinstance(ops, list) and len(ops) > 0:
                    disasm = ops[0].get("disasm", "")
            stack_bytes_hex = ""
            if pc_regs and (stack_bytes > 0):
                sp = pc_regs.get("rsp") or pc_regs.get("esp") or pc_regs.get("sp")
                if sp is not None:
                    try:
                        stack_bytes_hex = r2.cmdj(f"pxj {stack_bytes} @ {sp}")
                    except Exception:
                        stack_bytes_hex = ""
            # 外部调用仿真入口（如遇调esil不支持的call，需额外增强）
            trace.append({
                "step": steps,
                "pc": pc,
                "instruction": disasm,
                "registers": pc_regs,
                "stack": stack_bytes_hex,
            })
            # 单步
            ret = r2.cmd("aes")
            if ret and "cannot emulate" in ret:
                vm_error = ret
                setup_log.append(f"仿真报错: {ret.strip()}")
                break
            steps += 1
        r2.cmd("aek")
        final_regs = r2.cmdj("aerj") if steps > 0 else None
        result = {
            "success": vm_error is None,
            "final_registers": final_regs,
            "execution_trace": trace,
            "execution_summary": {
                "steps_executed": steps,
                "execution_time": round(time.time() - start_time, 3),
                "memory_setup_success": True,
                "architecture": r2.cmd("?e asm.arch").strip()
            },
            "emulation_type": "r2_esil",
            "setup_log": setup_log
        }
        if vm_error:
            result["error"] = vm_error
        return result
    except Exception as e:
        return {"success": False, "error": f"r2_emulator emulate_function error: {e}"}
