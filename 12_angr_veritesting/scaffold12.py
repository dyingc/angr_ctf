import angr
import claripy
import sys

def main(argv):
    path_to_binary = argv[1] if len(argv) > 1 else './binary/x32/12_angr_veritesting'
    project = angr.Project(path_to_binary, auto_load_libs=False)

    initial_state = project.factory.entry_state(
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        }
    )

    # 启用 veritesting：让 angr 自动合并循环内相似的分支路径
    simgr = project.factory.simgr(initial_state, veritesting=True)

    # find/avoid 优先用 stdout 检查（veritesting 合并后 addr 不可靠）
    def suc(state):
        stdout_output = state.posix.dumps(sys.stdout.fileno())
        reached = b'Good Job.' in stdout_output
        if reached:
            print("Reached success via stdout!")
        # 备选：检查成功的路径 0x080492c1（puts call 地址 0x080492c9 所在 CFG 块的首地址）
        # if state.addr == 0x080492c1:
        #     print("At success puts call!")
        #     return True
        return reached

    def fail(state):
        stdout_output = state.posix.dumps(sys.stdout.fileno())
        avoided = b'Try again.' in stdout_output
        if avoided:
            print("Avoided failure via stdout!")
        # 备选：检查失败路径的 0x080492d3（puts call 0x080492db 所在 CFG 块的首地址）
        # if state.addr == 0x080492d3:
        #     print("At failure puts call!")
        #     return True
        return avoided

    # 禁用 install_hooks，让 veritesting 自然处理循环
    # install_hooks(project)  # 注释掉

    # 探索：veritesting 会合并路径，solver 求解所有约束
    # simgr.explore(find=suc, avoid=fail)
    simgr.explore(find=0x080492c1)

    if simgr.found:
        solution_state = simgr.found[0]
        solution = solution_state.posix.dumps(sys.stdin.fileno()).decode().strip()
        print(f'Solution: {solution}')
    else:
        print('No solution found.')

if __name__ == '__main__':
    main(sys.argv)
