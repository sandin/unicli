from unidbg.command import CMD_RESULT_FAILED, CMD_RESULT_OK
from unidbg.executor.executor import Executor, MemoryPerm


def perm_to_str(perm: MemoryPerm) -> str:
    s = [' ', ' ', ' ']
    if perm & MemoryPerm.PROT_READ != 0:
        s[0] = 'R'
    if perm & MemoryPerm.PROT_WRITE != 0:
        s[1] = 'W'
    if perm & MemoryPerm.PROT_EXEC != 0:
        s[2] = 'E'
    return "".join(s)


def cmd_mem_list(context, line):
    if context['state'] != 1:
        print("invalid context state")
        return CMD_RESULT_FAILED

    executor = context['executor']  # type: Executor
    regions, err = executor.mem_regions()
    if err is not None:
        print("Error: can not read memory list, %s" % err)
        return CMD_RESULT_FAILED

    for start, end, prot in regions:
        print("[0x%08x - 0x%08x) %s" % (start, end+1, perm_to_str(prot)))
    return CMD_RESULT_OK
