from unidbg.command import CMD_RESULT_FAILED, CMD_RESULT_OK
from unidbg.common.context import Context, State
from unidbg.executor.executor import Executor, MemoryPerm
from unidbg.util.args_parser import parse_addr_arg, parse_int_arg
from unidbg.util.hexdump import hexdump


def perm_to_str(perm: MemoryPerm) -> str:
    s = ['-', '-', '-']
    if perm & MemoryPerm.PROT_READ != 0:
        s[0] = 'R'
    if perm & MemoryPerm.PROT_WRITE != 0:
        s[1] = 'W'
    if perm & MemoryPerm.PROT_EXEC != 0:
        s[2] = 'E'
    return "".join(s)


def cmd_mem_list(context: Context, line: str) -> int:
    if context.state != State.LOADED:
        print("invalid context state")
        return CMD_RESULT_FAILED

    regions, err = context.executor.mem_regions()
    if err is not None:
        print("Error: can not read memory list, %s" % err)
        return CMD_RESULT_FAILED

    for start, end, prot in regions:
        print("[0x%08x - 0x%08x) %s" % (start, end+1, perm_to_str(prot)))
    return CMD_RESULT_OK


def cmd_mem_read(context: Context, line: str) -> int:
    if context.state != State.LOADED:
        print("invalid context state")
        return CMD_RESULT_FAILED

    address, line = parse_addr_arg(line, -1)
    if address == -1:
        print("missing <addr> arg")
        return CMD_RESULT_FAILED

    size, line = parse_int_arg(line, -1)
    if size == -1:
        print("missing <size> arg")
        return CMD_RESULT_FAILED

    data, err = context.executor.mem_read(context.base_addr + address, size)
    if err is not None:
        print("Error: can not read memory at 0x%x - 0x%x, %s" % (address, address + size, err))
        return CMD_RESULT_FAILED

    hexdump(data, off=address)
    return CMD_RESULT_OK
