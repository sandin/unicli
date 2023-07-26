from unidbg.command import CMD_RESULT_FAILED, CMD_RESULT_OK
from unidbg.executor.executor import Executor, MemoryPerm
from unidbg.util.args_parser import parse_addr_arg, parse_int_arg
from unidbg.util.hexdump import hexdump


def cmd_mem_read(context, line):
    if context['state'] != 1:
        print("invalid context state")
        return CMD_RESULT_FAILED

    address, line = parse_addr_arg(line, -1)
    if address is -1:
        print("missing <addr> arg")
        return CMD_RESULT_FAILED

    size, line = parse_int_arg(line, -1)
    if size is -1:
        print("missing <size> arg")
        return CMD_RESULT_FAILED

    executor = context['executor']  # type: Executor
    base_addr = context['base_addr']  # type: int
    data, err = executor.mem_read(base_addr + address, size)
    if err is not None:
        print("Error: can not read memory at 0x%x - 0x%x, %s" % (address, address + size, err))
        return CMD_RESULT_FAILED

    hexdump(data, off=address)
    return CMD_RESULT_OK
