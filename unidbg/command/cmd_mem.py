from unidbg.command import CMD_RESULT_FAILED, CMD_RESULT_OK
from unidbg.context import Context, State
from unidbg.executor.executor import MemoryPerm
from unidbg.util.cmd_parser import parse_address, parse_number, parse_bytes
from unidbg.util.hexdump import hexdump


def perm_to_str(perm: MemoryPerm) -> str:
    s = ['-', '-', '-']
    if perm & MemoryPerm.PROT_READ != 0:
        s[0] = 'r'
    if perm & MemoryPerm.PROT_WRITE != 0:
        s[1] = 'w'
    if perm & MemoryPerm.PROT_EXEC != 0:
        s[2] = 'x'
    return "".join(s)


def cmd_mem_list(context: Context, args: list[str]) -> int:
    if context.state != State.LOADED:
        print("invalid context state")
        return CMD_RESULT_FAILED

    regions, err = context.executor.mem_regions()
    if err is not None:
        print("Error: can not read memory list, %s" % err)
        return CMD_RESULT_FAILED

    for start, end, prot in regions:
        start_addr = context.arch.format_address(start)
        end_addr = context.arch.format_address(end+1)
        print("%s - %s %s" % (start_addr, end_addr, perm_to_str(prot)))
    return CMD_RESULT_OK


def cmd_mem_read(context: Context, args: list[str]) -> int:
    if context.state != State.LOADED:
        print("invalid context state")
        return CMD_RESULT_FAILED

    # <address>
    if len(args) < 1:
        print("missing <addr> arg")
        return CMD_RESULT_FAILED
    address = parse_address(args[0], -1)
    if address == -1:
        print("invalid address format: %s" % args[0])
        return CMD_RESULT_FAILED

    # <size>
    if len(args) < 2:
        print("missing <size> arg")
        return CMD_RESULT_FAILED
    size = parse_number(args[1], -1)
    if size == -1:
        print("invalid number format: %s" % args[1])
        return CMD_RESULT_FAILED

    data, err = context.executor.mem_read(context.base_addr + address, size)
    if err is not None:
        print("Error: can not read memory at 0x%x - 0x%x, %s" % (address, address + size, err))
        return CMD_RESULT_FAILED
    hexdump(data, off=address)
    return CMD_RESULT_OK


def cmd_mem_write(context: Context, args: list[str]) -> int:
    if context.state != State.LOADED:
        print("invalid context state")
        return CMD_RESULT_FAILED

    # <address>
    if len(args) < 1:
        print("missing <addr> arg")
        return CMD_RESULT_FAILED
    address = parse_address(args[0], -1)
    if address == -1:
        print("invalid address format: %s" % args[0])
        return CMD_RESULT_FAILED

    # <data>
    if len(args) < 2:
        print("missing <data> arg")
        return CMD_RESULT_FAILED
    data = parse_bytes(args[1])
    if len(data) == 0:
        print("invalid data format: %s" % args[1])
        return CMD_RESULT_FAILED

    ret, err = context.executor.mem_write(context.base_addr + address, data)
    if err is not None:
        print("Error: can not write memory at 0x%x - 0x%x, %s" % (address, address + len(data), err))
        return CMD_RESULT_FAILED
    hexdump(data, off=address)
    return CMD_RESULT_OK


def cmd_mem_map(context: Context, args: list[str]) -> int:
    if context.state != State.LOADED:
        print("invalid context state")
        return CMD_RESULT_FAILED

    # <address>
    if len(args) < 1:
        print("missing <addr> arg")
        return CMD_RESULT_FAILED
    address = parse_address(args[0], -1)
    if address == -1:
        print("invalid address format: %s" % args[0])
        return CMD_RESULT_FAILED

    # <size>
    if len(args) < 2:
        print("missing <size> arg")
        return CMD_RESULT_FAILED
    size = parse_number(args[1], -1)
    if size == -1:
        print("invalid number format: %s" % args[1])
        return CMD_RESULT_FAILED

    # <prot>
    if len(args) < 3:
        prot = MemoryPerm.PROT_ALL
    else:
        prot = parse_number(args[2], MemoryPerm.PROT_NONE)

    addr, err = context.executor.mem_map(address, size, prot)
    start_addr = context.arch.format_address(address)
    end_addr = context.arch.format_address(address + size)
    if err is not None:
        print("Error: can not map memory at %s- %sx %s, %s" % (start_addr, end_addr, perm_to_str(prot), err))
        return CMD_RESULT_FAILED
    print("%s - %s %s" % (start_addr, end_addr, perm_to_str(prot)))
    return CMD_RESULT_OK
