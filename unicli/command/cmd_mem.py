from unicli.command import CMD_RESULT_FAILED, CMD_RESULT_OK
from unicli.context import Context, state_is_loaded
from unicli.executor.executor import MemoryPerm
from unicli.util import write_content_to_file
from unicli.util.hexdump import hexdump
from unicli.util.cmd_parser import Command
from unicli.util.memory import page_start, page_align


def perm_to_str(perm: MemoryPerm) -> str:
    s = ['-', '-', '-']
    if perm & MemoryPerm.PROT_READ != 0:
        s[0] = 'r'
    if perm & MemoryPerm.PROT_WRITE != 0:
        s[1] = 'w'
    if perm & MemoryPerm.PROT_EXEC != 0:
        s[2] = 'x'
    return "".join(s)


def cmd_mem_list(ctx: Context, cmd: Command) -> (int, str):
    if not state_is_loaded(ctx.state):
        return CMD_RESULT_FAILED, "invalid context state"

    regions, err = ctx.executor.mem_regions()
    if err is not None:
        return CMD_RESULT_FAILED, "can not read memory list, %s" % err

    for start, end, prot in regions:
        start_addr_s = ctx.arch.format_address(start)
        end_addr_s = ctx.arch.format_address(end + 1)
        print("%s - %s %s" % (start_addr_s, end_addr_s, perm_to_str(prot)))
    return CMD_RESULT_OK, None


def cmd_mem_read(ctx: Context, cmd: Command) -> (int, str):
    if not state_is_loaded(ctx.state):
        return CMD_RESULT_FAILED, "invalid context state"

    # <addr>
    address, err = cmd.get_addr_arg("addr", 0, -1)
    if err is not None:
        return CMD_RESULT_FAILED, err

    # <size>
    size, err = cmd.get_int_arg("size", 1, 0)
    if err is not None:
        return CMD_RESULT_FAILED, err

    # --out <out>
    out = cmd.get_str_flag(["o", "out"], 2, None)

    # --base <addr>
    base_addr = cmd.get_addr_flag(["b", "base"], 2, ctx.base_addr)

    data, err = ctx.executor.mem_read(base_addr + address, size)
    start_addr_s = ctx.arch.format_address(address)
    end_addr_s = ctx.arch.format_address(address + size)
    if err is not None:
        err = "can not read memory at %s - %s, %s" % (start_addr_s, end_addr_s, err)
        return CMD_RESULT_FAILED, err
    if out is not None:
        write_content_to_file(data, out)
        print("%s - %s %d bytes have been saved to the file: %s" % (start_addr_s, end_addr_s, len(data), out))
    else:
        hexdump(data, off=address)
    return CMD_RESULT_OK, None


def cmd_mem_write(ctx: Context, cmd: Command) -> (int, str):
    if not state_is_loaded(ctx.state):
        return CMD_RESULT_FAILED, "invalid context state"

    # <addr>
    address, err = cmd.get_addr_arg("addr", 0, -1)
    if err is not None:
        return CMD_RESULT_FAILED, err

    # <data>
    data, err = cmd.get_bytes_arg("data", 1, b"")
    if err is not None:
        return CMD_RESULT_FAILED, err

    # --base <addr>
    base_addr = cmd.get_addr_flag(["b", "base"], 2, ctx.base_addr)

    ret, err = ctx.executor.mem_write(base_addr + address, data)
    if err is not None:
        err = "can not write memory at 0x%x - 0x%x, %s" % \
              (base_addr + address, base_addr + address + len(data), err)
        return CMD_RESULT_FAILED, err
    hexdump(data, off=address)
    return CMD_RESULT_OK, None


def cmd_mem_map(ctx: Context, cmd: Command) -> (int, str):
    if not state_is_loaded(ctx.state):
        return CMD_RESULT_FAILED, "invalid context state"

    # <address>
    address, err = cmd.get_addr_arg("addr", 0, -1)
    if err is not None:
        return CMD_RESULT_FAILED, err

    # <size>
    size, err = cmd.get_int_arg("size", 1, -1)
    if err is not None:
        return CMD_RESULT_FAILED, err

    # <prot>
    prot, err = cmd.get_int_arg("prot", 2, int(MemoryPerm.PROT_ALL))
    if err is not None:
        return CMD_RESULT_FAILED, err

    address = page_start(address)
    size = page_align(size)

    addr, err = ctx.executor.mem_map(address, size, prot)
    start_addr_s = ctx.arch.format_address(address)
    end_addr_s = ctx.arch.format_address(address + size)
    if err is not None:
        err = "can not map memory at %s - %s %s, %s" % (start_addr_s, end_addr_s, perm_to_str(prot), err)
        return CMD_RESULT_FAILED, err
    print("%s - %s %s" % (start_addr_s, end_addr_s, perm_to_str(prot)))
    return CMD_RESULT_OK, None
