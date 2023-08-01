from .__init__ import CMD_RESULT_FAILED, CMD_RESULT_OK
from unicli.context import Context
from unicli.util.cmd_parser import Command


def cmd_hook_block(ctx: Context, cmd: Command) -> (int, str):
    address, err = cmd.get_addr_arg("addr", 0, -1)
    if err is not None:
        return CMD_RESULT_FAILED, err

    subcommand = cmd.get_subcommand_arg("subcommand", 1, None)
    if err is not None:
        return CMD_RESULT_FAILED, err

    # --base <addr>
    base_addr = cmd.get_addr_flag(["b", "base"], 2, ctx.base_addr)

    ret, err = ctx.executor.add_block_hook(base_addr + address, subcommand)
    if err is not None:
        return CMD_RESULT_FAILED, err
    address_s = ctx.arch.format_address(address)
    print("hook block at %s" % address_s)
    ctx.last_result = ret
    return CMD_RESULT_OK, None


def cmd_hook_code(ctx: Context, cmd: Command) -> (int, str):
    address, err = cmd.get_addr_arg("addr", 0, -1)
    if err is not None:
        return CMD_RESULT_FAILED, err

    subcommand = cmd.get_subcommand_arg("subcommand", 1, None)
    if err is not None:
        return CMD_RESULT_FAILED, err

    # --base <addr>
    base_addr = cmd.get_addr_flag(["b", "base"], 2, ctx.base_addr)

    ret, err = ctx.executor.add_code_hook(base_addr + address, subcommand)
    if err is not None:
        return CMD_RESULT_FAILED, err
    address_s = ctx.arch.format_address(address)
    print("hook code at %s" % address_s)
    ctx.last_result = ret
    return CMD_RESULT_OK, None
