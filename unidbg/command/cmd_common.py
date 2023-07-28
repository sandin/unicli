from .__init__ import CMD_RESULT_EXIT, CMD_RESULT_OK, CMD_RESULT_FAILED
from unidbg.context import Context
from unidbg.util.cmd_parser import Command
from unidbg.util import parse_init_script


def cmd_exit(ctx: Context, cmd: Command) -> (int, str):
    print("Bye, Happy Hacking.")
    return CMD_RESULT_EXIT, None


def cmd_help(ctx: Context, cmd: Command) -> (int, str):
    print(ctx.usage)
    return CMD_RESULT_OK, None


def cmd_script(ctx: Context, cmd: Command) -> (int, str):
    filename, err = cmd.get_file_arg("filename", 0, None)
    if err is not None:
        return CMD_RESULT_FAILED, err

    ctx.padding_cmds += parse_init_script(filename)
    print("load script file `%s`" % filename)
    return CMD_RESULT_OK, None


def cmd_set(ctx: Context, cmd: Command) -> (int, str):
    name, err = cmd.get_str_arg("name", 0, None)
    if err is not None:
        return CMD_RESULT_FAILED, err

    value, err = cmd.get_str_arg("value", 1, None)
    if err is not None:
        return CMD_RESULT_FAILED, err

    ctx.local_vars[name] = value
    print("set %s = %s" % (name, value))
    return CMD_RESULT_OK, None


def cmd_unset(ctx: Context, cmd: Command) -> (int, str):
    name, err = cmd.get_str_arg("name", 0, None)
    if err is not None:
        return CMD_RESULT_FAILED, err

    if name not in ctx.local_vars:
        return CMD_RESULT_FAILED, "%s is undefined" % name

    value = ctx.local_vars[name]
    del ctx.local_vars[name]
    print("unset %s(%s)" % (name, value))
    return CMD_RESULT_OK, None


def cmd_set_base(ctx: Context, cmd: Command) -> (int, str):
    address, err = cmd.get_addr_arg("addr", 0, -1)
    if err is not None:
        return CMD_RESULT_FAILED, err

    ctx.base_addr = address
    print("Set base address 0x%x" % (address))
    return CMD_RESULT_OK, None
