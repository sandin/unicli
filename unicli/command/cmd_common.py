from .__init__ import CMD_RESULT_EXIT, CMD_RESULT_OK, CMD_RESULT_FAILED
from unicli.context import Context, state_is_loaded
from unicli.util.cmd_parser import Command
from unicli.util import parse_init_script


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

    ctx.padding_cmds = parse_init_script(filename) + ctx.padding_cmds
    print("load script file `%s`" % filename)
    return CMD_RESULT_OK, None


def cmd_set_var(ctx: Context, cmd: Command) -> (int, str):
    name, err = cmd.get_str_arg("name", 0, None)
    if err is not None:
        return CMD_RESULT_FAILED, err

    value, err = cmd.get_str_arg("value", 1, None)
    if err is not None:
        return CMD_RESULT_FAILED, err

    ctx.local_vars[name] = value
    print("set %s = %s" % (name, value))
    return CMD_RESULT_OK, None


def cmd_unset_var(ctx: Context, cmd: Command) -> (int, str):
    name, err = cmd.get_str_arg("name", 0, None)
    if err is not None:
        return CMD_RESULT_FAILED, err

    if name not in ctx.local_vars:
        return CMD_RESULT_FAILED, "%s is undefined" % name

    value = ctx.local_vars[name]
    del ctx.local_vars[name]
    print("unset %s(%s)" % (name, value))
    return CMD_RESULT_OK, None


def cmd_print_var(ctx: Context, cmd: Command) -> (int, str):
    name, err = cmd.get_raw_arg("name", 0, None)
    if err is not None:
        return CMD_RESULT_FAILED, err

    if name.startswith("$"):
        name = name[1:]

    if name not in ctx.local_vars:
        return CMD_RESULT_FAILED, "%s is undefined" % name

    value = ctx.local_vars[name]
    print("$%s = %s" % (name, value))
    ctx.last_result = value
    return CMD_RESULT_OK, None

def cmd_set_base(ctx: Context, cmd: Command) -> (int, str):
    address, err = cmd.get_addr_arg("addr", 0, -1)
    if err is not None:
        return CMD_RESULT_FAILED, err

    ctx.base_addr = address
    print("Set base address 0x%x" % (address))
    ctx.last_result = ctx.base_addr
    return CMD_RESULT_OK, None


def cmd_disasm(ctx: Context, cmd: Command) -> (int, str):
    if not state_is_loaded(ctx.state):
        return CMD_RESULT_FAILED, "invalid context state"

    address, err = cmd.get_addr_arg("addr", 0, -1)
    if err is not None:
        return CMD_RESULT_FAILED, err

    size, err = cmd.get_int_arg("size", 1, -1)
    if err is not None:
        return CMD_RESULT_FAILED, err

    # --base <addr>
    base_addr = cmd.get_addr_flag(["b", "base"], 2, ctx.base_addr)

    ret, err = ctx.executor.disasm(base_addr + address, size)
    if err is not None:
        err = "can not disassemble code at 0x%x - 0x%x, %s" % (address, address + size, err)
        return CMD_RESULT_FAILED, err
    ctx.last_result = ret
    return CMD_RESULT_OK, None


def cmd_comment(ctx: Context, cmd: Command) -> (int, str):
    if not state_is_loaded(ctx.state):
        return CMD_RESULT_FAILED, "invalid context state"

    address, err = cmd.get_addr_arg("addr", 0, -1)
    if err is not None:
        return CMD_RESULT_FAILED, err

    comment = " ".join(cmd.get_raw().split(" ")[2:])

    # --base <addr>
    base_addr = cmd.get_addr_flag(["b", "base"], 2, ctx.base_addr)

    ret, err = ctx.executor.add_comment(base_addr + address, comment)
    if err is not None:
        err = "can not add comment at 0x%x, %s" % (address, err)
        return CMD_RESULT_FAILED, err
    ctx.last_result = ret
    return CMD_RESULT_OK, None


def cmd_run_expr(ctx: Context, cmd: Command) -> (int, str):
    expr = cmd.get_raw()[len(cmd.cmd):]
    if not expr:
        return CMD_RESULT_FAILED, "missing <expr> arg"

    try:
        ret = eval(expr)
        print(ret)
        ctx.last_result = ret
        return CMD_RESULT_OK, None
    except:
        return CMD_RESULT_FAILED, "can't eval expr: %s" % expr


def cmd_run_file(ctx: Context, cmd: Command) -> (int, str):
    filename, err = cmd.get_file_arg("filename", 0, None)
    if err is not None:
        return CMD_RESULT_FAILED, err

    with open(filename, 'rb') as f:
        g = globals()
        g.update({
            "__file__": filename,
            "__name__": "__main__",
            "ctx": ctx
        })
        exec(compile(f.read(), filename, 'exec'), g, g)
    return CMD_RESULT_OK, None
