from .__init__ import CMD_RESULT_FAILED, CMD_RESULT_OK
from unicli.context import Context, State
from unicli.util.cmd_parser import Command


def cmd_emu_start(ctx: Context, cmd: Command) -> (int, str):
    if ctx.state != State.LOADED:
        return CMD_RESULT_FAILED, "invalid context state"

    start_addr, err = cmd.get_addr_arg("start_addr", 0, -1)
    if err is not None:
        return CMD_RESULT_FAILED, err

    end_addr, err = cmd.get_addr_arg("end_addr", 1, -1)
    if err is not None:
        return CMD_RESULT_FAILED, err

    timeout, err = cmd.get_addr_arg("timeout", 2, 0)
    if err is not None:
        return CMD_RESULT_FAILED, err

    count, err = cmd.get_addr_arg("count", 3, 0)
    if err is not None:
        return CMD_RESULT_FAILED, err

    start_addr_s = ctx.arch.format_address(start_addr)
    end_addr_s = ctx.arch.format_address(end_addr)
    print("Start emulation, range: %s - %s" % (start_addr_s, end_addr_s))
    ret, err = ctx.executor.emu_start(ctx.base_addr + start_addr, ctx.base_addr + end_addr, timeout, count)
    if err is not None:
        err = "can not start emulation at %s - %s, %s" % (start_addr_s, end_addr_s, err)
        return CMD_RESULT_FAILED, err
    print("Emulation done, range: %s - %s" % (start_addr_s, end_addr_s))
    return CMD_RESULT_OK, None


def cmd_emu_stop(ctx: Context, cmd: Command) -> (int, str):
    if ctx.state != State.LOADED:
        return CMD_RESULT_FAILED, "invalid context state"

    ret, err = ctx.executor.emu_stop()
    if err is not None:
        err = "can not stop the emulation"
        return CMD_RESULT_FAILED, err
    print("Stop the emulation")
    return CMD_RESULT_OK, None
