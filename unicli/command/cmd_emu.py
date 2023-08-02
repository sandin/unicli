from .__init__ import CMD_RESULT_FAILED, CMD_RESULT_OK
from unicli.context import Context, State, state_is_loaded, state_is_running
from unicli.util.cmd_parser import Command


def cmd_emu_start(ctx: Context, cmd: Command) -> (int, str):
    if not state_is_loaded(ctx.state):
        return CMD_RESULT_FAILED, "invalid context state"

    start_addr, err = cmd.get_addr_arg("start_addr", 0, -1)
    if err is not None:
        return CMD_RESULT_FAILED, err

    end_addr, err = cmd.get_addr_arg("end_addr", 1, 0)
    if err is not None:
        return CMD_RESULT_FAILED, err

    timeout, err = cmd.get_int_arg("timeout", 2, 0)
    if err is not None:
        return CMD_RESULT_FAILED, err

    count, err = cmd.get_int_arg("count", 3, 0)
    if err is not None:
        return CMD_RESULT_FAILED, err

    # --base <addr>
    base_addr = cmd.get_addr_flag(["b", "base"], 4, ctx.base_addr)

    # --auto_map
    auto_map = cmd.has_flag(["a", "auto_map"], 4, False)

    start_addr_s = ctx.arch.format_address(start_addr)
    end_addr_s = ctx.arch.format_address(end_addr) if end_addr != -1 else ""
    ctx.state = State.RUNNING
    if end_addr != 0:
        ret, err = ctx.executor.emu_start(base_addr + start_addr, base_addr + end_addr, timeout, count, auto_map)
        ctx.state = State.LOADED
        print("Emulation done, range: %s - %s" % (start_addr_s, end_addr_s))
    else:
        ret, err = ctx.executor.emu_start(base_addr + start_addr, 0, timeout, count, auto_map)
    if err is not None:
        err = "can not start emulation at %s - %s, %s" % (start_addr_s, end_addr_s, err)
        return CMD_RESULT_FAILED, err
    ctx.last_result = ret
    return CMD_RESULT_OK, None


def cmd_emu_stop(ctx: Context, cmd: Command) -> (int, str):
    if not state_is_running(ctx.state):
        return CMD_RESULT_FAILED, "invalid context state"

    ret, err = ctx.executor.emu_stop()
    if err is not None:
        err = "can not stop the emulation"
        return CMD_RESULT_FAILED, err
    print("Stop the emulation")
    ctx.state = State.LOADED
    ctx.last_result = ret
    return CMD_RESULT_OK, None
