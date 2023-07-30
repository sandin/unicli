from .__init__ import CMD_RESULT_FAILED, CMD_RESULT_OK
from unicli.context import Context, state_is_running
from unicli.util.cmd_parser import Command


def cmd_step_inst(ctx: Context, cmd: Command) -> (int, str):
    if not state_is_running(ctx.state):
        return CMD_RESULT_FAILED, "invalid context state"

    ret, err = ctx.executor.step_inst()
    if err is not None:
        return CMD_RESULT_FAILED, "can not step to the next inst, %s" % err
    return CMD_RESULT_OK, None


def cmd_step_block(ctx: Context, cmd: Command) -> (int, str):
    if not state_is_running(ctx.state):
        return CMD_RESULT_FAILED, "invalid context state"

    ret, err = ctx.executor.step_block()
    if err is not None:
        return CMD_RESULT_FAILED, "can not step to the next inst, %s" % err
    return CMD_RESULT_OK, None


def cmd_step_address(ctx: Context, cmd: Command) -> (int, str):
    if not state_is_running(ctx.state):
        return CMD_RESULT_FAILED, "invalid context state"

    address, err = cmd.get_addr_arg("addr", 0, -1)
    if err is not None:
        return CMD_RESULT_FAILED, err

    ret, err = ctx.executor.step_address(address)
    if err is not None:
        return CMD_RESULT_FAILED, "can not step to the next inst, %s" % err
    return CMD_RESULT_OK, None