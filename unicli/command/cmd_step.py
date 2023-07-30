from .__init__ import CMD_RESULT_FAILED
from unicli.context import Context
from unicli.util.cmd_parser import Command


def cmd_step_inst(ctx: Context, cmd: Command) -> (int, str):
    return CMD_RESULT_FAILED, "not implement cmd"


def cmd_step_block(ctx: Context, cmd: Command) -> (int, str):
    return CMD_RESULT_FAILED, "not implement cmd"


def cmd_step_address(ctx: Context, cmd: Command) -> (int, str):
    return CMD_RESULT_FAILED, "not implement cmd"
