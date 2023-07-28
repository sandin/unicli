from .__init__ import CMD_RESULT_EXIT
from unidbg.context import Context
from unidbg.util.cmd_parser import Command


def cmd_exit(ctx: Context, cmd: Command) -> (int, str):
    print("Bye")
    return CMD_RESULT_EXIT, None
