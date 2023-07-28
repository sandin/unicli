from .__init__ import CMD_RESULT_EXIT, CMD_RESULT_OK
from unidbg.context import Context
from unidbg.util.cmd_parser import Command


def cmd_exit(ctx: Context, cmd: Command) -> (int, str):
    print("Bye, Happy Hacking.")
    return CMD_RESULT_EXIT, None


def cmd_help(ctx: Context, cmd: Command) -> (int, str):
    print(ctx.usage)
    return CMD_RESULT_OK, None
