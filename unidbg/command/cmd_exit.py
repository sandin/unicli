from .__init__ import CMD_RESULT_EXIT
from unidbg.context import Context


def cmd_exit(context: Context, args: list[str]) -> int:
    print("Bye")
    return CMD_RESULT_EXIT
