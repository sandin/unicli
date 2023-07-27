from .__init__ import CMD_RESULT_EXIT
from unidbg.common.context import Context


def cmd_exit(context: Context, line: str) -> int:
    print("Bye")
    return CMD_RESULT_EXIT
