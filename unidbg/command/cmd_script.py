import os
from .__init__ import CMD_RESULT_FAILED, CMD_RESULT_OK
from unidbg.context import Context
from unidbg.util import parse_init_script


def cmd_script(context: Context, args: list[str]) -> int:
    if len(args) < 1:
        print("Error: missing <filename> arg")
        return CMD_RESULT_FAILED

    filename = args[0]
    if not os.path.exists(filename):
        print("Error: `%s` file is not exists!" % filename)
        return CMD_RESULT_FAILED

    context.padding_cmds += parse_init_script(filename)
    print("load script file `%s`" % filename)
    return CMD_RESULT_OK
