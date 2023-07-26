from .__init__ import CMD_RESULT_EXIT


def cmd_exit(context, line):
    print("Bye")
    return CMD_RESULT_EXIT
