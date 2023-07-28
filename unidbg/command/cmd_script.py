from .__init__ import CMD_RESULT_FAILED, CMD_RESULT_OK
from unidbg.context import Context
from unidbg.util import parse_init_script
from unidbg.util.cmd_parser import Command


def cmd_script(context: Context, cmd: Command) -> (int, str):
    filename, err = cmd.get_file_arg("filename", 0, None)
    if err is not None:
        return CMD_RESULT_FAILED, err

    context.padding_cmds += parse_init_script(filename)
    print("load script file `%s`" % filename)
    return CMD_RESULT_OK, None
