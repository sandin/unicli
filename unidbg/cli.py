import os.path
import sys
from prompt_toolkit import prompt

from .__init__ import __version__
from .command.cmd_emu import cmd_emu_start, cmd_emu_stop
from .command.cmd_var import cmd_set, cmd_unset
from .context import Context
from .command import CMD_RESULT_EXIT, CMD_RESULT_FAILED
from .command.cmd_exit import cmd_exit
from .command.cmd_help import cmd_help
from .command.cmd_load import cmd_load
from .command.cmd_mem import cmd_mem_list, cmd_mem_read, cmd_mem_map, cmd_mem_write
from .command.cmd_reg import cmd_reg_write, cmd_reg_read
from .command.cmd_script import cmd_script
from .util import register_cmd, parse_init_script
from .util.cmd_parser import parse_command

g_all_commands = {}
register_cmd(g_all_commands, "exit", ".exit", "exit()", "e", handler=cmd_exit)
register_cmd(g_all_commands, "help", "h", handler=cmd_help)
register_cmd(g_all_commands, "load", "l", handler=cmd_load)
register_cmd(g_all_commands, "script",  "s", handler=cmd_script)
register_cmd(g_all_commands, "mem_list",  "ml", handler=cmd_mem_list)
register_cmd(g_all_commands, "mem_read",  "mr", handler=cmd_mem_read)
register_cmd(g_all_commands, "mem_write",  "mr", handler=cmd_mem_write)
register_cmd(g_all_commands, "mem_map",  "mm", handler=cmd_mem_map)
register_cmd(g_all_commands, "reg_write",  "rw", handler=cmd_reg_write)
register_cmd(g_all_commands, "reg_read",  "rr", handler=cmd_reg_read)
register_cmd(g_all_commands, "set",  "st", handler=cmd_set)
register_cmd(g_all_commands, "unset",  "us", handler=cmd_unset)
register_cmd(g_all_commands, "emu_start",  "es", handler=cmd_emu_start)
register_cmd(g_all_commands, "emu_stop",  "et", handler=cmd_emu_stop)


def main():
    print('UniDbg %s' % __version__)
    print('Type "help" for more information.')

    ctx = Context()
    if len(sys.argv) >= 2:
        init_script = sys.argv[1]
        if not os.path.exists(init_script):
            print("warning: %s init script file is not exists")
        ctx.padding_cmds += parse_init_script(init_script)
        print("load init script file `%s`" % init_script)

    while True:
        if len(ctx.padding_cmds) > 0:
            line = ctx.padding_cmds[0]
            del ctx.padding_cmds[0]
            if line.strip() and not line.startswith("#"):
                print("%s %s" % (ctx.prompt, line))
        else:
            line = prompt("%s " % ctx.prompt)
        if not line.strip() or line.startswith("#"):
            continue
        command = parse_command(ctx, line)
        if command.cmd in g_all_commands:
            ret, err = g_all_commands[command.cmd](ctx, command)
            if ret == CMD_RESULT_FAILED:
                print("Error: %s" % err)
                continue
            if ret == CMD_RESULT_EXIT:
                break
        else:
            print("unsupported command line: `%s`" % line)
