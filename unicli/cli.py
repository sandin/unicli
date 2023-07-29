import os.path
import sys
from prompt_toolkit import prompt

from .__init__ import __version__
from .command import CMD_RESULT_EXIT, CMD_RESULT_FAILED
from .command.cmd_hook import cmd_hook_block, cmd_hook_code
from .command.cmd_emu import cmd_emu_start, cmd_emu_stop
from .command.cmd_common import cmd_exit, cmd_help, cmd_script, cmd_set, cmd_unset, cmd_set_base
from .command.cmd_load import cmd_load, cmd_unload, cmd_load_list
from .command.cmd_mem import cmd_mem_list, cmd_mem_read, cmd_mem_map, cmd_mem_write
from .command.cmd_reg import cmd_reg_write, cmd_reg_read
from .context import Context, execute_command
from .util import register_cmd, parse_init_script
from .util.cmd_parser import parse_command

USAGE = """Usage: <command> <args..>
 common:
     s script <filename>                        Load a script file
    st set <name> <value>                       Set a local variable
    us unset <name>                             Unset a local variable
    sb set_base <abs_addr>                      Set base address for all relative addresses
     h help                                     Print help information
     e exit                                     Exit the program   
     
 load:
    lf load <filename>                          Load an ELF/PE/Mach-O file as a module
    lu unload <filename>                        Unload a module
    ll load_list                                List all loaded modules
     
 memory:
    mm mem_map <abs_addr> <size> [<port>]       Map a piece of virtual memory
    mw mem_write <rel_addr> <data>              Write data to memory at address
    mr mem_read <rel_addr> <size>               Read the memory at address
    ml mem_list                                 List all mapped memory range

 register:
    rw reg_write <reg_name> <value>             Write a register
    rr reg_read <reg_name>                      Read a register

 hook:
    hb hook_block <rel_addr> <subcommand>       Hook block at address
    hc hook_code <rel_addr> <subcommand>        Hook code at address

 emu:
    es emu_start <start_addr> <end_addr>        Start emulation
                 [<timeout> <count>]
    et emu_stop                                 Stop emulation        
"""

CMDS = {}
register_cmd(CMDS, "exit", ".exit", "exit()", "e", handler=cmd_exit)
register_cmd(CMDS, "help", "h", handler=cmd_help)
register_cmd(CMDS, "script", "s", handler=cmd_script)
register_cmd(CMDS, "set", "st", handler=cmd_set)
register_cmd(CMDS, "unset", "us", handler=cmd_unset)
register_cmd(CMDS, "set_base", "sb", handler=cmd_set_base)
register_cmd(CMDS, "load", "l", handler=cmd_load)
register_cmd(CMDS, "unload", "lu", handler=cmd_unload)
register_cmd(CMDS, "load_list", "ll", handler=cmd_load_list)
register_cmd(CMDS, "mem_list", "ml", handler=cmd_mem_list)
register_cmd(CMDS, "mem_read", "mr", handler=cmd_mem_read)
register_cmd(CMDS, "mem_write", "mr", handler=cmd_mem_write)
register_cmd(CMDS, "mem_map", "mm", handler=cmd_mem_map)
register_cmd(CMDS, "reg_write", "rw", handler=cmd_reg_write)
register_cmd(CMDS, "reg_read", "rr", handler=cmd_reg_read)
register_cmd(CMDS, "emu_start", "es", handler=cmd_emu_start)
register_cmd(CMDS, "emu_stop", "et", handler=cmd_emu_stop)
register_cmd(CMDS, "hook_block", "hb", handler=cmd_hook_block)
register_cmd(CMDS, "hook_code", "hc", handler=cmd_hook_code)


def main():
    print('UniCli %s' % __version__)
    print('Type "help" for more information.')

    ctx = Context(commands=CMDS, usage=USAGE)
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
        if command is None:
            continue
        ret, err = execute_command(ctx, command)
        if ret == CMD_RESULT_FAILED:
            print("Error: %s" % err)
            continue
        if ret == CMD_RESULT_EXIT:
            break
