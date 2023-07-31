import os.path
import sys
from prompt_toolkit import PromptSession

from .__init__ import __version__
from .command import CMD_RESULT_EXIT, CMD_RESULT_FAILED
from .command.cmd_ctx import cmd_ctx_save, cmd_ctx_restore, cmd_ctx_delete
from .command.cmd_hook import cmd_hook_block, cmd_hook_code
from .command.cmd_emu import cmd_emu_start, cmd_emu_stop
from .command.cmd_common import cmd_exit, cmd_help, cmd_script, cmd_set_var, cmd_unset_var, cmd_print_var, cmd_set_base, \
    cmd_disasm, cmd_run_expr
from .command.cmd_load import cmd_load, cmd_unload, cmd_load_list
from .command.cmd_mem import cmd_mem_list, cmd_mem_read, cmd_mem_map, cmd_mem_write
from .command.cmd_reg import cmd_reg_write, cmd_reg_read
from .command.cmd_step import cmd_step_inst, cmd_step_block, cmd_step_address
from .context import Context, execute_command
from .util import register_cmd, parse_init_script
from .util.cmd_parser import parse_command

USAGE = """Usage: <command> <args..> <flags..>
 common:
     f script <filename>                        Load a script file
     s set <name> <value>                       Set a local variable
     u unset <name>                             Unset a local variable
     p print <name>                             Print a local variable
     b set_base <addr>                          Set base address for all relative addresses
     d disasm <addr>                            Disassemble code at address
            [--base <address>]                  Base address of <addr>
     ! run <expr>                               Execute any python expression
     h help                                     Print help information
     e exit                                     Exit the program   
     
 load:
    lf load <filename>                          Load an ELF/PE/Mach-O file as a module
            [--format <format>]                 File format: elf, pe, macho, raw
            [--arch <arch>]                     Cpu arch: arm, arm64, x86, x86_64
            [--base <address>]                  Base address for load
            [--offset <offset>]                 Offset for raw file
    lu unload <filename>                        Unload a module
    ll load_list                                List all loaded modules
     
 memory:
    mm mem_map <abs_addr> <size> [<port>]       Map a piece of virtual memory
    mw mem_write <addr> <data>                  Write data to memory at address
                [--base <address>]              Base address of <addr>
    mr mem_read <addr> <size>                   Read the memory at address
                [--out <output_file>]           Dump memory to a file
                [--base <address>]              Base address of <addr>
    ml mem_list                                 List all mapped memory range

 register:
    rw reg_write <reg_name> <value>             Write a register
    rr reg_read <reg_name>                      Read a register

 hook:
    hb hook_block <addr> <subcommand>           Hook block at address
                  [--base <address>]            Base address of <addr>
    hc hook_code <addr> <subcommand>            Hook code at address
                  [--base <address>]            Base address of <addr>

 emu:
    es emu_start <start_addr> <end_addr>        Start emulation
                 [<timeout> <count>]
                 [--base <address>]             Base address of <start_addr> and <end_addr>
    et emu_stop                                 Stop emulation        
    
 context:
    cs ctx_save [<name>]                        Store the last context
    cr ctx_restore [<name>]                     Restore the context by name
    cd ctx_del <name>                           Delete the saved context by name
    
 step:
    si step_inst                                Step to the next inst
    sb step_block                               Step to the next block
    st step_to <rel_addr>                       Step to the address
"""

CMDS = {}
register_cmd(CMDS, "exit", ".exit", "exit()", "e", handler=cmd_exit)
register_cmd(CMDS, "help", "h", handler=cmd_help)
register_cmd(CMDS, "script", "f", handler=cmd_script)
register_cmd(CMDS, "set", "s", handler=cmd_set_var)
register_cmd(CMDS, "unset", "u", handler=cmd_unset_var)
register_cmd(CMDS, "print", "e", handler=cmd_print_var)
register_cmd(CMDS, "set_base", "b", handler=cmd_set_base)
register_cmd(CMDS, "disasm", "d", handler=cmd_disasm)
register_cmd(CMDS, "run", "!", handler=cmd_run_expr)
register_cmd(CMDS, "load", "lf", handler=cmd_load)
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
register_cmd(CMDS, "step_inst", "si", handler=cmd_step_inst)
register_cmd(CMDS, "step_block", "sb", handler=cmd_step_block)
register_cmd(CMDS, "step_to", "st", handler=cmd_step_address)
register_cmd(CMDS, "cs", "ctx_save", handler=cmd_ctx_save)
register_cmd(CMDS, "cr", "ctx_restore", handler=cmd_ctx_restore)
register_cmd(CMDS, "cd", "ctx_del", handler=cmd_ctx_delete)


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

    session = PromptSession()
    while True:
        if len(ctx.padding_cmds) > 0:
            line = ctx.padding_cmds[0]
            del ctx.padding_cmds[0]
            if line.strip() and not line.startswith("#"):
                print("%s %s" % (ctx.prompt, line))
        else:
            line = session.prompt("%s " % ctx.prompt)
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
