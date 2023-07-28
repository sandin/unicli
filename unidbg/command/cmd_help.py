from .__init__ import CMD_RESULT_OK
from unidbg.context import Context
from unidbg.util.cmd_parser import Command

USAGE = """Usage: <command> <args..>
 common:
     l load <filename>                          Load an ELF/PE/Mach-O file
     s script <filename>                        Load a script file
    st set <name> <value>                       Set a local variable
    us unset <name>                             Unset a local variable
    sb set_base <abs_addr>                      Set base address for all relative addresses
     h help                                     Print help information
     e exit                                     Exit the program   
   
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


def cmd_help(ctx: Context, cmd: Command) -> (int, str):
    print(USAGE)
    return CMD_RESULT_OK, None
