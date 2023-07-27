from .__init__ import CMD_RESULT_OK
from unidbg.context import Context

USAGE = """Usage: <command> <args..>
command:
   load <filename>                          load an ELF/PE/Mach-O file
   mem_map <abs_addr> <size> [<port>]       map a piece of virtual memory
   mem_write <rel_addr> <data>              write data to memory at address
   mem_read <rel_addr> <size>               read the memory at address
   mem_list                                 list all mapped memory range
   reg_write <reg_name> <value>             write a register
   reg_read <reg_name>                      read a register
   hook_block <rel_addr> <subcommand>       hook block at address
   hook_code <rel_addr> <subcommand>        hook code at address
   emu_start <start_addr> <end_addr>        start new execution
   set_base_addr <abs_addr>                 set base address for all relative addresses
   script <filename>                        load script file
   help                                     print help information
   exit                                     exit program   
"""


def cmd_help(context: Context, args: list[str]) -> int:
    print(USAGE)
    return CMD_RESULT_OK
