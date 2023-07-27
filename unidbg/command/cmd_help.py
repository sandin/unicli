from .__init__ import CMD_RESULT_OK
from unidbg.context import Context

USAGE = """Usage: <command> <args..>
command:
   load <filename>                      load an ELF/PE/Mach-O file
   mem_map <addr> <size> <port>         map a memory range
   mem_write <addr> <bytes>             write memory at address
   mem_read <addr> <size>               read memory at address
   mem_list                             list all mapped memory range
   reg_write <reg_name>                 write a register
   reg_read <reg_name>                  read a register
   hook_block <addr> <subcommand>       hook block at address
   hook_code <addr> <subcommand>        hook code at address
   emu_start <start_addr> <end_addr>    start new execution
   script <filename>                    load script file
   help                                 print help information
   exit                                 exit program   
"""


def cmd_help(context: Context, args: list[str]) -> int:
    print(USAGE)
    return CMD_RESULT_OK
