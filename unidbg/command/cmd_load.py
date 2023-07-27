import os.path

from .__init__ import CMD_RESULT_FAILED, CMD_RESULT_OK
from unidbg.common.context import Context, State
from unidbg.executor.executor import Arch
from unidbg.util.args_parser import parse_arg
from unidbg.loader.elf_loader import ElfLoader
from unidbg.util.file_format import get_file_format, FileFormat
from unidbg.executor.unicorn_executor import UnicornExecutor


def cmd_load(context: Context, line: str) -> int:
    filename, _ = parse_arg(line)
    if filename is None:
        print("Error: missing arg <filename>")
        return CMD_RESULT_FAILED

    if not os.path.exists(filename):
        print("Error: `%s` file is not exists!" % filename)
        return CMD_RESULT_FAILED

    file_format = get_file_format(filename)
    if file_format == FileFormat.ELF:
        context.loader = ElfLoader()
    # TODO: if file_format == FileFormat.PE:
    #   context.loader = PELoader()
    # TODO: if file_format == FileFormat.MACH_O:
    #   context.loader = MachOLoader()
    else:
        print("Error: unsupported file format %s" % filename)
        return CMD_RESULT_FAILED

    # Create Unicorn Executor
    arch = Arch.ARCH_ARM64  # TODO:
    context.executor = UnicornExecutor(arch)

    # Load ELF/PE/Mach-O file into virtual memory
    loaded_info, err = context.loader.load(context.executor, filename)
    if err is not None:
        print("Error: can not load %s, %s" % (filename, err))
        return CMD_RESULT_FAILED
    context.base_addr = loaded_info.load_bias
    context.state = State.LOADED
    return CMD_RESULT_OK
