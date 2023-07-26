import os.path

from .__init__ import CMD_RESULT_FAILED, CMD_RESULT_OK
from ..executor.executor import Arch
from ..util.args_parser import parse_arg
from ..loader.elf_loader import ElfLoader
from ..util.file_format import get_file_format, FileFormat
from ..executor.unicorn_executor import UnicornExecutor


def cmd_load(context, line):
    filename, _ = parse_arg(line)
    if filename is None:
        print("Error: missing arg <filename>")
        return CMD_RESULT_FAILED

    if not os.path.exists(filename):
        print("Error: `%s` file is not exists!" % filename)
        return CMD_RESULT_FAILED

    file_format = get_file_format(filename)
    if file_format == FileFormat.ELF:
        loader = ElfLoader()
    # TODO: if file_format == FileFormat.PE:
    #   loader = PELoader()
    # TODO: if file_format == FileFormat.MACH_O:
    #   loader = MachOLoader()
    else:
        print("Error: unsupported file format %s" % filename)
        return CMD_RESULT_FAILED

    # Create Unicorn Executor
    arch = Arch.ARCH_ARM64  # TODO:
    context['executor'] = UnicornExecutor(arch)

    # Load ELF/PE/Mach-O file into virtual memory
    ret, err = loader.load(context['executor'], filename)
    if not ret:
        print("Error: can not load %s, %s" % (filename, err))
        return CMD_RESULT_FAILED

    return CMD_RESULT_OK
