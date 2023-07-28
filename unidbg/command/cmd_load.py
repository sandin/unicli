import os.path

from .__init__ import CMD_RESULT_FAILED, CMD_RESULT_OK
from unidbg.context import Context, State
from unidbg.arch.arch import Arch
from unidbg.loader.elf_loader import ElfLoader
from unidbg.util.file_format import get_file_format, FileFormat, get_cpu_arch
from unidbg.util.cmd_parser import Command
from unidbg.executor.unicorn_executor import UnicornExecutor
from unidbg.arch.arch_arm64 import ArchSpecArm64


def cmd_load(ctx: Context, cmd: Command) -> (int, str):
    filename, err = cmd.get_file_arg("filename", 0, None)
    if err is not None:
        return CMD_RESULT_FAILED, err

    # Create Loader
    file_format = get_file_format(filename)
    if file_format == FileFormat.ELF:
        ctx.loader = ElfLoader()
    # TODO: if file_format == FileFormat.PE:
    #   context.loader = PELoader()
    # TODO: if file_format == FileFormat.MACH_O:
    #   context.loader = MachOLoader()
    else:
        return CMD_RESULT_FAILED, "unsupported file format %s" % filename

    # Arch Spec helper
    arch = get_cpu_arch(filename)
    if arch == Arch.ARCH_ARM64:
        ctx.arch = ArchSpecArm64()
    else:
        return CMD_RESULT_FAILED, "unsupported arch %d" % arch

    # Create Executor
    ctx.executor = UnicornExecutor(ctx, arch)

    # Load ELF/PE/Mach-O file into virtual memory
    loaded_info, err = ctx.loader.load(ctx.executor, filename)
    if err is not None:
        return CMD_RESULT_FAILED, "can not load %s, %s" % (filename, err)
    ctx.base_addr = loaded_info.load_bias
    ctx.state = State.LOADED
    return CMD_RESULT_OK, None
