from typing import Optional
from .__init__ import CMD_RESULT_FAILED, CMD_RESULT_OK
from unidbg.context import Context, State
from unidbg.arch.arch import Arch
from unidbg.loader.elf_loader import ElfLoader
from unidbg.util.file_format import get_file_format, FileFormat, get_cpu_arch
from unidbg.util.cmd_parser import Command
from unidbg.executor.unicorn_executor import UnicornExecutor
from unidbg.arch.arch_arm64 import ArchSpecArm64
from unidbg.loader.loader import LoadedInfo


def _set_current_loaded_info(ctx: Context, loaded_info: Optional[LoadedInfo]):
    if loaded_info is not None:
        ctx.base_addr = loaded_info.load_bias
        ctx.state = State.LOADED
    else:
        ctx.base_addr = 0
        ctx.state = State.INVALID


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
    ctx.loaded.append(loaded_info)
    _set_current_loaded_info(ctx, loaded_info)
    print("Successfully loaded module: %s" % filename)
    return CMD_RESULT_OK, None


def cmd_unload(ctx: Context, cmd: Command) -> (int, str):
    filename, err = cmd.get_str_arg("filename", 0, None)
    if err is not None:
        return CMD_RESULT_FAILED, err

    if filename == "all":
        ctx.loaded.clear()
        _set_current_loaded_info(ctx, None)
        print("Successfully unloaded all modules")
        return CMD_RESULT_OK, None

    loaded_info = None
    for item in ctx.loaded:
        if item.filename == filename:
            loaded_info = item

    if loaded_info is None:
        return CMD_RESULT_FAILED, "%s m has not been loaded" % filename
    ctx.loaded.remove(loaded_info)
    loaded_info = ctx.loaded[0] if len(ctx.loaded) > 0 else None
    _set_current_loaded_info(ctx, loaded_info)
    print("Successfully unloaded module: %s" % filename)
    return CMD_RESULT_OK, None


def cmd_load_list(ctx: Context, cmd: Command) -> (int, str):
    if len(ctx.loaded) > 0:
        for item in ctx.loaded:  # type: LoadedInfo
            start_addr_s = ctx.arch.format_address(item.load_bias)
            end_addr_s = ctx.arch.format_address(item.load_bias + item.load_size)
            print("%s - %s %s" % (start_addr_s, end_addr_s, item.filename))
    else:
        print("Nothing loaded yet")
    return CMD_RESULT_OK, None
