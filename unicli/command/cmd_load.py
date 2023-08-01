from typing import Optional
from .__init__ import CMD_RESULT_FAILED, CMD_RESULT_OK
from unicli.context import Context, State
from unicli.arch.arch import Arch
from unicli.loader.elf_loader import ElfLoader
from unicli.util.file_format import get_file_format, FileFormat, get_cpu_arch, str_to_file_format, str_to_cpu_arch, \
    cpu_arch_to_str
from unicli.util.cmd_parser import Command
from unicli.executor.unicorn_executor import UnicornExecutor
from unicli.arch.arch_arm64 import ArchSpecArm64
from unicli.loader.loader import LoadedInfo
from ..loader.raw_loader import RawLoader


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

    base_addr = cmd.get_int_flag(['b', 'base'], 1, 0)
    input_format = cmd.get_str_flag(['f', 'format'], 1, None)
    input_arch = cmd.get_str_flag(['a', 'arch'], 1, None)
    offset = cmd.get_int_flag(['o', 'offset'], 1, 0)

    # check file format
    if input_format is not None:
        file_format = str_to_file_format(input_format)
    else:
        file_format = get_file_format(filename)

    # Create Loader
    if file_format not in ctx.loader:
        if file_format == FileFormat.RAW:
            if input_arch is None:
                return CMD_RESULT_FAILED, "missing <arch> flag"
            ctx.loader[file_format] = RawLoader()
        elif file_format == FileFormat.ELF:
            ctx.loader[file_format] = ElfLoader()
        # TODO: if file_format == FileFormat.PE:
        #   ctx.loader[file_format] = PELoader()
        # TODO: if file_format == FileFormat.MACH_O:
        #   ctx.loader[file_format] = MachOLoader()
        else:
            return CMD_RESULT_FAILED, "unsupported file format %s" % filename

    # Arch Spec helper
    if input_arch is not None:
        arch = str_to_cpu_arch(input_arch)
    else:
        arch = get_cpu_arch(filename)

    if ctx.arch is None:
        if arch == Arch.ARCH_ARM64:
            ctx.arch = ArchSpecArm64()
        else:
            return CMD_RESULT_FAILED, "unsupported arch %d" % arch
    else:
        if ctx.arch.arch() != arch:
            return CMD_RESULT_FAILED, "can't load files from %s arch file, current arch is %s" \
                                  % (cpu_arch_to_str(arch), cpu_arch_to_str(ctx.arch.arch()))

    # Create Executor
    if ctx.executor is None:
        ctx.executor = UnicornExecutor(ctx, arch)

    # Load ELF/PE/Mach-O file into virtual memory
    loaded_info, err = ctx.loader[file_format].load(ctx.executor, filename, base_addr, offset)
    if err is not None:
        return CMD_RESULT_FAILED, "can not load %s, %s" % (filename, err)
    ctx.loaded.append(loaded_info)
    _set_current_loaded_info(ctx, loaded_info)
    print("Successfully loaded module: %s" % filename)
    ctx.last_result = loaded_info
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
    ctx.last_result = True
    return CMD_RESULT_OK, None


def cmd_load_list(ctx: Context, cmd: Command) -> (int, str):
    if len(ctx.loaded) > 0:
        for item in ctx.loaded:  # type: LoadedInfo
            start_addr_s = ctx.arch.format_address(item.load_bias)
            end_addr_s = ctx.arch.format_address(item.load_bias + item.load_size)
            print("%s - %s %s" % (start_addr_s, end_addr_s, item.filename))
    else:
        print("Nothing loaded yet")
    ctx.last_result = list(ctx.loaded)  # clone
    return CMD_RESULT_OK, None
