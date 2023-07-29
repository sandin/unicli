from enum import IntEnum
import lief

from unicli.arch.arch import Arch


class FileFormat(IntEnum):
    UNKNOWN = 0
    RAW = 1
    ELF = 2
    PE = 3
    MACH_O = 4


def get_file_format(filename: str) -> FileFormat:
    """
    Get file format
    :param filename: filepath
    :return: FileFormat
    """
    if lief.is_elf(filename):
        return FileFormat.ELF
    if lief.is_pe(filename):
        return FileFormat.PE
    if lief.is_macho(filename):
        return FileFormat.MACH_O
    return FileFormat.UNKNOWN


def str_to_file_format(txt: str) -> FileFormat:
    """
    Convert string to file format
    """
    if txt == "raw":
        return FileFormat.RAW
    if txt == "elf":
        return FileFormat.ELF
    if txt == "pe":
        return FileFormat.PE
    if txt == "macho":
        return FileFormat.MACH_O
    return FileFormat.UNKNOWN


def get_cpu_arch(filename: str) -> Arch:
    return Arch.ARCH_ARM64  # TODO: only support arm64 for now


def str_to_cpu_arch(txt: str) -> Arch:
    if txt == "arm":
        return Arch.ARCH_ARM
    if txt == "arm64":
        return Arch.ARCH_ARM64
    if txt == "x86":
        return Arch.ARCH_X86
    if txt == "x86_64" or txt == "x86-64":
        return Arch.ARCH_X86_64
    return Arch.ARCH_UNKNOWN


def cpu_arch_to_str(arch: Arch) -> str:
    if arch == Arch.ARCH_ARM:
        return "arm"
    if arch == Arch.ARCH_ARM64:
        return "arm64"
    if arch == Arch.ARCH_X86:
        return "x86"
    if arch == Arch.ARCH_X86_64:
        return "x86_64"
    return "unknown"
