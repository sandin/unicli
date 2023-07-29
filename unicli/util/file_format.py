from enum import IntEnum
import lief

from unicli.arch.arch import Arch


class FileFormat(IntEnum):
    UNKNOWN = 0
    ELF = 1
    PE = 2
    MACH_O = 3


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


def get_cpu_arch(filename: str) -> Arch:
    return Arch.ARCH_ARM64  # TODO: only support arm64 for now
