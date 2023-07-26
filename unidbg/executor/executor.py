from enum import IntEnum


class MemoryPerm(IntEnum):
    PROT_NONE = 0
    PROT_READ = 1
    PROT_WRITE = 2
    PROT_EXEC = 4
    PROT_ALL = 7


class Arch(IntEnum):
    ARCH_NONE = 0
    ARCH_ARM = 1
    ARCH_ARM64 = 2
    ARCH_X86 = 3
    ARCH_X86_64 = 4


class Executor(object):
    """
    Interface Executor
    """

    def mem_map(self, address: int, size: int, perms: MemoryPerm):
        """
        Map memory at address
        :param address: start address
        :param size: size
        :param perms: memory permissions
        :return: (success, error)
        """
        pass

    def mem_write(self, address: int, data: bytes):
        """
        Write memory at address
        :param address: to writen
        :param data: bytes
        :return: (success, error)
        """
        pass

    def mem_protect(self, address: int, size: int, perms: MemoryPerm):
        """
        Protect memory at address
        :param address: to protect
        :param size: memory size
        :param perms: memory permissions
        :return: (success, error)
        """