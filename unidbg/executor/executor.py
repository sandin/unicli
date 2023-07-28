from enum import IntEnum


class MemoryPerm(IntEnum):
    PROT_NONE = 0
    PROT_READ = 1
    PROT_WRITE = 2
    PROT_EXEC = 4
    PROT_ALL = 7


class Executor(object):
    """
    Interface Executor
    """

    def mem_map(self, address: int, size: int, perms: MemoryPerm) -> (int, str):
        """
        Map memory at address
        :param address: start address
        :param size: size
        :param perms: memory permissions
        :return: (success, error)
        """
        pass

    def mem_write(self, address: int, data: bytes) -> (bool, str):
        """
        Write memory at address
        :param address: to writen
        :param data: bytes
        :return: (success, error)
        """
        pass

    def mem_read(self, address: int, size: int) -> (bool, str):
        """
        Read memory at address
        :param address: to read
        :param size: size
        :return: (success, error)
        """
        pass

    def mem_protect(self, address: int, size: int, perms: MemoryPerm) -> (bool, str):
        """
        Protect memory at address
        :param address: to protect
        :param size: memory size
        :param perms: memory permissions
        :return: (success, error)
        """
        pass

    def mem_regions(self) -> (list, str):
        """
        List all mapped memory regions
        :return: (memory list, error)
        """
        pass

    def reg_write(self, reg_num: int, value: int) -> (bool, str):
        """
        Write a value to the specified register
        :param reg_num: target reg
        :param value: value
        :return: (success, error)
        """
        pass

    def reg_read(self, reg_num: int) -> (int, str):
        """
        Read the value of the specified register
        :param reg_num: target reg
        :return: (value, error)
        """
        pass

    def emu_start(self, start_addr: int, end_addr: int, timeout: int, count: int) -> (bool, str):
        """
        Start emulation at the specified addr
        :param start_addr: address to start
        :param end_addr: address to end
        :param timeout: timeout
        :param count: count
        :return: (success, error)
        """
        pass

    def emu_stop(self) -> (bool, str):
        """
        Stop the emulation
        :return: (success, error)
        """
        pass
