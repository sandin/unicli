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

    def mem_read(self, address: int, size: int) -> (bytearray, str):
        """
        Read memory at address
        :param address: to read
        :param size: size
        :return: (bytearray, error)
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

    def emu_start(self, start_addr: int, end_addr: int, timeout: int, count: int, auto_map: bool = False) -> (bool, str):
        """
        Start emulation at the specified addr
        :param start_addr: address to start
        :param end_addr: address to end
        :param timeout: timeout
        :param count: count
        :param auto_map: auto map all unmapped memory
        :return: (success, error)
        """
        pass

    def emu_stop(self) -> (bool, str):
        """
        Stop the emulation
        :return: (success, error)
        """
        pass

    def add_block_hook(self, address: int, subcommand: any) -> (bool, str):
        """
        Add block hook
        :param address: target address
        :param subcommand: subcommand that need to be executed when the hook is hit
        :return: (success, error)
        """
        pass

    def del_block_hook(self, address: int) -> (bool, str):
        """
        Delete block hook
        :param address: target address
        :return: (success, error)
        """
        pass

    def add_code_hook(self, address: int, subcommand: any) -> (bool, str):
        """
        Add code hook
        :param address: target address
        :param subcommand: subcommand that need to be executed when the hook is hit
        :return: (success, error)
        """
        pass

    def del_code_hook(self, address: int) -> (bool, str):
        """
        Delete code hook
        :param address: target address
        :return: (success, error)
        """
        pass

    def disasm(self, address: int, size: int) -> (bool, str):
        """
        Disassemble code
        :param address: target address
        :param size: code size
        :return: (success, error)
        """
        pass

    def step_inst(self) -> (bool, str):
        """
        Step to the next inst
        :return: (success, error)
        """
        pass

    def step_block(self) -> (bool, str):
        """
        Step to the next block
        :return: (success, error)
        """
        pass

    def step_address(self, address: int) -> (bool, str):
        """
        Step to the address
        :param address: target address, stop before this address will not execute the inst at this address.
        :return: (success, error)
        """
        pass

    def ctx_save(self, name: str) -> (any, str):
        """
        Save the last context
        :param name: name
        :return: (context, error)
        """
        pass

    def ctx_restore(self, context: any) -> (bool, str):
        """
        Restore the context
        :param context: ctx to restore
        :return: (success, error)
        """
        pass
