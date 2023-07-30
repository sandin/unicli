from enum import IntEnum


class Arch(IntEnum):
    ARCH_UNKNOWN = 0
    ARCH_ARM = 1
    ARCH_ARM64 = 2
    ARCH_X86 = 3
    ARCH_X86_64 = 4


class ArchSpec(object):
    """
    Interface ArchSpec
    """

    def arch(self) -> Arch:
        """
        Get current arch
        """
        pass

    def address_size(self) -> int:
        """
        Get size of address type
        :return: size of bytes
        """
        pass

    def format_address(self, address: int) -> str:
        """
        Format address to string
        :param address: address
        :return: display address string
        """
        pass

    def format_number(self, val: int) -> str:
        """
        Format number
        :param val: value
        :return: display number string
        """
        pass

    def get_reg_num(self, reg_name: str, def_val: int) -> int:
        """
        Convert register name to register number(id)
        :param reg_name: register name
        :param def_val: default value
        :return: register number(id)
        """
        pass

    def get_reg_name(self, reg_number: int, def_val: str) -> str:
        """
        Convert register number(id) to register name
        :param reg_number: register name
        :param def_val: default value
        :return: register name
        """
        pass

    def get_instruction_pointer_reg_num(self) -> int:
        """
        Get Register name of instrument pointer(IP, PC)
        :return: register number(id)
        """
        pass

    def get_all_reg_num(self) -> list[int]:
        """
        Get all register numbers
        :return: id list
        """
        pass
