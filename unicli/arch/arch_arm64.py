from unicli.arch.arch import ArchSpec, Arch
from unicorn.arm64_const import *

g_general_regs_arm64 = [
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
    UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7,
    UC_ARM64_REG_X8, UC_ARM64_REG_X9, UC_ARM64_REG_X8, UC_ARM64_REG_X9,
    UC_ARM64_REG_X10, UC_ARM64_REG_X11, UC_ARM64_REG_X12, UC_ARM64_REG_X13,
    UC_ARM64_REG_X14, UC_ARM64_REG_X15, UC_ARM64_REG_X16, UC_ARM64_REG_X17,
    UC_ARM64_REG_X18, UC_ARM64_REG_X19, UC_ARM64_REG_X20, UC_ARM64_REG_X21,
    UC_ARM64_REG_X22, UC_ARM64_REG_X23, UC_ARM64_REG_X24, UC_ARM64_REG_X25,
    UC_ARM64_REG_X26, UC_ARM64_REG_X27, UC_ARM64_REG_X28, UC_ARM64_REG_X29,
    UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_PC
]

g_general_regs_arm64_id_to_name = {
    UC_ARM64_REG_X0: "X0", UC_ARM64_REG_X1: "X1", UC_ARM64_REG_X2: "X2", UC_ARM64_REG_X3: "X3",
    UC_ARM64_REG_X4: "X4", UC_ARM64_REG_X5: "X5", UC_ARM64_REG_X6: "X6", UC_ARM64_REG_X7: "X7",
    UC_ARM64_REG_X8: "X8", UC_ARM64_REG_X9: "X9", UC_ARM64_REG_X10: "X10", UC_ARM64_REG_X11: "X11",
    UC_ARM64_REG_X12: "X12", UC_ARM64_REG_X13: "X13", UC_ARM64_REG_X14: "X14", UC_ARM64_REG_X15: "X15",
    UC_ARM64_REG_X16: "X16", UC_ARM64_REG_X17: "X17", UC_ARM64_REG_X18: "X18", UC_ARM64_REG_X19: "X19",
    UC_ARM64_REG_X20: "X20", UC_ARM64_REG_X21: "X21", UC_ARM64_REG_X22: "X22", UC_ARM64_REG_X23: "X23",
    UC_ARM64_REG_X24: "X24", UC_ARM64_REG_X25: "X25", UC_ARM64_REG_X26: "X26", UC_ARM64_REG_X27: "X27",
    UC_ARM64_REG_X28: "X28", UC_ARM64_REG_X29: "FP", UC_ARM64_REG_X30: "LR", UC_ARM64_REG_SP: "SP",
    UC_ARM64_REG_PC: "PC",
    # TODO: w0~30
}


class ArchSpecArm64(ArchSpec):

    def arch(self) -> Arch:
        return Arch.ARCH_ARM64

    def address_size(self) -> int:
        return 8

    def format_address(self, address: int) -> str:
        return "0x{:0>10x}".format(address)

    def format_number(self, reg_val: int) -> str:
        return "0x{:0>16x}".format(reg_val)

    def get_reg_num(self, reg_name: str, def_val: int) -> int:
        reg_name = reg_name.upper()
        if reg_name == "FP":
            return UC_ARM64_REG_X29
        elif reg_name == "LR":
            return UC_ARM64_REG_X30
        tmp = "UC_ARM64_REG_" + reg_name
        try:
            reg_id = eval(tmp)
            return reg_id
        except:
            return def_val

    def get_reg_name(self, reg_number: int, def_val: str) -> str:
        if reg_number in g_general_regs_arm64_id_to_name:
            return g_general_regs_arm64_id_to_name[reg_number]
        return def_val

    def get_all_reg_num(self) -> (list[int], str):
        return g_general_regs_arm64

    def get_instruction_pointer_reg_num(self) -> int:
        return UC_ARM64_REG_PC

