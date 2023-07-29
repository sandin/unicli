from .executor import Executor, MemoryPerm
from unicorn import *
from capstone import *
from unicli.arch.arch import Arch
from unicli.context import Context, execute_command
from unicli.util.cmd_parser import Command


class UnicornExecutor(Executor):
    MIN_ADDR = 0x01000000

    def __init__(self, ctx: Context, arch: Arch):
        Executor.__init__(self)
        self.context = ctx  # type: Context
        if arch == Arch.ARCH_ARM64:
            self._mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)  # type: unicorn.Uc
            self.cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)  # type: Cs
        else:
            raise Exception("Unsupported arch")
        self.block_hooks = {}
        self.code_hooks = {}
        self._setup_hooks()

    def _setup_hooks(self):
        self._mu.hook_add(UC_HOOK_BLOCK, self.hook_block, self)
        self._mu.hook_add(UC_HOOK_CODE, self.hook_code, self)

    @staticmethod
    def hook_block(mu: unicorn.Uc, address: int, size: int, user_data: any):
        executor = user_data # type: UnicornExecutor
        ctx = executor.context  # type: Context
        rel_address = address - ctx.base_addr
        address_s = ctx.arch.format_address(rel_address)
        block_name = "blk_%x" % rel_address
        print("%s %s:" % (address_s, block_name))

        # user's hooks
        if rel_address in executor.block_hooks:
            subcommand = executor.block_hooks[rel_address]
            execute_command(ctx, subcommand)

    @staticmethod
    def hook_code(mu: unicorn.Uc, address: int, size: int, user_data: any):
        executor = user_data # type: UnicornExecutor
        ctx = executor.context  # type: Context
        cs = executor.cs  # type: Cs
        rel_address = address - ctx.base_addr

        code, err = executor.mem_read(address, size)
        if err is not None:
            print("Error: can not read memory at 0x%x" % address)
            return

        for i in cs.disasm(code, rel_address, 0):
            address_s = ctx.arch.format_address(i.address)
            print("{}              {:<10s} {:<s}".format(address_s, i.mnemonic, i.op_str))

        # user's hooks
        if rel_address in executor.code_hooks:
            subcommand = executor.code_hooks[rel_address]
            execute_command(ctx, subcommand)

    def mem_map(self, address: int, size: int, perms: MemoryPerm) -> (int, str):
        try:
            if address == 0:
                address = self._find_available_mem_range(size)
            self._mu.mem_map(address, size, self._map_perms(perms))
            return address, None
        except UcError as e:
            return 0, e

    def mem_write(self, address: int, data: bytes) -> (bool, str):
        try:
            self._mu.mem_write(address, data)
            return True, None
        except UcError as e:
            return False, e

    def mem_read(self, address: int, size: int) -> (bool, str):
        try:
            data = self._mu.mem_read(address, size)
            return data, None
        except UcError as e:
            return False, e

    def mem_protect(self, address: int, size: int, perms: MemoryPerm) -> (bool, str):
        try:
            self._mu.mem_protect(address, size, self._map_perms(perms))
            return True, None
        except UcError as e:
            return False, e

    def mem_regions(self) -> (list, str):
        memory_ranges = []
        for start, end, perms in self._mu.mem_regions():
            memory_ranges.append((start, end, self._unmap_perms(perms)))
        return memory_ranges, None

    @staticmethod
    def _map_perms(perms: MemoryPerm) -> int:
        return int(perms)

    @staticmethod
    def _unmap_perms(perms: int) -> MemoryPerm:
        return MemoryPerm(perms)

    def _find_available_mem_range(self, size: int) -> int:
        last_addr = self.MIN_ADDR
        for start, end, perms in self._mu.mem_regions():
            if start - last_addr > size:
                return last_addr
            last_addr = end
        return last_addr

    def reg_write(self, reg_num: int, value: int) -> (bool, str):
        try:
            self._mu.reg_write(reg_num, value)
            return True, None
        except UcError as e:
            return False, e

    def reg_read(self, reg_num: int) -> (int, str):
        try:
            value = self._mu.reg_read(reg_num)
            return value, None
        except UcError as e:
            return False, e

    def emu_start(self, start_addr: int, end_addr: int, timeout: int, count: int) -> (bool, str):
        try:
            self._mu.emu_start(start_addr, end_addr, timeout, count)
            return True, None
        except UcError as e:
            return False, e

    def emu_stop(self) -> (bool, str):
        try:
            self._mu.emu_stop()
            return True, None
        except UcError as e:
            return False, e

    def add_block_hook(self, address: int, subcommand: Command) -> (bool, str):
        self.block_hooks[address] = subcommand
        return True, None

    def del_block_hook(self, address: int) -> (bool, str):
        if address not in self.block_hooks:
            return False, "the address has not been hooked"
        del self.block_hooks[address]
        return True, None

    def add_code_hook(self, address: int, subcommand: Command) -> (bool, str):
        self.code_hooks[address] = subcommand
        return True, None

    def del_code_hook(self, address: int) -> (bool, str):
        if address not in self.code_hooks:
            return False, "the address has not been hooked"
        del self.code_hooks[address]
        return True, None
