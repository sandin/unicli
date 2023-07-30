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
            self.mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)  # type: unicorn.Uc
            self.cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)  # type: Cs
        else:
            raise Exception("Unsupported arch")
        self.block_hooks = {}
        self.code_hooks = {}
        self._setup_hooks()
        self._exit_enabled = False

    def _setup_hooks(self):
        self.mu.hook_add(UC_HOOK_BLOCK, self.hook_block, self)
        self.mu.hook_add(UC_HOOK_CODE, self.hook_code, self)
        self.mu.hook_add(UC_HOOK_MEM_UNMAPPED, self.hook_mem_unmapped, self)
        #self._mu.hook_add(UC_HOOK_INTR, self.hook_intr, self)

    @staticmethod
    def hook_mem_unmapped(self, type, address, size, value, data) -> bool:
        print("hook_mem_unmapped", type, hex(address), size, value)
        return False

    @staticmethod
    def hook_block(mu: unicorn.Uc, address: int, size: int, user_data: any):
        executor = user_data  # type: UnicornExecutor
        ctx = executor.context  # type: Context
        rel_address = address - ctx.base_addr
        address_s = ctx.arch.format_address(rel_address)
        block_name = "blk_%x" % rel_address
        print("%s %s:" % (address_s, block_name))

        # user's hooks
        if rel_address in executor.block_hooks:
            for subcommand in executor.block_hooks[rel_address]:
                execute_command(ctx, subcommand)

    @staticmethod
    def hook_code(mu: unicorn.Uc, address: int, size: int, user_data: any):
        executor = user_data # type: UnicornExecutor
        ctx = executor.context  # type: Context

        # user's hooks
        # the callback of uc_hook is called before the instruction is executed
        # so if you want to post-instruction hook, just hook the next address
        rel_address = address - ctx.base_addr
        if rel_address in executor.code_hooks:
            subcommand = executor.code_hooks[rel_address]
            execute_command(ctx, subcommand)

        # disassemble code
        executor.disasm(address, size)

    @staticmethod
    def hook_intr(mu: unicorn.Uc, intr_num: int, user_data: any):
        print("hook_intr", intr_num)

    def disasm(self, address: int, size: int) -> (bool, str):
        code, err = self.mem_read(address, size)
        if err is not None:
            return False, "can not read memory at 0x%x" % address

        rel_address = address - self.context.base_addr
        for i in self.cs.disasm(code, rel_address, 0):
            address_s = self.context.arch.format_address(i.address)
            print("{}              {:<10s} {:<s}".format(address_s, i.mnemonic, i.op_str))
        return True, None

    def mem_map(self, address: int, size: int, perms: MemoryPerm) -> (int, str):
        try:
            if address == 0:
                address = self._find_available_mem_range(size)
            self.mu.mem_map(address, size, self._map_perms(perms))
            return address, None
        except UcError as e:
            return 0, e

    def mem_write(self, address: int, data: bytes) -> (bool, str):
        try:
            self.mu.mem_write(address, data)
            return True, None
        except UcError as e:
            return False, e

    def mem_read(self, address: int, size: int) -> (bool, str):
        try:
            data = self.mu.mem_read(address, size)
            return data, None
        except UcError as e:
            return False, e

    def mem_protect(self, address: int, size: int, perms: MemoryPerm) -> (bool, str):
        try:
            self.mu.mem_protect(address, size, self._map_perms(perms))
            return True, None
        except UcError as e:
            return False, e

    def mem_regions(self) -> (list, str):
        memory_ranges = []
        for start, end, perms in self.mu.mem_regions():
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
        for start, end, perms in self.mu.mem_regions():
            if start - last_addr > size:
                return last_addr
            last_addr = end
        return last_addr

    def reg_write(self, reg_num: int, value: int) -> (bool, str):
        try:
            self.mu.reg_write(reg_num, value)
            return True, None
        except UcError as e:
            return False, e

    def reg_read(self, reg_num: int) -> (int, str):
        try:
            value = self.mu.reg_read(reg_num)
            return value, None
        except UcError as e:
            return False, e

    def emu_start(self, start_addr: int, end_addr: int, timeout: int, count: int) -> (bool, str):
        try:
            if end_addr == 0 and self._exit_enabled is False:
                self.mu.ctl_exits_enabled(True)
                self._exit_enabled = True
            self.mu.emu_start(start_addr, end_addr, timeout, count)
            return True, None
        except UcError as e:
            return False, e

    def emu_stop(self) -> (bool, str):
        try:
            self.mu.emu_stop()
            self.mu.ctl_exits_enabled(False)
            self._exit_enabled = False
            return True, None
        except UcError as e:
            return False, e

    def add_block_hook(self, address: int, subcommand: Command) -> (bool, str):
        if address not in self.block_hooks:
            self.block_hooks[address] = []
        self.block_hooks[address].append(subcommand)
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
