from inspect import isfunction
from prompt_toolkit import print_formatted_text
from prompt_toolkit.formatted_text import FormattedText
from .executor import Executor, MemoryPerm
from unicorn import *
from capstone import *
from unicli.arch.arch import Arch
from unicli.context import Context, execute_command
from unicli.util.cmd_parser import Command
from unicli.tracker.tracker import Tracker, StopCondition, StopConditionType
from unicli.util.memory import page_start, page_align


class UnicornExecutor(Executor):
    MIN_ADDR = 0x00000000

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
        self.all_code_hooks = []
        self._setup_hooks()
        self._exit_enabled = False
        self._auto_map_unmapped: bool = False
        self.comments = {}
        self.block_comments = {}

    def _setup_hooks(self):
        self.mu.hook_add(UC_HOOK_BLOCK, self.hook_block, self)
        self.mu.hook_add(UC_HOOK_CODE, self.hook_code, self)
        self.mu.hook_add(UC_HOOK_MEM_UNMAPPED, self.hook_mem_unmapped, self)
        #self._mu.hook_add(UC_HOOK_INTR, self.hook_intr, self)

    @staticmethod
    def hook_mem_unmapped(self, type, address, size, value, user_data) -> bool:
        executor = user_data  # type: UnicornExecutor
        ctx = executor.context  # type: Context

        print("hook_mem_unmapped", type, hex(address), size, value)
        if executor._auto_map_unmapped:
            aligned_address = page_start(address)
            aligned_size = page_align(size)
            print("auto map memory, addr=0x%x size=%d" % (aligned_address, aligned_size))
            ret, err = executor.mem_map(aligned_address, aligned_size, MemoryPerm.PROT_ALL)
            if err is not None:
                return True  # continue the execution
        return False

    @staticmethod
    def hook_block(mu: unicorn.Uc, address: int, size: int, user_data: any):
        executor = user_data  # type: UnicornExecutor
        ctx = executor.context  # type: Context
        rel_address = address - ctx.base_addr  # TODO: the base address of the current module
        address_s = ctx.arch.format_address(rel_address, uppercase=True)
        block_name = "blk_%x" % rel_address
        if len(executor.block_comments) > 0 and address in executor.block_comments:
            for i, comment in enumerate(executor.block_comments[address]):
                if i > 0:
                    block_name += "\n"
                prefix = " " if i == 0 else ""
                block_name += "%s%s" % (prefix, comment)

        if not ctx.tracker.on_new_block(address, size, block_name):
            executor.emu_stop()
            return  # breakpoint

        if ctx.tracker.is_jump:
            print("----------------------------------------------------------------")
        print("%s %s:" % (address_s, block_name))

        # user's hooks
        if address in executor.block_hooks:
            hook = executor.block_hooks[address]
            if type(hook) == Command:
                execute_command(ctx, hook)
            elif isfunction(hook):
                hook(ctx, address, size, user_data)

    @staticmethod
    def get_comment_at_address(executor, address: int):
        if len(executor.comments) > 0 and address in executor.comments:
            comments = ""
            for i, comment in enumerate(executor.comments[address]):
                if i > 0:
                    comments += "\n"
                prefix = "                                                                     " if i > 0 else ""
                comments += "%s ; %s" % (prefix, comment)
            return comments
        return None

    @staticmethod
    def hook_code(mu: unicorn.Uc, address: int, size: int, user_data: any):
        executor = user_data  # type: UnicornExecutor
        ctx = executor.context  # type: Context
        comment = executor.get_comment_at_address(executor, address)

        # disassemble code
        asm, err = executor.disasm(address, size)

        if not ctx.tracker.on_new_inst(address, size, asm, comment):
            executor.emu_stop()
            return  # breakpoint

        # user's hooks
        # the callback of uc_hook is called before the instruction is executed
        # so if you want to post-instruction hook, just hook the next address
        for hook in executor.all_code_hooks:
            hook(mu, address, size, user_data)
        if address in executor.code_hooks:
            hook = executor.code_hooks[address]
            if type(hook) == Command:
                ret, err = execute_command(ctx, hook)
                if err is not None:
                    print("Error: can not execute subcommand: %s, %s" % (hook.cmd, err))
            elif isfunction(hook):
                hook(ctx, address, size, user_data)

        # print asm with comment
        if comment is not None:
            print(asm, end="")
            if ctx.colorful:
                print_formatted_text(FormattedText([('#ff0000', comment)]))
            else:
                print(comment)
        else:
            print(asm)

    @staticmethod
    def hook_intr(mu: unicorn.Uc, intr_num: int, user_data: any):
        print("hook_intr", intr_num)

    def disasm(self, address: int, size: int) -> (str, str):
        code, err = self.mem_read(address, size)
        if err is not None:
            return False, "can not read memory at 0x%x" % address

        rel_address = address - self.context.base_addr
        ret = ""
        i = 0
        for inst in self.cs.disasm(code, rel_address, 0):
            address_s = self.context.arch.format_address(inst.address, uppercase=True)
            if i > 0:
                ret += "\n"
            ret += "{}               {:<10s} {:<31s}".format(address_s, inst.mnemonic, inst.op_str)
            i += 1
        return ret, None

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

    def mem_read(self, address: int, size: int) -> (bytearray, str):
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

    def emu_start(self, start_addr: int, end_addr: int, timeout: int, count: int, auto_map: bool = False) -> (bool, str):
        try:
            if end_addr == 0 and self._exit_enabled is False:
                self.mu.ctl_exits_enabled(True)
                self._exit_enabled = True
                if self.context.tracker.get_stop_condition() is None:
                    self.context.tracker.set_stop_condition(StopCondition(StopConditionType.ON_NEXT_INST, 0))
            self._auto_map_unmapped = auto_map
            self.mu.emu_start(start_addr, end_addr, timeout, count)
            return True, None
        except UcError as e:
            return False, e

    def emu_stop(self) -> (bool, str):
        try:
            self.mu.emu_stop()
            self.mu.ctl_exits_enabled(False)
            self._exit_enabled = False
            self.context.tracker.set_stop_condition(None)
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
        if address == 0:  # hack
            self.all_code_hooks.append(subcommand)
        else:
            self.code_hooks[address] = subcommand
        return True, None

    def del_code_hook(self, address: int) -> (bool, str):
        if address not in self.code_hooks:
            return False, "the address has not been hooked"
        del self.code_hooks[address]
        return True, None

    def step_inst(self) -> (bool, str):
        self.context.tracker.set_stop_condition(StopCondition(StopConditionType.ON_NEXT_INST, 0))
        return self.emu_start(self.context.tracker.get_next_address(), 0, 0, 0)

    def step_block(self) -> (bool, str):
        self.context.tracker.set_stop_condition(StopCondition(StopConditionType.ON_NEXT_BLOCK, 0))
        return self.emu_start(self.context.tracker.get_next_address(), 0, 0, 0)

    def step_address(self, address: int) -> (bool, str):
        self.context.tracker.set_stop_condition(StopCondition(StopConditionType.ON_ADDRESS, address))
        return self.emu_start(self.context.tracker.get_next_address(), 0, 0, 0)

    def ctx_save(self, name: str) -> (any, str):
        try:
            ctx = self.mu.context_save()
            return ctx, None
        except UcError as e:
            return None, e

    def ctx_restore(self, context: any) -> (bool, str):
        try:
            self.mu.context_restore(context)
            return True, None
        except UcError as e:
            return False, e

    def add_comment(self, address: int, comment: str) -> (bool, str):
        if address not in self.comments:
            self.comments[address] = [comment]
        else:
            self.comments[address].append(comment)
        return True, None

    def add_block_comment(self, address: int, comment: str) -> (bool, str):
        if address not in self.block_comments:
            self.block_comments[address] = [comment]
        else:
            self.block_comments[address].append(comment)
        return True, None
