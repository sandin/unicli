from .executor import Executor, MemoryPerm
from unicorn import *
from unicorn.arm64_const import *

from unidbg.arch.arch import Arch


class UnicornExecutor(Executor):
    MIN_ADDR = 0x01000000

    def __init__(self, arch: Arch):
        Executor.__init__(self)
        if arch == Arch.ARCH_ARM64:
            self._mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)  # type: unicorn.Uc
        else:
            raise Exception("Unsupported arch")

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
