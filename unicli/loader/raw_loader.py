import os.path
import sys
import lief

from .loader import Loader, LoadedInfo
from unicli.executor.executor import Executor, MemoryPerm
from unicli.util.memory import page_start, page_end, page_offset, PAGE_SIZE, page_align
from ..util import read_file_content


class RawLoader(Loader):
    """
    Loader for Raw file
    """

    def load(self, executor: Executor, filename: str, base_addr: int = 0, offset: int = 0) -> (LoadedInfo, str):
        loaded_info = LoadedInfo(filename=filename)

        total_file_size = os.path.getsize(filename)
        if total_file_size == 0:
            return None, "Invalid file size"

        min_vaddr, max_vaddr = self._get_load_range(offset, total_file_size)
        loaded_info.load_size = max_vaddr - min_vaddr
        if loaded_info.load_size == 0:
            return None, "Can not found loadable segments"

        start, err = executor.mem_map(base_addr + min_vaddr, loaded_info.load_size, MemoryPerm.PROT_ALL)
        if err is not None:
            return None, "Can not map memory at address 0x%x, size 0x%x, %s" % (base_addr + min_vaddr, loaded_info.load_size, err)
        print("Map memory reserve address space [0x%x - 0x%x]" % (start, start + loaded_info.load_size))
        loaded_info.load_start = start
        loaded_info.load_bias = start - min_vaddr

        # LoadSegments
        with open(filename, "rb") as f:
            file_bytes = read_file_content(f, 0, total_file_size)
            seg_start = base_addr + offset
            executor.mem_write(seg_start, file_bytes)
            if err is not None:
                return None, "Can not write memory [0x%x - 0x%x], %s" % (seg_start, seg_start + total_file_size, err)
            print("Map memory from file [0x%x - 0x%x] to virtual memory [0x%x - 0x%x]"
                  % (0, total_file_size, seg_start, seg_start + total_file_size))
        return loaded_info, None

    @staticmethod
    def _get_load_range(offset: int, file_size: int) -> (int, int):
        min_vaddr = page_start(offset)
        max_vaddr = page_end(offset + file_size)
        return min_vaddr, max_vaddr
