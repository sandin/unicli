import sys
import lief

from .loader import Loader
from ..executor.executor import Executor, MemoryPerm


class ElfLoader(Loader):
    """
    Loader for ELF file
    """

    def load(self, executor: Executor, filename: str) -> (bool, str):
        elf = lief.ELF.parse(filename)
        if elf.format != lief.EXE_FORMATS.ELF:
            return False, "Bad ELF format"

        # ReserveAddressSpace
        load_size = self._get_load_size(elf)
        base_addr, _ = executor.mem_map(0, load_size, MemoryPerm.PROT_NONE)

        # LoadSegments
        for segment in elf.segments:  # type: lief.ELF.Segment
            if segment.type != lief.ELF.SEGMENT_TYPES.LOAD:
                continue  # skip this segment

            print(segment)  # TODO: debug only

            # TODO: unicorn mem_map can map any specified address, so do we still need align memory to pagesize?
            seg_start = base_addr + segment.virtual_address
            seg_size = segment.virtual_address
            seg_end = seg_start + seg_size
            seg_bytes = segment.content.tobytes()
            seg_file_end = seg_start + len(seg_bytes)
            assert len(seg_bytes) <= segment.virtual_size  # memory size always >= file size

            port = self._pflags_to_prot(segment.flags)
            executor.mem_protect(seg_start, seg_size, port)
            executor.mem_write(seg_start, seg_bytes)
            print("Map memory from file [%d - %d] to virtual memory [%d - %d]"
                  % (segment.file_offset, len(seg_bytes), seg_start, seg_end))

            if seg_end > seg_file_end:
                zeros = bytes(seg_end - seg_file_end)
                executor.mem_write(seg_file_end, zeros)  # .bss
        return True, None

    @staticmethod
    def _pflags_to_prot(pflags: int) -> MemoryPerm:
        return MemoryPerm.PROT_ALL  # TODO

    @staticmethod
    def _get_load_size(elf: lief.ELF.Binary) -> int:
        min_vaddr = sys.maxsize
        max_vaddr = 0
        for segment in elf.segments:  # type: lief.ELF.Segment
            if segment.type == lief.ELF.SEGMENT_TYPES.LOAD:
                min_vaddr = min(min_vaddr, segment.virtual_address)
                max_vaddr = min(max_vaddr, segment.virtual_address + segment.virtual_size)
        return max_vaddr - min_vaddr

