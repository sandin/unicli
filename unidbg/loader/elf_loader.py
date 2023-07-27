import os.path
import sys
import lief

from .loader import Loader, LoadedInfo
from unidbg.executor.executor import Executor, MemoryPerm
from unidbg.util.memory import page_start, page_end, page_offset, PAGE_SIZE


class ElfLoader(Loader):
    """
    Loader for ELF file
    """

    def load(self, executor: Executor, filename: str) -> (LoadedInfo, str):
        loaded_info = LoadedInfo()
        elf = lief.ELF.parse(filename)
        if elf.format != lief.EXE_FORMATS.ELF:
            return None, "Bad ELF format"

        # ReserveAddressSpace
        total_file_size = os.path.getsize(filename)
        if total_file_size <= 0:
            return None, "Invalid file size"

        min_vaddr, max_vaddr = self._get_load_range(elf)
        loaded_info.load_size = max_vaddr - min_vaddr
        if loaded_info.load_size == 0:
            return None, "Can not found loadable segments"

        addr = min_vaddr
        start, err = executor.mem_map(0, loaded_info.load_size, MemoryPerm.PROT_ALL)
        if err is not None:
            return None, "Can not map memory for size 0x%x, %s" % (loaded_info.load_size, err)
        print("Map memory reserve address space [0x%x - 0x%x]" % (start, start + loaded_info.load_size))
        loaded_info.load_start = start
        loaded_info.load_bias = start - addr

        # LoadSegments
        with open(filename, "rb") as f:
            for segment in elf.segments:  # type: lief.ELF.Segment
                if segment.type != lief.ELF.SEGMENT_TYPES.LOAD:
                    continue  # skip this segment
                #print(segment)

                seg_start = segment.virtual_address + loaded_info.load_bias
                seg_end = seg_start + segment.virtual_size  # memory size(always >= file size)
                seg_file_size = segment.content.nbytes
                seg_file_end = seg_start + seg_file_size  # file size

                seg_page_start = page_start(seg_start)
                seg_page_end = page_start(seg_end)

                # File offset
                file_start = segment.file_offset
                file_end = file_start + seg_file_size

                file_page_start = page_start(file_start)
                file_length = file_end - file_page_start

                if file_end > total_file_size:
                    return None, "Invalid segment file end=%d, file size=%d" % (file_end, total_file_size)

                if file_length != 0:
                    file_bytes = self._read_file_content(f, file_page_start, file_length)
                    executor.mem_write(seg_page_start, file_bytes)
                    if err is not None:
                        return None, "Can not write memory [0x%x - 0x%x], %s" % (seg_page_start, seg_page_start + file_length, err)
                    print("Map memory from file [0x%x - 0x%x] to virtual memory [0x%x - 0x%x]"
                          % (file_page_start, file_page_start + file_length, seg_page_start, seg_page_start + file_length))

                if segment.flags & lief.ELF.SEGMENT_FLAGS.W != 0 and page_offset(seg_file_end) > 0:
                    zeros = bytes(PAGE_SIZE - page_offset(seg_file_end))
                    ret, err = executor.mem_write(seg_file_end, zeros)  # .bss
                    if err is not None:
                        return None, "Can not write memory [0x%x - 0x%x], %s" % (seg_file_end, seg_file_end + len(zeros), err)
                    print("Fill memory with zeros to align with page size [0x%x - 0x%x]" % (seg_file_end, seg_file_end + len(zeros)))

                seg_file_end = page_end(seg_file_end)
                if seg_page_end > seg_file_end:  # .bss
                    zeros = bytes(seg_page_end - seg_file_end)
                    ret, err = executor.mem_write(seg_file_end, zeros)
                    if err is not None:
                        return None, "Can not write memory [0x%x - 0x%x], %s" % (seg_file_end, seg_file_end + len(zeros), err)
                    print("Fill memory with zeros for .bss section [0x%x - 0x%x]" % (seg_file_end, seg_file_end + len(zeros)))
        return loaded_info, None

    @staticmethod
    def _read_file_content(f, offset: int, size: int) -> bytes:
        f.seek(offset)
        return f.read(size)

    @staticmethod
    def _get_load_range(elf: lief.ELF.Binary) -> (int, int):
        min_vaddr = sys.maxsize
        max_vaddr = 0
        found_pt_load = False
        for segment in elf.segments:  # type: lief.ELF.Segment
            if segment.type == lief.ELF.SEGMENT_TYPES.LOAD:
                min_vaddr = min(min_vaddr, segment.virtual_address)
                max_vaddr = max(max_vaddr, segment.virtual_address + segment.virtual_size)
                found_pt_load = True
        if not found_pt_load:
            min_vaddr = 0

        min_vaddr = page_start(min_vaddr)
        max_vaddr = page_end(max_vaddr)
        return min_vaddr, max_vaddr
