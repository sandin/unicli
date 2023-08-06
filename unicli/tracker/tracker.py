from dataclasses import dataclass, field
from typing import Optional
from enum import IntEnum
from unicli.tracker.basic_block import BasicBlock, Instruction


class StopConditionType(IntEnum):
    ON_NEXT_INST = 0
    ON_NEXT_BLOCK = 1
    ON_ADDRESS = 2


@dataclass()
class StopCondition:
    type: StopConditionType = StopConditionType.ON_NEXT_INST
    address: int = 0


class Tracker(object):

    def __init__(self):
        self._start_addr = 0  # type: int
        self._last_addr = 0  # type: int
        self._current_addr = 0  # type: int
        self._next_addr = 0  # type: int
        self._blocks = {}  # type: dict[int, BasicBlock]
        self._head_block = None  # type: Optional[BasicBlock]
        self._tail_block = None   # type: Optional[BasicBlock]
        self._stop_condition = None  # type: Optional[StopCondition]
        self._stop_inst_count = 0  # type: int
        self._stop_block_count = 0  # type: int
        self.is_jump = False  # type: bool

    def find_block(self, start_addr):
        return Tracker._find_block(self._head_block, start_addr)

    @staticmethod
    def _find_block(block, start_addr):
        if block is None:
            return None
        if block.start_addr == start_addr:
            return block
        for succ in block.successors:
            found = Tracker._find_block(succ, start_addr)
            if found:
                return found
        return None

    def on_new_block(self, address: int, size: int, name: str) -> bool:
        self._current_addr = address
        self.is_jump = self._next_addr != 0 and self._current_addr != self._next_addr

        if self._should_stop_on_block(address, size):
            return False

        if address not in self._blocks:
            blk = BasicBlock(start_addr=address, name=name)
        else:
            blk = self._blocks[address]
        if self._head_block is None:
            self._head_block = blk
        if self._tail_block is None:
            self._tail_block = blk
        else:
            blk.predecessors.add(self._tail_block)
            self._tail_block.successors.add(blk)
            self._tail_block = blk
        return True  # continue

    def on_new_inst(self, address: int, size: int, inst: str, comment: str) -> bool:
        if self._start_addr == 0:
            self._start_addr = address
        self._last_addr = self._current_addr
        self._current_addr = address
        self._next_addr = address + size

        if self._should_stop_on_inst(address, size):
            return False

        if self._tail_block is not None:
            self._tail_block.instructions.append(Instruction(address, size, inst, comment))
        return True  # continue

    def _should_stop_on_block(self, address, size):
        if self._stop_condition is not None and self._stop_condition.type == StopConditionType.ON_NEXT_BLOCK:
            if self._stop_block_count > 0:
                self._stop_block_count = 0
                return True  # It's the beginning of a new block
            self._stop_block_count += 1
        return False

    def _should_stop_on_inst(self, address, size):
        if self._stop_condition is not None:
            if self._stop_condition.type == StopConditionType.ON_NEXT_INST:
                if self._stop_inst_count > 0:
                    self._stop_inst_count = 0
                    return True
                self._stop_inst_count += 1
            elif self._stop_condition.type == StopConditionType.ON_ADDRESS:
                if address == self._stop_condition.address:
                    return True
        return False

    def set_stop_condition(self, stop_condition: Optional[StopCondition]):
        self._stop_condition = stop_condition
        self._stop_inst_count = 0
        self._stop_block_count = 0

    def get_stop_condition(self):
        return self._stop_condition

    def get_next_address(self):
        return self._current_addr
