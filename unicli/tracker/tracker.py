from dataclasses import dataclass, field
from typing import Optional
from enum import IntEnum


@dataclass
class Instruction:
    address: int = 0
    size: int = 0


@dataclass()
class BasicBlock:
    start_addr: int = 0
    end_addr: int = 0
    predecessor: set[any] = field(default_factory=set)
    successor: any = None
    instructions: list[Instruction] = field(default_factory=list)

    def __hash__(self):
        return self.start_addr


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

    def on_new_block(self, address: int, size: int) -> bool:
        self._current_addr = address
        self.is_jump = self._next_addr != 0 and self._current_addr != self._next_addr

        if self._should_stop_on_block(address, size):
            return False

        if address not in self._blocks:
            blk = BasicBlock(start_addr=address)
        else:
            blk = self._blocks[address]
        if self._head_block is None:
            self._head_block = blk
        if self._tail_block is None:
            self._tail_block = blk
        else:
            blk.predecessor.add(self._tail_block)
            self._tail_block.successor = blk
            self._tail_block = blk
        return True  # continue

    def on_new_inst(self, address: int, size: int) -> bool:
        if self._start_addr == 0:
            self._start_addr = address
        self._last_addr = self._current_addr
        self._current_addr = address
        self._next_addr = address + size

        if self._should_stop_on_inst(address, size):
            return False

        if self._tail_block is not None:
            self._tail_block.instructions.append(Instruction(address, size))
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
