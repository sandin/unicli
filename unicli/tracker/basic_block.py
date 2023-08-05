from dataclasses import dataclass, field


@dataclass
class Instruction:
    address: int = 0
    size: int = 0
    inst: str = None


@dataclass()
class BasicBlock:
    name: str = None
    start_addr: int = 0
    end_addr: int = 0
    predecessors: set[any] = field(default_factory=set)
    successors: set[any] = field(default_factory=set)
    instructions: list[Instruction] = field(default_factory=list)

    def __hash__(self):
        return self.start_addr
