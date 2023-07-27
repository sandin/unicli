from enum import IntEnum
from typing import Optional
from dataclasses import dataclass, field

from unidbg.arch.arch import ArchSpec
from unidbg.executor.executor import Executor
from unidbg.loader.loader import Loader


class State(IntEnum):
    INVALID = 0
    LOADED = 1


@dataclass
class Context:
    executor: Optional[Executor] = None
    loader: Optional[Loader] = None
    arch: Optional[ArchSpec] = None
    base_addr: int = 0
    padding_cmds: list[str] = field(default_factory=list)
    state: State = State.INVALID
    prompt: str = ">>>"
