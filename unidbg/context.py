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
    commands: dict[str, any] = field(default_factory=dict)
    usage: str = None
    executor: Optional[Executor] = None
    loader: Optional[Loader] = None
    arch: Optional[ArchSpec] = None
    base_addr: int = 0
    padding_cmds: list[str] = field(default_factory=list)
    state: State = State.INVALID
    prompt: str = ">>>"
    local_vars: dict[str, str] = field(default_factory=dict)


def execute_command(ctx: Context, command) -> (int, str):
    if command.cmd in ctx.commands:
        cmd_handle_func = ctx.commands[command.cmd]
        return cmd_handle_func(ctx, command)
    else:
        return False, "unsupported command: `%s`" % command.cmd

