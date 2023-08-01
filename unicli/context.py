from enum import IntEnum
from typing import Optional
from dataclasses import dataclass, field
from unicli.arch.arch import ArchSpec
from unicli.executor.executor import Executor
from unicli.loader.loader import Loader, LoadedInfo
from unicli.util.file_format import FileFormat


class State(IntEnum):
    INVALID = 0
    LOADED = 1
    RUNNING = 2


@dataclass
class Context:
    commands: dict[str, any] = field(default_factory=dict)
    usage: str = None
    executor: Optional[Executor] = None
    saved_context: dict[str, any] = field(default_factory=dict)
    loader: dict[FileFormat, Loader] = field(default_factory=dict)
    loaded: list[LoadedInfo] = field(default_factory=list)
    arch: Optional[ArchSpec] = None
    base_addr: int = 0
    padding_cmds: list[str] = field(default_factory=list)
    state: State = State.INVALID
    prompt: str = ">>>"
    local_vars: dict[str, str] = field(default_factory=dict)
    last_result: any = None


def execute_command(ctx: Context, command) -> (int, str):
    if command.cmd in ctx.commands:
        cmd_handle_func = ctx.commands[command.cmd]
        return cmd_handle_func(ctx, command)
    else:
        return False, "unsupported command: `%s`" % command.cmd


def state_is_loaded(state: State) -> bool:
    return state >= State.LOADED


def state_is_running(state: State) -> bool:
    return state == State.RUNNING

