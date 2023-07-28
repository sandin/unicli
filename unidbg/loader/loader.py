from dataclasses import dataclass
from unidbg.executor.executor import Executor


@dataclass
class LoadedInfo:
    filename: str = None
    load_start: int = 0
    load_bias: int = 0
    load_size: int = 0


class Loader(object):
    """
    Interface Loader
    """

    def load(self, executor: Executor, filename: str) -> (LoadedInfo, str):
        """
        Load a file
        :param executor: executor
        :param filename: filename
        :return: (result, error)
        """
        pass
