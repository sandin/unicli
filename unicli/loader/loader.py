from dataclasses import dataclass
from unicli.executor.executor import Executor


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

    def load(self, executor: Executor, filename: str, base_addr: int = 0, offset: int = 0) -> (LoadedInfo, str):
        """
        Load a file
        :param executor: executor
        :param filename: filename
        :param base_addr: base address
        :param offset: offset of base address
        :return: (result, error)
        """
        pass
