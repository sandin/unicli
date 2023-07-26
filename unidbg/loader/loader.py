from ..executor.executor import Executor


class LoadedInfo(object):
    def __init__(self):
        self.load_start = 0
        self.load_bias = 0
        self.load_size = 0


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
