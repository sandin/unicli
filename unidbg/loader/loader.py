from ..executor.executor import Executor


class Loader(object):
    """
    Interface Loader
    """

    def load(self, executor: Executor, filename: str) -> (bool, str):
        """
        Load a file
        :param executor: executor
        :param filename: filename
        :return: (result, error)
        """
        pass
