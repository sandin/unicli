from unicli.tracker.basic_block import BasicBlock


class CfgGenerator(object):
    """
    Interface CFG Generator
    """

    def generate(self, bb: BasicBlock) -> (str, str):
        """
        Generate CFG to output
        :param bb: Basic Block
        :return: (output, error)
        """
        pass
