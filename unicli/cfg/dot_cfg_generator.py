from unicli.cfg.cfg_generator import CfgGenerator
from unicli.tracker.basic_block import BasicBlock


GRAPH_TEMPLATE = """digraph G {{
    node [shape=record];

    {blocks}

    {edges}
}}
"""

INST_TEMPLATE = """{asm}<br align="left"/>\n"""

BLOCK_TEMPLATE = """
    {block_name} [label=<
{block_name}: <br align="left"/>
{insts}
    >];
"""

EDGE_TEMPLATE = """{from_block} -> {to_block}\n"""


class DotCfgGenerator(CfgGenerator):

    def generate(self, bb: BasicBlock) -> (str, str):
        blocks = set()
        DotCfgGenerator._get_blocks(bb, blocks)

        blocks_txt = self._generate_blocks(blocks)
        if not blocks_txt:
            return False, "Can not generate blocks of cfg"

        edges_txt = self._generate_edges(blocks)
        if not edges_txt:
            return False, "Can not generate blocks of cfg"

        content = GRAPH_TEMPLATE.format(blocks=blocks_txt, edges=edges_txt)
        return content, None

    @staticmethod
    def _get_blocks(bb: BasicBlock, blocks: set, include_preds=False):
        if bb not in blocks:
            blocks.add(bb)
        if include_preds:
            for pred in bb.predecessors:
                if pred not in blocks:
                    DotCfgGenerator._get_blocks(pred, blocks)
        for succ in bb.successors:
            if succ not in blocks:
                DotCfgGenerator._get_blocks(succ, blocks)

    @staticmethod
    def _generate_blocks(blocks: set[BasicBlock]):
        txt = ""
        for block in blocks:
            txt += DotCfgGenerator._generate_block(block)
        return txt

    @staticmethod
    def _generate_block(bb: BasicBlock):
        insts = ""
        for inst in bb.instructions:
            insts += INST_TEMPLATE.format(asm=inst.inst)
        insts = insts[:-1]  # remove the last \n
        return BLOCK_TEMPLATE.format(block_name=bb.name, insts=insts)

    @staticmethod
    def _generate_edges(blocks: set[BasicBlock]):
        txt = ""
        edges = set()
        for block in blocks:
            for pred in block.predecessors:
                if (pred.name, block.name) not in edges:
                    txt += EDGE_TEMPLATE.format(from_block=pred.name, to_block=block.name)
                    edges.add((pred.name, block.name))
            for succ in block.successors:
                if (block.name, succ.name) not in edges:
                    txt += EDGE_TEMPLATE.format(from_block=block.name, to_block=succ.name)
                    edges.add((block.name, succ.name))
        return txt
