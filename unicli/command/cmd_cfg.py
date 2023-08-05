import os
from .__init__ import CMD_RESULT_FAILED, CMD_RESULT_OK
from unicli.context import Context
from unicli.util.cmd_parser import Command
from unicli.cfg.dot_cfg_generator import DotCfgGenerator


def cmd_cfg_save(ctx: Context, cmd: Command) -> (int, str):
    if ctx.tracker is None:
        return CMD_RESULT_FAILED, "invalid state"

    # <addr>
    address, err = cmd.get_addr_arg("addr", 0, -1)
    if err is not None:
        return CMD_RESULT_FAILED, err

    # --out <out>
    out = cmd.get_str_flag(["o", "out"], 1, None)
    if out is None:
        return CMD_RESULT_FAILED, "missing out arg"

    # --format <format>
    file_format = cmd.get_str_flag(['f', 'format'], 1, "dot")
    if file_format == "dot":
        cfg_generator = DotCfgGenerator()
    else:
        return CMD_RESULT_FAILED, "unsupported format: %s" % file_format

    # find the target block
    block = ctx.tracker.find_block(address)
    if block is None:
        return CMD_RESULT_FAILED, "can not find block at address: 0x%x" % address

    # generate CFG for block
    content, err = cfg_generator.generate(block)
    if err is not None:
        return CMD_RESULT_FAILED, "can not generate CFG: %s" % err

    if not os.path.exists(out):
        os.makedirs(out, exist_ok=True)
    filename = os.path.join(out, "%s.%s" % (block.name, file_format))
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)
    print("CFG has been saved to file: %s" % filename)
    return CMD_RESULT_OK, None
