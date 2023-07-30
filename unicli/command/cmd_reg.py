import sys
from unicli.command import CMD_RESULT_FAILED, CMD_RESULT_OK
from unicli.context import Context, State, state_is_loaded
from unicli.util.cmd_parser import Command


ALL_REG_NUM = sys.maxsize
ALL_REG_NAME = "all"


def cmd_reg_read(ctx: Context, cmd: Command) -> (int, str):
    if not state_is_loaded(ctx.state):
        return CMD_RESULT_FAILED, "invalid context state"

    regs_batch = []
    i = 0
    while i < cmd.args_num():
        # <reg_name>
        reg_name, err = cmd.get_str_arg("reg_name", i, None)
        if err is not None:
            return CMD_RESULT_FAILED, err
        if reg_name == "all":
            reg_num = ALL_REG_NUM
        else:
            reg_num = ctx.arch.get_reg_num(reg_name, -1)
            if reg_num == -1:
                return CMD_RESULT_FAILED, "invalid reg name: %s" % reg_name

        if reg_num == ALL_REG_NUM:
            for reg_num in ctx.arch.get_all_reg_num():
                regs_batch.append(reg_num)
        else:
            regs_batch.append(reg_num)
        i += 1

    i = 0
    for reg_num in regs_batch:
        value, err = ctx.executor.reg_read(reg_num)
        reg_name = ctx.arch.get_reg_name(reg_num, "")
        if err is not None:
            err = "can not read reg %s, %s" % (reg_name, err)
            return CMD_RESULT_FAILED, err
        new_line = (i != 0 and (i + 1) % 2 == 0) or i == len(regs_batch) - 1
        print("%3s => %s    " % (reg_name, ctx.arch.format_number(value)), end="\n" if new_line else "")
        i += 1
    return CMD_RESULT_OK, None


def cmd_reg_write(ctx: Context, cmd: Command) -> (int, str):
    if not state_is_loaded(ctx.state):
        return CMD_RESULT_FAILED, "invalid context state"

    regs_batch = []
    i = 0
    while i < cmd.args_num():
        # <reg_name>
        reg_name, err = cmd.get_str_arg("reg_name", i, None)
        if err is not None:
            return CMD_RESULT_FAILED, err
        if reg_name == "all":
            reg_num = ALL_REG_NUM
        else:
            reg_num = ctx.arch.get_reg_num(reg_name, -1)
            if reg_num == -1:
                return CMD_RESULT_FAILED, "invalid reg name: %s" % reg_name

        # <value>
        i += 1
        value, err = cmd.get_int_arg("value", i, -1)
        if err is not None:
            return CMD_RESULT_FAILED, err

        if reg_num == ALL_REG_NUM:
            for reg_num in ctx.arch.get_all_reg_num():
                regs_batch.append((reg_num, value))
        else:
            regs_batch.append((reg_num, value))
        i += 1

    i = 0
    for reg_num, value in regs_batch:
        ret, err = ctx.executor.reg_write(reg_num, value)
        reg_name = ctx.arch.get_reg_name(reg_num, "")
        if err is not None:
            err = "can not write reg %s => %d, %s" % (reg_name, value, err)
            return CMD_RESULT_FAILED, err
        new_line = (i != 0 and (i + 1) % 2 == 0) or i == len(regs_batch) - 1
        print("%3s => %s    " % (reg_name, ctx.arch.format_number(value)), end="\n" if new_line else "")
        i += 1
    return CMD_RESULT_OK, None
