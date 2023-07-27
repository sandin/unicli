import sys
from unidbg.command import CMD_RESULT_FAILED, CMD_RESULT_OK
from unidbg.context import Context, State
from unidbg.util.cmd_parser import parse_number


ALL_REG_NUM = sys.maxsize


def cmd_reg_read(context: Context, args: list[str]) -> int:
    if context.state != State.LOADED:
        print("invalid context state")
        return CMD_RESULT_FAILED

    # <reg_name>
    if len(args) < 1:
        print("missing <reg_name> arg")
        return CMD_RESULT_FAILED
    reg_name = args[0]
    if reg_name == "all":
        reg_num = ALL_REG_NUM
    else:
        reg_num = context.arch.get_reg_num(reg_name, -1)
        if reg_num == -1:
            print("invalid reg name: %s" % args[0])
            return CMD_RESULT_FAILED

    regs_batch = []
    if reg_num == ALL_REG_NUM:
        for reg_num in context.arch.get_all_reg_num():
            regs_batch.append(reg_num)
    else:
        regs_batch.append(reg_num)

    i = 0
    for reg_num in regs_batch:
        value, err = context.executor.reg_read(reg_num)
        reg_name = context.arch.get_reg_name(reg_num, "")
        if err is not None:
            print("Error: can not read reg %s, %s" % (reg_name, err))
            return CMD_RESULT_FAILED
        new_line = (i != 0 and (i + 1) % 2 == 0) or i == len(regs_batch) - 1
        print("%3s => %s    " % (reg_name, context.arch.format_number(value)), end="\n" if new_line else "")
        i += 1
    return CMD_RESULT_OK


def cmd_reg_write(context: Context, args: list[str]) -> int:
    if context.state != State.LOADED:
        print("invalid context state")
        return CMD_RESULT_FAILED

    # <reg_name>
    if len(args) < 1:
        print("missing <reg_name> arg")
        return CMD_RESULT_FAILED
    reg_name = args[0]
    if reg_name == "all":
        reg_num = ALL_REG_NUM
    else:
        reg_num = context.arch.get_reg_num(reg_name, -1)
        if reg_num == -1:
            print("invalid reg name: %s" % args[0])
            return CMD_RESULT_FAILED

    # <value>
    if len(args) < 2:
        print("missing <value> arg")
        return CMD_RESULT_FAILED
    value = parse_number(args[1], sys.maxsize)
    if value == sys.maxsize:
        print("invalid number format: %s" % args[1])
        return CMD_RESULT_FAILED

    regs_batch = []
    if reg_num == ALL_REG_NUM:
        for reg_num in context.arch.get_all_reg_num():
            regs_batch.append((reg_num, value))
    else:
        regs_batch.append((reg_num, value))

    i = 0
    for reg_num, value in regs_batch:
        ret, err = context.executor.reg_write(reg_num, value)
        reg_name = context.arch.get_reg_name(reg_num, "")
        if err is not None:
            print("Error: can not write reg %s => %d, %s" % (reg_name, value, err))
            return CMD_RESULT_FAILED
        new_line = (i != 0 and (i + 1) % 2 == 0) or i == len(regs_batch) - 1
        print("%3s => %s    " % (reg_name, context.arch.format_number(value)), end="\n" if new_line else "")
        i += 1
    return CMD_RESULT_OK
