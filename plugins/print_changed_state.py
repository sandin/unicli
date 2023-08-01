from unicorn import *
from unicli.context import Context


g_last_reg_values = {}


def hook_code(mu: unicorn.Uc, address: int, size: int, user_data: any):
    global g_last_reg_values
    executor = user_data  # type: UnicornExecutor
    ctx = executor.context  # type: Context

    for reg_num in ctx.arch.get_all_reg_num():
        val, err = executor.reg_read(reg_num)
        if err is not None:
            continue
        if reg_num in g_last_reg_values:
            if reg_num == ctx.arch.get_instruction_pointer_reg_num() \
                    or reg_num == ctx.arch.get_frame_pointer_reg_num():
                continue
            old_val = g_last_reg_values[reg_num]
            if val != old_val:
                reg_name = ctx.arch.get_reg_name(reg_num, "")
                prefix = "                                                       ; "
                print("%s%3s: %s => %s    " % (prefix, reg_name, ctx.arch.format_number(old_val), ctx.arch.format_number(val)))
        g_last_reg_values[reg_num] = val


def main(ctx: Context):
    print("Hello Unicli Plugin")
    mu = ctx.executor.mu  # type: unicorn.Uc
    #mu.hook_add(UC_HOOK_CODE, hook_code, ctx.executor)
    ctx.executor.add_code_hook(0, hook_code)


if __name__ == "__main__":
    main(ctx)
