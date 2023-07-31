from .__init__ import CMD_RESULT_FAILED, CMD_RESULT_OK
from unicli.context import Context, state_is_loaded
from unicli.util.cmd_parser import Command


def cmd_ctx_save(ctx: Context, cmd: Command) -> (int, str):
    if not state_is_loaded(ctx.state):
        return CMD_RESULT_FAILED, "invalid context state"

    name, err = cmd.get_str_arg("name", 2, "last_context")
    if err is not None:
        return CMD_RESULT_FAILED, err

    context, err = ctx.executor.ctx_save(name)
    if err is not None:
        return CMD_RESULT_FAILED, "can not save the last context, %s" % err
    ctx.saved_context[name] = context
    return CMD_RESULT_OK, None


def cmd_ctx_restore(ctx: Context, cmd: Command) -> (int, str):
    if not state_is_loaded(ctx.state):
        return CMD_RESULT_FAILED, "invalid context state"

    name, err = cmd.get_str_arg("name", 2, "last_context")
    if err is not None:
        return CMD_RESULT_FAILED, err

    if name not in ctx.saved_context:
        return CMD_RESULT_FAILED, "can not find the context by name %s" % name

    context = ctx.saved_context[name]
    ret, err = ctx.executor.ctx_restore(context)
    if err is not None:
        return CMD_RESULT_FAILED, "can not save the last context, %s" % err
    return CMD_RESULT_OK, None


def cmd_ctx_delete(ctx: Context, cmd: Command) -> (int, str):
    if not state_is_loaded(ctx.state):
        return CMD_RESULT_FAILED, "invalid context state"

    name, err = cmd.get_str_arg("name", 2, "last_context")
    if err is not None:
        return CMD_RESULT_FAILED, err

    if name not in ctx.saved_context:
        return CMD_RESULT_FAILED, "can not find the context by name %s" % name

    del ctx.saved_context[name]
    return CMD_RESULT_OK, None
