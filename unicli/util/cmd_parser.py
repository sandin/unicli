import os
from inspect import isfunction
from typing import Optional

from unicli.context import Context


LAST_RESULT_VAR_NAME = "0"


def tokenize(line: str, split_tokens: list[str], wrap_tokens: list[str], end_tokens: list[str]):
    parts = []
    last_part = ""
    in_wrap = False
    for i in range(0, len(line)):
        c = line[i]
        if c in wrap_tokens:
            in_wrap = not in_wrap
            continue
        if not in_wrap and c in end_tokens:
            return parts
        if not in_wrap and c in split_tokens:
            if len(last_part.strip()) > 0:
                parts.append(last_part)
            last_part = ""
            continue
        last_part += c
    if len(last_part.strip()) > 0:
        parts.append(last_part)
    return parts


def join_args(args: list[str]):
    s = ""
    for i, arg in enumerate(args):
        if " " in arg:
            s += '"' + arg + '"'
        else:
            s += arg
        if i != len(args) -1:
            s += " "
    return s


EXPRESSION_TOKEN = ["+", "-", "*", "/"]


def is_expression(text: str) -> bool:
    for c in text:
        if c in EXPRESSION_TOKEN:
            return True
    return False


def parse_var(var_solver, arg: str, def_val: Optional[any]) -> (str, str):
    if type(var_solver) == dict:
        def solver(var_name, def_val):
            if var_name in var_solver:
                return var_solver[var_name]
            return def_val
    elif isfunction(var_solver):
        solver = var_solver
    else:
        raise Exception("unexpected type of var solver", type(var_solver))

    ret = ""  # type: str
    split_tokens = EXPRESSION_TOKEN + [' ']
    var_token = "$"
    last_var_name = None
    for i in range(0, len(arg)):
        c = arg[i]
        if c == var_token:
            last_var_name = ""
            continue
        if c in split_tokens:
            if last_var_name is not None and len(last_var_name) > 0:
                var_val = solver(last_var_name, None)
                if var_val is None:
                    return def_val, "use undefined local var `%s`" % arg
                ret = ret + str(var_val)
                last_var_name = None
        if last_var_name is not None:
            last_var_name += c
        else:
            ret += c
    if last_var_name is not None and len(last_var_name) > 0:
        var_val = solver(last_var_name, None)
        if var_val is None:
            return def_val, "use undefined local var `%s`" % arg
        ret = ret + str(var_val)
    return ret, None


def is_hexadecimal(text: str) -> bool:
    return text.startswith("0x")


def parse_number(text: str, def_val: int, base=10) -> (int, str):
    arg = def_val
    if type(text) == int:
        return text
    if text:
        if is_expression(text):
            try:
                ret = eval(text)
                if type(ret) == int:
                    arg = ret
                elif type(ret) == str:
                    return parse_number(ret, def_val, base)
            except:
                pass
        elif is_hexadecimal(text):
            try:
                arg = int(text, base=16)
            except:
                pass
        else:
            try:
                arg = int(text, base=base)
            except:
                pass
    return arg


def parse_address(text: str, def_val: int = -1) -> (int, str):
    return parse_number(text, def_val, base=16)


def parse_bytes(text: str) -> bytes:
    data = bytearray()
    if " " in text:
        parts = tokenize(text, [" "], [], [])
        for part in parts:
            data.append(int(part, base=16))
    else:
        b = ""
        for c in text:
            if len(b) == 2:
                data.append(int(b, base=16))
                b = ""
            b += c
        if len(b) == 2:
            data.append(int(b, base=16))
    return bytes(data)


ERR_USE_DEF = "ERR_UES_DEF"


class Command(object):

    def __init__(self, ctx: Context, raw: str, cmd: Optional[str], args: list[str]):
        self.ctx = ctx
        self.raw = raw
        self.cmd = cmd
        self.args = args

    def get_raw(self):
        return self.raw

    def get_args(self):
        return self.args

    def args_num(self):
        return len(self.args)

    def _get_arg(self, name: str, index: int, def_val: Optional[any]) -> (any, str):
        if index >= len(self.args):
            if def_val is not None:  # it's an optional arg, just use the default value
                return def_val, ERR_USE_DEF
            return def_val, "missing <%s> arg" % name
        arg = self.args[index]
        return arg, None

    def get_raw_arg(self, name: str, index: int, def_val: Optional[str]) -> (str, str):
        arg, err = self._get_arg(name, index, def_val)
        if err is not None:
            return def_val, err if err != ERR_USE_DEF else None
        return arg, err

    @staticmethod
    def parse_var_with_ctx(ctx: Context, arg: str, def_val: Optional[any]) -> (str, str):
        def var_solver(var_name, in_def_val):
            if var_name in ctx.local_vars:
                return ctx.local_vars[var_name]
            if var_name == LAST_RESULT_VAR_NAME:
                return ctx.last_result
            reg_num = ctx.arch.get_reg_num(var_name, -1)
            if reg_num == -1:
                return in_def_val
            val, err = ctx.executor.reg_read(reg_num)
            return hex(val) if err is None else in_def_val
        return parse_var(var_solver, arg, def_val)

    def get_str_arg(self, name: str, index: int, def_val: Optional[str]) -> (str, str):
        arg, err = self._get_arg(name, index, def_val)
        if err is not None:
            return def_val, err if err != ERR_USE_DEF else None
        return self.parse_var_with_ctx(self.ctx, arg, def_val)

    def get_file_arg(self, name: str, index: int, def_val: Optional[str]) -> (str, str):
        arg, err = self.get_str_arg(name, index, def_val)
        if err is not None:
            return def_val, err if err != ERR_USE_DEF else None
        arg, err = self.parse_var_with_ctx(self.ctx, arg, def_val)
        if err is not None:
            return def_val, err
        if not os.path.exists(arg):
            return def_val, "`%s` file is not exists!" % arg
        return os.path.abspath(arg), None

    def get_addr_arg(self, name: str, index: int, def_val: Optional[int]) -> (int, str):
        arg, err = self._get_arg(name, index, def_val)
        if err is not None:
            return def_val, err if err != ERR_USE_DEF else None
        arg, err = self.parse_var_with_ctx(self.ctx, arg, def_val)
        if err is not None:
            return def_val, err
        addr = parse_address(arg, def_val)
        if addr == def_val:
            return def_val, "invalid address format: `%s` = `%s`" % (name, arg)
        return addr, None

    def get_int_arg(self, name: str, index: int, def_val: Optional[int]) -> (int, str):
        arg, err = self._get_arg(name, index, def_val)
        if err is not None:
            return def_val, err if err != ERR_USE_DEF else None
        arg, err = self.parse_var_with_ctx(self.ctx, arg, def_val)
        if err is not None:
            return def_val, err
        addr = parse_number(arg, def_val)
        if addr == def_val:  # TODO: bug
            return def_val, "invalid number format: `%s` = `%s`" % (name, arg)
        return addr, None

    def get_bytes_arg(self, name: str, index: int, def_val: Optional[bytes]) -> (int, str):
        arg, err = self._get_arg(name, index, def_val)
        if err is not None:
            return def_val, err if err != ERR_USE_DEF else None
        arg, err = self.parse_var_with_ctx(self.ctx, arg, def_val)
        if err is not None:
            return def_val, err
        data = parse_bytes(arg)
        if len(data) == 0:
            return def_val, "invalid data format: `%s` = `%s`" % (name, arg)
        return data, None

    def get_subcommand_arg(self, name: str, index: int, def_val: Optional[any]) -> (any, str):
        if index >= len(self.args):
            return def_val, "missing <%s> arg" % name
        cmd = self.args[index]
        args = self.args[index+1:]
        return Command(self.ctx, "", cmd, args)

    def get_str_flag(self, names: list[str], start_index: int, def_val: Optional[str]) -> Optional[str]:
        i = start_index
        while i < len(self.args):
            arg = self.args[i]
            if arg.startswith('-') and len(arg) >= 2:
                if arg[1] == '-':
                    flag_name = arg[2:]  # --flag
                else:
                    flag_name = arg[1:]  # -f
                if flag_name in names:
                    i += 1
                    if i < len(self.args):
                        return self.args[i]
            i += 1
        return def_val

    def get_addr_flag(self, names: list[str], start_index: int, def_val: int) -> Optional[int]:
        val = self.get_str_flag(names, start_index, None)
        if val is not None:
            return parse_address(val, def_val)
        return def_val

    def get_int_flag(self, names: list[str], start_index: int, def_val: int) -> int:
        flag = self.get_str_flag(names, start_index, None)
        if flag is not None:
            return parse_number(flag, def_val)
        return def_val

    def has_flag(self, names: list[str], start_index: int, def_val: bool) -> bool:
        i = start_index
        while i < len(self.args):
            arg = self.args[i]
            if arg.startswith('-') and len(arg) >= 2:
                if arg[1] == '-':
                    flag_name = arg[2:]  # --flag
                else:
                    flag_name = arg[1:]  # -f
                if flag_name in names:
                    return True
            i += 1
        return def_val


def parse_command(ctx: Context, line: str) -> Optional[Command]:
    if line.startswith("!"):
        line = "! " + line[1:]
    parts = tokenize(line, [' '], ['"', "'", '[', ']'], ['#'])
    if len(parts) > 0:
        c = Command(ctx, line, None, [])
        c.cmd = parts[0]
        c.args += parts[1:]
        return c
    return None
