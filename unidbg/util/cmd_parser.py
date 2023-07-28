import os
from typing import Optional

from unidbg.context import Context


def tokenize(line: str, split_tokens: list[str], wrap_tokens: list[str], end_tokens: list[str]):
    parts = []
    last_part = ""
    in_wrap = False
    for i in range(0, len(line)):
        c = line[i]
        if c in end_tokens:
            return parts
        if c in wrap_tokens:
            in_wrap = not in_wrap
            continue
        if not in_wrap and c in split_tokens:
            parts.append(last_part)
            last_part = ""
            continue
        last_part += c
    if len(last_part) > 0:
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


def is_expression(text: str) -> bool:
    expression_token = ["+", "-", "*", "/"]
    for c in text:
        if c in expression_token:
            return True
    return False


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
            arg = int(text, base=16)
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

    def __init__(self, ctx: Context, cmd: Optional[str], args: list[str]):
        self.ctx = ctx
        self.cmd = cmd
        self.args = args

    def get_args(self):
        return self.args

    def _get_arg(self, name: str, index: int, def_val: Optional[any]) -> (any, str):
        if index >= len(self.args):
            if def_val is not None:  # it's an optional arg, just use the default value
                return def_val, ERR_USE_DEF
            return def_val, "missing <%s> arg" % name
        arg = self.args[index]
        # replace with local var
        if arg.startswith("$"):
            var_name = arg[1:]
            if var_name not in self.ctx.local_vars:
                return def_val, "use undefined local var `%s`" % arg
            arg = self.ctx.local_vars[var_name]
        return arg, None

    def get_str_arg(self, name: str, index: int, def_val: Optional[str]) -> (str, str):
        return self._get_arg(name, index, def_val)

    def get_file_arg(self, name: str, index: int, def_val: Optional[str]) -> (str, str):
        arg, err = self.get_str_arg(name, index, def_val)
        if err is not None:
            return def_val, err if err != ERR_USE_DEF else None
        if not os.path.exists(arg):
            return def_val, "`%s` file is not exists!" % arg
        return os.path.abspath(arg), None

    def get_addr_arg(self, name: str, index: int, def_val: Optional[int]) -> (int, str):
        arg, err = self._get_arg(name, index, def_val)
        if err is not None:
            return def_val, err if err != ERR_USE_DEF else None
        addr = parse_address(arg, def_val)
        if addr == def_val:
            return def_val, "invalid address format: %s" % arg
        return addr, None

    def get_int_arg(self, name: str, index: int, def_val: Optional[int]) -> (int, str):
        arg, err = self._get_arg(name, index, def_val)
        if err is not None:
            return def_val, err if err != ERR_USE_DEF else None
        addr = parse_number(arg, def_val)
        if addr == def_val:
            return def_val, "invalid number format: %s" % arg
        return addr, None

    def get_bytes_arg(self, name: str, index: int, def_val: Optional[bytes]) -> (int, str):
        arg, err = self._get_arg(name, index, def_val)
        if err is not None:
            return def_val, err if err != ERR_USE_DEF else None
        data = parse_bytes(arg)
        if len(data) == 0:
            return def_val, "invalid data format: %s" % arg
        return data, None

    def get_subcommand_arg(self, name: str, index: int, def_val: Optional[any]) -> (any, str):
        if index >= len(self.args):
            return def_val, "missing <%s> arg" % name
        cmd = self.args[index]
        args = self.args[index+1:]
        return Command(self.ctx, cmd, args)


def parse_command(ctx: Context, line: str) -> Optional[Command]:
    parts = tokenize(line, [' '], ['"', "'"], ['#'])
    if len(parts) > 0:
        c = Command(ctx, None, [])
        c.cmd = parts[0]
        c.args += parts[1:]
        return c
    return None
