from dataclasses import dataclass, field


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


@dataclass
class Command:
    cmd: str = None
    args: list[str] = field(default_factory=list)


def parse_command(line: str) -> Command:
    c = Command()
    parts = tokenize(line, [' '], ['"', "'"], ['#'])
    if len(parts) > 0:
        c.cmd = parts[0]
        c.args = parts[1:]
    return c
