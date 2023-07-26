

def parse_arg(line: str) -> (str, str):
    if not line.strip():
        return None, ""
    if " " in line:
        idx = line.index(" ")
        return line[:idx], line[(idx+1):]
    return line, ""


def parse_int_arg(line: str, def_val: int, base=10) -> (int, str):
    arg, remain = parse_arg(line)
    if arg:
        if arg.startswith("0x"):
            base = 16
        try:
            arg = int(arg, base=base)
        except:
            arg = def_val
    else:
        arg = def_val
    return arg, remain


def parse_addr_arg(line: str, def_val: int) -> (int, str):
    return parse_int_arg(line, def_val, base=16)
