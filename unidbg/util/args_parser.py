

def parse_arg(line: str) -> (str, str):
    if not line.strip():
        return None, ""
    if " " in line:
        idx = line.index(" ")
        return line[:idx], line[idx+1:]
    return line, ""


