import os


def register_cmd(commands, *cmds, handler):
    for cmd in cmds:
        commands[cmd] = handler


def parse_init_script(filename: str) -> list[str]:
    cmds = []
    with open(filename, "r") as f:
        for line in f:
            cmds.append(line.strip())
    return cmds


def write_content_to_file(content: bytes, filename: str) -> bool:
    dir_name = os.path.dirname(filename)
    if dir_name and not os.path.exists(dir_name):
        os.makedirs(dir_name, exist_ok=True)
    with open(filename, "bw") as f:
        f.write(content)
        return True


def read_file_content(f, offset: int, size: int) -> bytes:
    f.seek(offset)
    return f.read(size)
