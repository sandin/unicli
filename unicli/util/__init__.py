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
    with open(filename, "bw") as f:
        f.write(content)
        return True

