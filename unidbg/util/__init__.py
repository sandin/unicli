

def register_cmd(commands, *cmds, handler):
    for cmd in cmds:
        commands[cmd] = handler


def parse_init_script(filename):
    cmds = []
    with open(filename, "r") as f:
        for line in f:
            cmds.append(line.strip())
    return cmds
