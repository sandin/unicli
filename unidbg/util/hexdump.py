

def hexdump(buf, off=0):
    last_bs, last_line = None, None
    for i in range(0, len(buf), 16):
        bs = bytearray(buf[i : i + 16])
        line = "0x{:08x}  {:23}  {:23}  |{:16}|".format(
            off + i,
            " ".join(("{:02X}".format(x) for x in bs[:8])),
            " ".join(("{:02X}".format(x) for x in bs[8:])),
            "".join((chr(x) if 32 <= x < 127 else "." for x in bs)),
        )
        #if bs == last_bs:
        #    line = "*"
        if bs != last_bs or line != last_line:
            print(line)
        last_bs, last_line = bs, line
    print("0x{:08x}".format(off + len(buf)))