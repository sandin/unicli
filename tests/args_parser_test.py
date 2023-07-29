import pytest

from unicli.context import Context
from unicli.util.cmd_parser import parse_command, parse_address, parse_bytes


def test_parse_args():
    ctx = Context()

    command = parse_command(ctx, 'help')
    assert command.cmd == "help"
    assert len(command.args) == 0

    command = parse_command(ctx, 'load /your/path/libdemo.so')
    assert command.cmd == "load"
    assert len(command.args) == 1
    command.args[0] = "/your/path/libdemo.so"

    command = parse_command(ctx, 'mem_read 0x38550 0x10')
    assert command.cmd == "mem_read"
    assert len(command.args) == 2
    command.args[0] = "0x38550"
    command.args[1] = "0x10"

    command = parse_command(ctx, 'reg_write sp 0x00010000+(8*1024)')
    assert command.cmd == "reg_write"
    assert len(command.args) == 2
    command.args[0] = "sp"
    command.args[1] = "0x00010000+(8*1024)"

    command = parse_command(ctx, '# comment')
    assert command is None

    command = parse_command(ctx, 'mem_list # comment')
    assert command.cmd == "mem_list"
    assert len(command.args) == 0

    command = parse_command(ctx, 'mem_write 0x38550 "C0 03 5F D6" # patch ret')
    assert command.cmd == "mem_write"
    assert len(command.args) == 2
    command.args[0] = "0x38550"
    command.args[1] = "C0 03 5F D6"

    command = parse_command(ctx, 'hook_block 0x38550 mem_read 0xFBA68 0x10')
    assert command.cmd == "hook_block"
    assert len(command.args) == 4
    command.args[0] = "0x38550"
    command.args[1] = "mem_read"
    command.args[1] = "0xFBA68"
    command.args[1] = "0x10"

    command = parse_command(ctx, 'emu_start 0x4061C 0x4061C  # adrl X20, #0xFBD50 ')
    assert command.cmd == "emu_start"
    assert len(command.args) == 2
    command.args[0] = "0x4061C"
    command.args[1] = "0x4061C"


def test_get_flags():
    ctx = Context()

    command = parse_command(ctx, 'mem_read 0x38550 0x38550+0x1000 --out "/you/path/output.bin" -f')
    assert command.cmd == "mem_read"
    assert len(command.args) == 5
    assert command.get_addr_arg("start_addr", 0, 0) == 0x38550
    assert command.get_addr_arg("end_addr", 1, 0) == (0x38550+0x1000)
    assert command.get_str_flag(["o", "out"], 2, "") == "/you/path/output.bin"
    assert command.has_flag(["f", "force"], 2, False) is True


def test_parse_address():
    # valid format
    assert parse_address("0x38550") == 0x38550
    assert parse_address("0x00010000") == 0x00010000

    # always treat address as hexadecimal
    assert parse_address("38550") == 0x38550
    assert parse_address("23b736") == 0x23b736
    assert parse_address("abcdef") == 0xabcdef
    assert parse_address("deadcafe") == 0xdeadcafe

    # python expression
    assert parse_address("0x00010000+0x101") == 0x00010101
    assert parse_address("0x00010000 + 0x101") == 0x00010101
    assert parse_address(" 0x00010000 + 0x101 ") == 0x00010101
    assert parse_address(" 0x00010001 - 0x10000 ") == 0x00000001

    # invalid format
    assert parse_address("", -1) == -1
    assert parse_address(" ", -1) == -1
    assert parse_address("i38b00", -1) == -1
    assert parse_address("a + b", -1) == -1
    assert parse_address("x - y", -1) == -1


def test_parse_bytes():
    assert parse_bytes("C0 03 5F D6") == b"\xC0\x03\x5F\xD6"
    assert parse_bytes("C0 3 5F D6") == b"\xC0\x03\x5F\xD6"
    assert parse_bytes("C0035FD6") == b"\xC0\x03\x5F\xD6"
    assert parse_bytes("C0035FD61") == b"\xC0\x03\x5F\xD6"  # ignore incomplete parts

    buffer = b''.join([
        b'\xA0\x81\xE6\x96\x87\xE4\xBB\xB6\xE5\xA6\x82\xE4\xB8\x8B\xEF\xBC',
        b'\x9A\x3C\x2F\x64\x69\x76\x3E\x3C\x75\x6C\x3E\x3C\x6C\x69\x3E\x3C'])
    assert parse_bytes(
        "A0 81 E6 96 87 E4 BB B6 E5 A6 82 E4 B8 8B EF BC 9A 3C 2F 64 69 76 3E 3C 75 6C 3E 3C 6C 69 3E 3C") \
           == buffer
