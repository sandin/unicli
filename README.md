# UniDbg

An interactive command line debugger for unicorn.

​     

Dependencies:

* [unicorn](https://github.com/unicorn-engine/unicorn)
* [capstone](https://github.com/capstone-engine/capstone)
* [LIEF](https://github.com/lief-project/LIEF)
* [prompt_toolkit](https://github.com/prompt-toolkit/python-prompt-toolkit)

​       

## Basic Usage

Start the debugger:
```bash
$ unidbg
UniDbg 0.0.1
Type "help" for more information.
```

​            

Load an ELF/PE/Mach-O file into memory:

```bash
>>> load /your/path/libdemo.so
Load Success, base address: 0x10bb32000
```
> NOTE: unidbg will map all LOAD segments in the ELF file to unicorn's virtual memory.

​           

Create a block of memory to be used as stack memory:

```bash
>>> mem_map 0x10000000 0x2000 PROT_ALL
Memory mapped at address: 0x10000000
```

​            

Set the value of the `sp` register:

```bash
>>> reg_write sp 0x10000000+0x2000
Register sp = 0x10002000
```

​                 

Patch some instructions that you don't want to execute:

```bash
>>> mem_write 0x10bb32000+0x38550 "C0 03 5F D6"
0x000000010bb6a550 C0 03 5F D6 00 00 00 00  00 00 00 00 00 00 00 00
>>> mem_write 0x10bb32000+0x374F0 "1F 20 03 D5"
0x000000010bb694f0 1F 20 03 D5 00 00 00 00  00 00 00 00 00 00 00 00
```

​        

Setup some event hooks:

```
>>> hook_block 0x10bb32000+0x40844 mem_read 0x10bb32000+0x374F0
add a block hook at address 0x10bb72844

>>> hook_code 0x10bb32000+0x40844 reg_read sp
add a code hook at address 0x10bb72844
```

> The subcommand (`mem_read` or `reg_read` ) will be executed when the hook event is hit.

​               

Then goto the address which you want to  execution:

```
>>> emu_start 0x10bb32000+0x407E0 0x10bb32000+0x40844 
    0x000000010bb727d8 0x00000000000407E8:    ldr             d0, [x8]
    0x000000010bb727e0 0x00000000000407F0:    ldrb            w10, [x8, #8]
->  0x000000010bb727e8 0x00000000000407F8:    ldrb            w12, [x8, #9]
```

​         

Now you can read memory after the exection:

```
>>> mem_read 0x10bb32000+0x374F0
0x000000010bb694f0  30 78 34 38 34 37 31 36 38 00                    0x4847168.
```

​     

Or read all registers:

```bash
>>> reg_read all
  x00 = 0x10bc2dab8
  x01 = 0x00000000
  x02 = 0x00000010
  x03 = 0x00000000
  x04 = 0x00000000
  x05 = 0x00000000
  x06 = 0x00000000
  x07 = 0x00000000
  x08 = 0x10bc2dab8
  x09 = 0x00000000
  x10 = 0x00000038
  x11 = 0x000000bd
  x12 = 0x00000043
  x13 = 0x00000000
  x14 = 0x00000000
  x15 = 0x00000000
  x16 = 0x00000000
  x17 = 0x00000000
  x18 = 0x00000000
  x19 = 0x00000000
  x20 = 0x10bc2dd50
  x21 = 0x00000000
  x22 = 0x00000000
  x23 = 0x00000000
  x24 = 0x00000000
  x25 = 0x00000000
  x26 = 0x00000000
  x27 = 0x00000000
  x28 = 0x00000000
  x29(fp) = 0x00000000
  x30(lr) = 0x10bb72acc
  x31(sp) = 0x14bd31000
  x32(pc) = 0x10bb72844
```

​        

## Advanced Usage

### init_script

You can load an init script at startup, and in that script file you can write some init commands that will be executed automatically at the beginning.

​        

init_script:
```
help
load /your/path/libdemo.so
mem_list
mem_read 0x38550 0x10
mem_read 0xF9068 0x08
mem_read 0xFDC80 0x08
```

​          

Then pass it in as a parameter on startup:

```
> unidbg init_script
UniDbg 0.0.1
Type "help" for more information.
load init script file `init_script`
>>> load /your/path/libdemo.so
Map memory reserve address space [0x1000000 - 0x10fe000]
Map memory from file [0x0 - 0xe396c] to virtual memory [0x1000000 - 0x10e396c]
Map memory from file [0xe3000 - 0xe9110] to virtual memory [0x10f3000 - 0x10f9110]
Fill memory with zeros to align with page size [0x10f9110 - 0x10fa000]
Fill memory with zeros for .bss section [0x10fa000 - 0x10fd000]
>>> mem_list
[0x01000000 - 0x010fe000) RWE
>>> mem_read 0x38550 0x10
0x00038550  10 06 00 90 11 8E 45 F9  10 62 2C 91 20 02 1F D6  |......E..b,. ...|
>>> mem_read 0xF9068 0x08
0x000f9068  A0 D4 0F 00 00 00 00 00                           |........        |
>>> mem_read 0xFDC80 0x08
0x000fdc80  00 00 00 00 00 00 00 00                           |........        |
```

​      

### script

You can actually write all the commands to a script file and then use the script command to load the file and execute it.

​     

script_file:

```
help
load /your/path/libdemo.so
mem_list
mem_read 0x38550 0x10
mem_read 0xF9068 0x08
mem_read 0xFDC80 0x08

# initialize stack & registers
mem_map 0x00010000 8*1024*1024
reg_write all 0
reg_write sp 0x00010000+(8*1024*1024)
reg_read all

# patch code
set ret "C0 03 5F D6"
set nop "1F 20 03 D5"
mem_write 0x38550 $ret
mem_write 0x374F0 $ret
mem_write 0x37E10 $ret
mem_write 0x40528 $nop
mem_write 0x40530 $nop
unset ret
unset nop

# hook address
hook_block 0x40800 reg_read X8
hook_code 0x4083c mem_read 0xFBAB8 0xa

# start emulation
reg_write X20 0xFBD50
emu_start 0x407E0 0x40844

# read registers and the memory of interest
reg_read all
mem_read 0xFBAB8 0xa

exit
```