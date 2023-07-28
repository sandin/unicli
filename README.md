# UniDbg

An interactive command line debugger for unicorn.

​      

Dependencies:

* [unicorn](https://github.com/unicorn-engine/unicorn)
* [capstone](https://github.com/capstone-engine/capstone)
* [LIEF](https://github.com/lief-project/LIEF)
* [prompt_toolkit](https://github.com/prompt-toolkit/python-prompt-toolkit)

​              

## Install

Install with pip:
```
$ pip install unidbg
```

Install with source code:
```
$ git clone git@github.com:sandin/unidbg.git
$ cd unidbg
$ pip install -r requirements.txt
```

> NOTE: Using unidbg in python venv is highly recommended!

​                          

## Basic Usage

Start the debugger:

```bash
$ unidbg
UniDbg 0.0.1
Type "help" for more information.
```

​                                  

### Load Module

Load an ELF/PE/Mach-O file into memory:

```bash
>>> load /your/path/libdemo.so
Map memory reserve address space [0x1000000 - 0x10fe000]
Map memory from file [0x0 - 0xe396c] to virtual memory [0x1000000 - 0x10e396c]
Map memory from file [0xe3000 - 0xe9110] to virtual memory [0x10f3000 - 0x10f9110]
Fill memory with zeros to align with page size [0x10f9110 - 0x10fa000]
Fill memory with zeros for .bss section [0x10fa000 - 0x10fd000]
Successfully loaded module: /your/path/libdemo.so
```
> NOTE: unidbg will map all LOAD segments in the ELF file to unicorn's virtual memory.

​              

### Memory Map 

Create a block of memory to be used as stack memory:

```bash
>>> mem_map 0x00010000 8*1024*1024
0x0000010000 - 0x0000810000 rwx
```

​               

### Register Write

Set the value of the `sp` register:

```bash
>>> reg_write sp 0x00010000+(8*1024*1024)
 SP => 0x0000000000810000    
```

​                    

### Memory Write

Patch some instructions that you don't want to execute:

```bash
>>> mem_write 0x38550 "C0 03 5F D6" # ret
0x0000038550  C0 03 5F D6                                       |.._.            |
>>> mem_write 0x40530 "1F 20 03 D5" # nop
0x0000040530  1F 20 03 D5                                       |. ..            |
```

> NOTE: `0x38550` and `0x40530` are relative addresses based on the module base address.

​                   

### Block/Code Hook

Setup some event hooks:

```
>>> hook_block 0x40800 reg_read X8
hook block at 0x0000040800
   
>>> hook_code 0x4083c mem_read 0xFBAB8 0xa
hook code at 0x000004083c
```

> The subcommand (`mem_read` or `reg_read` ) will be executed when the hook event is hit.

​                   

### Start Emulation

Then jump to the specified address to start the simulation execution, unidbg will print all executed assembly code and block information.

```
>>> emu_start 0x407E0 0x40844
Start emulation, range: 0x00000407e0 - 0x0000040844
0x00000407e0 blk_407e0:
0x00000407e0              add        x0, x20, #0x350
0x00000407e4              ldarb      w8, [x0]
0x00000407e8              tbz        w8, #0, #0x40a84
0x0000040a84 blk_40a84:
0x0000040a84              bl         #0x38550
0x0000038550 blk_38550:
0x0000038550              ret     
0x00000407fc blk_407fc:
0x00000407fc              adrp       x9, #0xbd000
0x0000040800 blk_40800:
 X8 => 0x00000000010fbab8     
0x0000040800              ldr        d0, [x8]
0x0000040a88 blk_40a88:
0x0000040a88              cbz        w0, #0x407ec 
0x0000040800              ldr        d0, [x8]
0x0000040804              ldrb       w10, [x8, #8]
0x0000040834              adrp       x0, #0xfb000
0x0000040838              add        x0, x0, #0xab8
0x000004083c              mov        w2, #0x10
0x0000040840              mov        x1, xzr
Emulation done, range: 0x00000407e0 - 0x0000040844
```

> NOTE: If there is a registered hook, then these subcommands will also print the output at the corresponding address.

​            

### Memory Read         

Now you can read some interested memory after the simulation execution:

```
>>> mem_read 0xFBAB8 0xa
0x00000fbab8  30 78 34 38 34 37 31 36  38 00                    |0x4847168.      |
```

​            

### Register Read

And you can also read the values in all the registers.

```bash
>>> reg_read all
 X0 => 0x00000000010fbab8     X1 => 0x0000000000000000    
 X2 => 0x0000000000000010     X3 => 0x0000000000000000    
 X4 => 0x0000000000000000     X5 => 0x0000000000000000    
 X6 => 0x0000000000000000     X7 => 0x0000000000000000    
 X8 => 0x00000000010fbab8     X9 => 0x0000000000000000    
 X8 => 0x00000000010fbab8     X9 => 0x0000000000000000    
X10 => 0x0000000000000038    X11 => 0x00000000000000bd    
X12 => 0x0000000000000043    X13 => 0x0000000000000000    
X14 => 0x0000000000000000    X15 => 0x0000000000000000    
X16 => 0x0000000000000000    X17 => 0x0000000000000000    
X18 => 0x0000000000000000    X19 => 0x0000000000000000    
X20 => 0x00000000000fbd50    X21 => 0x0000000000000000    
X22 => 0x0000000000000000    X23 => 0x0000000000000000    
X24 => 0x0000000000000000    X25 => 0x0000000000000000    
X26 => 0x0000000000000000    X27 => 0x0000000000000000    
X28 => 0x0000000000000000     FP => 0x0000000000000000    
 LR => 0x0000000001040acc     SP => 0x0000000000810000    
 PC => 0x0000000001040844  
```

​           

## Advanced Usage

### Init Script

You can load an init script at startup, and in that script file you can write some init commands that will be executed automatically at the beginning.

​        

init_script:

```
help
load /your/path/libdemo.so
load_list
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

unload all
exit
```

> NOTE: In fact, you can write a lot of commands to a script file, then load that file with the `script` command, and unidbg will batch execute all the commands in that file together. 

For more information you can just type `help`.