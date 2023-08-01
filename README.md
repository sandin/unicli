# UniCli

[中文文档](README_zh.md)        

An interactive command line interface for unicorn.

The aim of this project is to provide a handy command line tool for analyzing binary assemblies, not to implement a complete simulation environment, which many projects have proved to be impossible.

This tool will allow you to focus on the subject of your analysis instead of some repetitive and boring coding.

​                                                 

## Install

Install with pip:
```
$ pip install unicli
```

Install with source code:
```
$ git clone git@github.com:sandin/unicli.git
$ cd unicli
$ pip install -r requirements.txt
```

> NOTE: Using unicli in python venv is highly recommended!

​                            

## Example

* [Crack string encryption using unicli](samples/decrypt_string0/README.md)

​            

## Basic Usage

Start the debugger:

```bash
$ unicli
UniCli 0.0.1
Type "help" for more information.
```

If you install unicli with source code, then just type:
```
$ python -m unicli
```

If you run it with PyCharm:
* Create a new Python [Run/Debug Configuration], config and run it:
  * Module name: `unicli`
  * Execution:
    * [x] Emulate terminal in output console


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
> NOTE: unicli will map all LOAD segments in the ELF file to unicorn's virtual memory.

​              

### Memory Map 

Create a block of memory to be used as stack memory:

```bash
>>> mem_map 0x00010000 8*1024*1024
0x0000010000 - 0x0000810000 rwx
```

​                

### Set Variable

For convenience, we can set some local variables for reuse.

```
>>> set stack_pointer 0x00010000+(8*1024*1024)
set stack_pointer = 0x00010000+(8*1024*1024)
```

​     

### Register Write

Then we can set the value of the `sp` register and use the local variable we just created.

```bash
>>> reg_write sp $stack_pointer
 SP => 0x0000000000810000    
```

​                    

### Memory Write

Patch some instructions that you don't want to execute:

```bash
>>> set ret "C0 03 5F D6"
>>> set nop "1F 20 03 D5"

>>> mem_write 0x38550 $ret  # .__cxa_guard_acquire
0x0000038550  C0 03 5F D6                                       |.._.            |
>>> mem_write 0x40528 $nop  # bl .__cxa_guard_release
0x0000040528  1F 20 03 D5                                       |. ..            |
```

> NOTE: `0x38550` and `0x40528` are relative addresses based on the current module base address.

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

In fact, you can jump to any place to execute a piece of assembly code, and after each execution, you can use the last context to jump to another address to continue executing another piece of assembly code.

UniCli will prints out all executed assembly code, as well as block information, during simulated execution.  If there is a registered hook, then these subcommands will also print the output at the corresponding address. For example, we would like to look at the current value in a register when the code is run to a certain address.

​    

First let's jump to the beginning of the target function and execute the previous two assembly instructions in order to initialize the values of some registers that we will need to use later.

```
>>> reg_write all 0 sp $stack_pointer
>>> emu_start 0x4061C 0x4061C+8
Start emulation, range: 0x000004061c - 0x0000040624
0x000004061c blk_4061c:
0x000004061c              adrp       x20, #0xfb000
0x0000040620              add        x20, x20, #0xd50
Emulation done, range: 0x000004061c - 0x0000040624
```

​       

Then we can jump to the middle of the function to execute another piece of assembly instruction, which uses the registers we initialized earlier.

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
0x0000040a88 blk_40a88:
0x0000040a88              cbz        w0, #0x407ec
0x0000040a8c blk_40a8c:
0x0000040a8c              adrp       x8, #0xbd000
0x0000040a90              ldr        d0, [x8, #0x238]
0x0000040a94              adrp       x1, #0xfb000
0x0000040a98              adrp       x0, #0x43000
0x0000040a9c              adrp       x2, #0xf9000
0x0000040aa0              add        x1, x1, #0xab8
0x0000040aa4              mov        w8, #1
0x0000040aa8              mov        w9, #0x4385
0x0000040aac              add        x0, x0, #0x950
0x0000040ab0              add        x2, x2, #0
0x0000040ab4              strb       w8, [x1, #0xa]
0x0000040ab8              str        d0, [x1]
0x0000040abc              strh       w9, [x1, #8]
0x0000040ac0              bl         #0x37e10
0x0000040800 blk_40800:
 X8 => 0x00000000010fbab8    
0x0000040800              ldr        d0, [x8]
0x0000040804              ldrb       w10, [x8, #8]
0x0000040808              ldrb       w12, [x8, #9]
0x000004080c              ldr        d1, [x9, #0x230]
0x000004083c              mov        w2, #0x10
0x00000fbab8  30 78 34 38 34 37 31 36  38 00                    |0x4847168.      |
0x0000040840              mov        x1, xzr
Emulation done, range: 0x00000407e0 - 0x0000040844
```

We can see that because we previously hooked the address `0x0000040800` , so we can observe the value in the `X8` register at the time of execution to that address. And we can also observe the value of `0x00000fbab8` memory at the time of execution to the address `0x000004083c`.

​               

### Memory Read

In addition to the hook, you can also wait for the simulation to finish executing to read the value of some memory of interest.

```
>>> mem_read 0xFB560 0x19
0x00000fb560  43 68 65 63 6B 20 6F 76  65 72 6C 61 79 20 70 65  |Check overlay pe|
0x00000fb570  72 6D 69 73 73 69 6F 6E  00                       |rmission.       |
>>> mem_read 0xFBA88 0xa
0x00000fba88  30 78 34 34 34 39 44 34  34 00                    |0x4449D44.      |
>>> mem_read 0xFBAB8 0xa
0x00000fbab8  30 78 34 38 34 37 31 36  38 00                    |0x4847168.      |
```

Bingo! These memories on this example were originally placed with some encrypted strings, but after simulation execution now you can see the decrypted string in plaintext.

​              

### Memory Dump

If you need a large range of memory block data, you can also dump that memory into a file and then analyze them using other tools.

```
>>> mem_read 0xFBAB8 0x100000 --out dump_memory_FBAB8.bin
0x00000fbab8 - 0x00001fbab8 1048576 bytes have been saved to the file: dump_memory_FBAB8.bin
```

​                                

### Register Read

And you can also read some registers:

```
>>> reg_read sp pc
 SP => 0x0000000000810000     PC => 0x0000000001040844  
```

​        

Or you can simply read all the registers directly:

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
set stack_pointer 0x00010000+(8*1024*1024)
reg_write all 0
reg_write sp $stack_pointer
reg_read all

# patch code
set ret "C0 03 5F D6"
set nop "1F 20 03 D5"
mem_write 0x38550 $ret  # .__cxa_guard_acquire
mem_write 0x374F0 $ret  # .__cxa_guard_release
mem_write 0x37E10 $ret  # .__cxa_atexit
mem_write 0x40528 $nop
mem_write 0x40530 $nop
unset ret
unset nop

# hook address
hook_block 0x40800 reg_read X8
hook_code 0x4083c mem_read 0xFBAB8 0xa

# start emulation
reg_write all 0 sp $stack_pointer x24 0xFBD50
emu_start 0x3B98C 0x3B9A8
mem_read 0xFB560 0x19  # "Check overlay permission"

# start emulation
reg_write all 0 sp $stack_pointer X20 0xFBD50
emu_start 0x40674 0x406C4
mem_read 0xFBA88 0xa # "0x4449D44"

# start emulation
reg_write all 0 sp $stack_pointer
emu_start 0x4061C 0x4061C+8  # adrp x20, #0xfb000 | add x20, x20, #0xd50
emu_start 0x407E0 0x40844
mem_read 0xFBAB8 0xa  # "0x4847168"

# read registers and the memory of interest
reg_read sp pc
#reg_read all

unload all
exit
```

In fact, you can write a lot of commands to a script file, then load that file with the `script` command, and unicli will batch execute all the commands in that file together. 

​                    

Now you're a master of UniCli, have fun with hacking. And for more information you can just type `help`.