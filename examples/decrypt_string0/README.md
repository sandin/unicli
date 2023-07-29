# Crack string encryption using unicli

In this article, we will use a real-life sample to demonstrate how to use unicli to crack an encrypted string algorithm. 

This sample is a dynamic library for the android arm64 architecture, We'll just call it `libdemo.so`. Most of the strings in this dynamic library are encrypted, and it is not possible to directly look up the strings and locate the critical assembly code with tools such as idapro.

First of all, it is generally preferred to assume that the string decryption process takes place inside `.init_array`, so let's take a look at the list of functions in `.init_array` inside this so follow:

```assembly
.init_array:00000000000F39B0 ; ELF Initialization Function Table
.init_array:00000000000F39B0 ; ===========================================================================
.init_array:00000000000F39B0
.init_array:00000000000F39B0 ; Segment type: Pure data
.init_array:00000000000F39B0                 AREA .init_array, DATA, ALIGN=3
.init_array:00000000000F39B0                 ; ORG 0xF39B0
.init_array:00000000000F39B0 off_F39B0       DCQ sub_411D8           ; DATA XREF: LOAD:0000000000000088↑o
.init_array:00000000000F39B0                                         ; LOAD:00000000000001D8↑o
.init_array:00000000000F39B8                 DCQ sub_385AC
.init_array:00000000000F39C0                 DCQ loc_38BE4
.init_array:00000000000F39C0 ; .init_array   ends
.init_array:00000000000F39C0
.fini_array:00000000000F39C8 ; ELF Termination Function Table
```

We can see that there are 3 functions inside `.init_array`, we examined these 3 functions separately and found that the assembly inside the 2nd function looks very much like a string decryption logic. Let's take a look at the disassembled code within this function:

```c++
void sub_385AC()
{
  // ...
	v0 = atomic_load((unsigned __int8 *)qword_FBDC0);
  if ( (v0 & 1) == 0 && __cxa_guard_acquire(qword_FBDC0) )
  {
    dword_FB2A0 = 493179568;
    qword_FB298 = 0xFE75B244D4BDD4ACLL;
    word_FB2A4 = 26055;
    unk_FB2A7 = xmmword_BDA80;
    byte_FB2A6 = -121;
    unk_FB2B7 = 0x8855C50971534017LL;
    unk_FB2BF = 391;
    __cxa_atexit((void (__fastcall *)(void *))sub_423BC, &qword_FB298, &off_F9000);
    __cxa_guard_release(qword_FBDC0);
  }
  sub_43C24((__int64)&qword_FB298);
  qword_F9128 = (__int64)&qword_FB298;
	// ...
}

int8x16_t __fastcall sub_43C24(__int64 a1)
{
	// ...
  if ( *(_BYTE *)(a1 + 40) )
  {
    v1 = *(int8x16_t *)a1;
    v2 = *(int8x16_t *)(a1 + 16);
    v3.n64_u64[0] = *(unsigned __int64 *)(a1 + 32);
    *(_BYTE *)(a1 + 40) = 0;
    result = veorq_s8(v1, (int8x16_t)xmmword_BD8B0);
    *(int8x16_t *)a1 = result;
    *(int8x16_t *)(a1 + 16) = veorq_s8(v2, (int8x16_t)xmmword_BD8B0);
    *(int8x8_t *)(a1 + 32) = veor_s8(v3, (int8x8_t)0x8707DD23B1C9B5EFLL);
  }
  return result;
}
```

From the disassembled code, we can almost confirm that this is the logic for a decrypted string. Now let's start using unicli to simulate the execution of this code to verify our suspicions.

​                  

## Load Memory

For convenience, I saved some part of the `.text` and `.rodata` segments inside the `libdemo.so`, and put them in the examples directory so you can use them to reproduce the process of this article.

Now we use unicli to load that memory in for execution. They were as follows:

```
.text   0x00000385ac - 0x0000038c04
.text   0x0000043000 - 0x0000046000
.rodata 0x00000bce50 - 0x00000bdc00
```

Unicli can support loading these scattered chunks of memory into unicorn's virtual memory according to their offsets. This mechanism allows you to dump several chunks of memory from an ELF file or directly from the runtime debugger, and then load them into unicli for offline analysis.

```
>>> load examples/decrypt_string0/text_385AC.bin --format raw --arch arm64 --base 0x02000000 --offset 0x385AC
Map memory reserve address space [0x2038000 - 0x2039000]
Map memory from file [0x0 - 0x658] to virtual memory [0x20385ac - 0x2038c04]
Successfully loaded module: /Users/san/project/python/unicli/examples/decrypt_string0/text_385AC.bin

>>> load examples/decrypt_string0/text_43000.bin --format raw --arch arm64 --base 0x02000000 --offset 0x43000
Map memory reserve address space [0x2043000 - 0x2046000]
Map memory from file [0x0 - 0x3000] to virtual memory [0x2043000 - 0x2046000]
Successfully loaded module: /Users/san/project/python/unicli/examples/decrypt_string0/text_43000.bin

>>> load examples/decrypt_string0/rodata_BCE50.bin --format raw --arch arm64 --base 0x02000000 --offset 0xBCE50
Map memory reserve address space [0x20bc000 - 0x20be000]
Map memory from file [0x0 - 0xdb0] to virtual memory [0x20bce50 - 0x20bdc00]
Successfully loaded module: /Users/san/project/python/unicli/examples/decrypt_string0/rodata_BCE50.bin
```

We can see that unicli maps the memory in the file to virtual memory according to the offsets, so that we have the same memory layout as at normal runtime.

In addition to the `.text` segment, the code we're about to run requires the `.plt` and `.bss` segments, so we're also mapping these blocks of memory to virtual memory.

```
>>> mem_map 0x02000000+0x36E00 0x385A0-0x36E00  # .plt segment
0x0002036000 - 0x0002038000 rwx

>>> mem_map 0x02000000+0xF9110 0xFDC90-0xF9110  # .bss segment
0x00020f9000 - 0x00020fe000 rwx
```

Our code needs to read some global variables from `.bss` and will write some data to those global variables. Here we just need to initialize them to 0.

​              

## Patch Code


The `.plt` segment is mainly used to call import functions, which we are not going to call, but just turn it into a dummy function and return it. For example, these functions in the `.plt` segment looked like this:

```assembly
.plt:0000000000038550 ; int __fastcall __cxa_guard_acquire(__guard *)
.plt:0000000000038550 .__cxa_guard_acquire                    ; CODE XREF: sub_385AC:loc_38814↓p
.plt:0000000000038550                                         ; sub_385AC:loc_3888C↓p ...
.plt:0000000000038550                 ADRP            X16, #__cxa_guard_acquire_ptr@PAGE
.plt:0000000000038554                 LDR             X17, [X16,#__cxa_guard_acquire_ptr@PAGEOFF]
.plt:0000000000038558                 ADD             X16, X16, #__cxa_guard_acquire_ptr@PAGEOFF
.plt:000000000003855C                 BR              X17
```

We simply use unicli to patch these functions:

```
>>> mem_write 0x38550 $ret  # .__cxa_guard_acquire
0x0000038550  C0 03 5F D6                                       |.._.            |

>>> mem_write 0x374F0 $ret  # .__cxa_guard_release
0x00000374f0  C0 03 5F D6                                       |.._.            |

>>> mem_write 0x37E10 $ret  # .__cxa_atexit
0x0000037e10  C0 03 5F D6                                       |.._.            |
```

After we patch, these functions will look like the following:

```assembly
.plt:0000000000038550 ; int __fastcall __cxa_guard_acquire(__guard *)
.plt:0000000000038550 .__cxa_guard_acquire                    ; CODE XREF: sub_385AC:loc_38814↓p
.plt:0000000000038550                                         ; sub_385AC:loc_3888C↓p ...
.plt:0000000000038550                 ret
```

This will have no effect when these import functions are called, since we are not going to implement such functions, and whether they are called or not does not affect the outcome of our execution.

​             

## Registers & Stack

We are going to simulate the execution of a function inside `.init_array`, so we need to initialize all the registers and stack memory before executing it.

First let's map a chunk of memory and use it as stack memory.

```
>>> mem_map 0x00010000 8*1024*1024
0x0000010000 - 0x0000810000 rwx

>>> set sp 0x00010000+(8*1024*1024)
set sp = 0x00010000+(8*1024*1024)
```

For convenience, we save the value of the `sp` register to a local variable, then we can use it to set the register.

```
>>> reg_write all 0 sp $sp
 X0 => 0x0000000000000000     X1 => 0x0000000000000000    
 X2 => 0x0000000000000000     X3 => 0x0000000000000000    
 X4 => 0x0000000000000000     X5 => 0x0000000000000000    
 X6 => 0x0000000000000000     X7 => 0x0000000000000000    
 X8 => 0x0000000000000000     X9 => 0x0000000000000000    
 X8 => 0x0000000000000000     X9 => 0x0000000000000000    
X10 => 0x0000000000000000    X11 => 0x0000000000000000    
X12 => 0x0000000000000000    X13 => 0x0000000000000000    
X14 => 0x0000000000000000    X15 => 0x0000000000000000    
X16 => 0x0000000000000000    X17 => 0x0000000000000000    
X18 => 0x0000000000000000    X19 => 0x0000000000000000    
X20 => 0x0000000000000000    X21 => 0x0000000000000000    
X22 => 0x0000000000000000    X23 => 0x0000000000000000    
X24 => 0x0000000000000000    X25 => 0x0000000000000000    
X26 => 0x0000000000000000    X27 => 0x0000000000000000    
X28 => 0x0000000000000000     FP => 0x0000000000000000    
 LR => 0x0000000000000000     SP => 0x0000000000000000    
 PC => 0x0000000000000000     SP => 0x0000000000810000   
```

This command actually has two steps:

* step 1, `reg_write all 0`, we initialize all the registers to 0 first.
* step 2, `reg_write sp $sp`, we set the `sp` register using the previously saved local variable, it points to the memory we just mapped.

​                

## Start Emulation

Now that all the preparations are done, we can start simulating the execution, we will follow the simulated execution of unicli and analyze this assembly code block by block to try to understand the specific algorithm of this string encryption.

```assembly
Start emulation, range: 0x00000385ac - 0x0000038810
0x00000385ac blk_385ac:
0x00000385ac              stp        x21, x20, [sp, #-0x20]!
0x00000385b0              stp        x19, x30, [sp, #0x10]
0x00000385b4              adrp       x21, #0xfb000
0x00000385b8              add        x21, x21, #0xd50
0x00000385bc              add        x0, x21, #0x70
0x00000385c0              ldarb      w8, [x0]
0x00000385c4              tbz        w8, #0, #0x38814
```

First, it reads the value of a global variable from the `.bss` segment at `0xfb000 + 0xd50 + 0x70`, and then determines if it is `0`. If it is `0`, it jumps to the block at `0x38814`, whereas the `0` means the encrypted string has not been initialized in the `.bss` segment, it need to jump to the next branch to do the initialization, note that after initialization the string is still ciphertext, it also needs to call the decryption function of another string to decrypt it. Let's follow the simulation execution to see the process of initializing the ciphertext.

​                 

```assembly
0x0000038814 blk_38814:
0x0000038814              bl         #0x38550      ; .__cxa_guard_acquire
0x0000038550 blk_38550:
0x0000038550              ret                      ; patch
0x0000038818 blk_38818:
0x0000038818              cbz        w0, #0x385c8
```

Inside the `blk_38814` block, it first calls an import function called `__cxa_guard_acquire`, and since we've patched that function before, it will just return when it's called.  

​         

```assembly
0x000003881c blk_3881c:
0x000003881c              adrp       x8, #0xbd000
0x0000038820              ldr        d0, [x8, #0x3a0]     ; .rodata 0xbd3a0 AC D4 BD D4 44 B2 75 FE
0x0000038824              adrp       x1, #0xfb000
0x0000038828              mov        w8, #0x52b0
0x000003882c              add        x1, x1, #0x298       ; x1 = .bss 0xfb298 
0x0000038830              movk       w8, #0x1d65, lsl #16 ; w8 = 0x1d6552b0
0x0000038834              str        w8, [x1, #8]         ; .bss 0xfb298+0x8 <= b0 52 65 1D
0x0000038838              adrp       x8, #0xbd000         
0x000003883c              str        d0, [x1]             ; .bss 0xfb298 <= AC D4 BD D4 44 B2 75 FE
0x0000038840              ldr        q0, [x8, #0xa80]     ; .rodata 0xbda80 61 43 14 2C 21 8C 38 8D  2F 07 1A 7E 58 A4 50 E2
0x0000038844              mov        w8, #0x65c7
0x0000038848              strh       w8, [x1, #0xc]       ; .bss 0xfb298+0xc <= C7 65
0x000003884c              adrp       x8, #0xbd000
0x0000038850              stur       q0, [x1, #0xf]       ; .bss 0xfb298+0xf <= 61 43 14 2C 21 8C 38 8D  2F 07 1A 7E 58 A4 50 E2
0x0000038854              ldr        d0, [x8, #0x3a8]     ; .rodata 0xbd3a8 17 40 53 71 09 C5 55 88
0x0000038858              mov        w8, #0x87            ;
0x000003885c              adrp       x0, #0x42000
0x0000038860              adrp       x2, #0xf9000
0x0000038864              strb       w8, [x1, #0xe]       ; .bss 0xfb298+0xe <= 87
0x0000038868              mov        w8, #0x187
0x000003886c              add        x0, x0, #0x3bc
0x0000038870              add        x2, x2, #0
0x0000038874              stur       d0, [x1, #0x1f]      ; .bss 0xfb298+0x1f <= 17 40 53 71 09 C5 55 88
0x0000038878              sturh      w8, [x1, #0x27]      ; .bss 0xfb298+0x27 <= 87 01
0x000003887c              bl         #0x37e10           ; .__cxa_atexit
0x0000037e10 blk_37e10:
0x0000037e10              ret                           ; patch
0x0000038880 blk_38880:
0x0000038880              add        x0, x21, #0x70
0x0000038884              bl         #0x374f0
0x00000374f0 blk_374f0:
0x00000374f0              ret        
0x0000038888 blk_38888:
0x0000038888              b          #0x385c8
```

The block is a bit long, its using some data from the `.rodata` segement and stack to construct an encrypted string ciphertext, and save it to a global variable in the `.bss` segment.  The start address of this string is `0xfb298` and its length is `0x28`. The memory at this address will be the target of our next focus.

After the execution of this block, this memory currently holds the ciphertext of the encrypted string, we can use unicli to print the bytes of this memory first when the simulation reaches `0x3887c`, which is as follows:

```assembly
>>> hook_code 0x3887c mem_read 0xFB298 0x29
0x000003887c              bl         #0x37e10    ; .__cxa_atexit
0x00000fb298  AC D4 BD D4 44 B2 75 FE  B0 52 65 1D C7 65 87 61  |....D.u..Re..e.a|
0x00000fb2a8  43 14 2C 21 8C 38 8D 2F  07 1A 7E 58 A4 50 E2 17  |C.,!.8./..~X.P..|
0x00000fb2b8  40 53 71 09 C5 55 88 87  01                       |@Sq..U...       |
```

​            

The code then jumps to block `0x385c8`, which is another branch for conditional jumps in the first block.

```assembly
0x00000385c8 blk_385c8:
0x00000385c8              adrp       x19, #0xfb000
0x00000385cc              add        x19, x19, #0x298    ; 0xfb298
0x00000385d0              mov        x0, x19
0x00000385d4              bl         #0x43c24
```

In this block, we see that it's calling another function and passing the string of the ciphertext we just constructed in `.bss` as the 1st parameter, which we guess is the function that decrypts that string. Let's take a look.

```assembly
0x0000043c24 blk_43c24:
0x0000043c24              ldrb       w8, [x0, #0x28]
0x0000043c28              cbz        w8, #0x43c5c
0x0000043c2c blk_43c2c:
0x0000043c2c              adrp       x8, #0xbd000
0x0000043c30              ldr        q3, [x8, #0x8b0] ; .rodata 0xbd8b0   EF B5 C9 B1 23 DD 07 87  EF B5 C9 B1 23 DD 07 87
0x0000043c34              adrp       x8, #0xbd000
0x0000043c38              ldp        q0, q1, [x0]     ; q0 = 0xbd8b0+0x00 AC D4 BD D4 44 B2 75 FE  B0 52 65 1D C7 65 87 61
																											; q1 = 0xbd8b0+0x10 43 14 2C 21 8C 38 8D 2F  07 1A 7E 58 A4 50 E2 17
0x0000043c3c              ldr        d2, [x0, #0x20]  ; d2 = 0xbd8b0+0x20 40 53 71 09 C5 55 88 87
0x0000043c40              ldr        d4, [x8, #0x328] ; .rodata 0xbd328   EF B5 C9 B1 23 DD 07 87
0x0000043c44              strb       wzr, [x0, #0x28] ; .rodata 0xFB298+0x28 <= 00
0x0000043c48              eor        v0.16b, v0.16b, v3.16b  ;  q0 = q0 ^ q3
0x0000043c4c              eor        v1.16b, v1.16b, v3.16b  ;  q1 = q1 ^ q3
0x0000043c50              eor        v2.8b, v2.8b, v4.8b     ;  d2 = d2 ^ d4
0x0000043c54              stp        q0, q1, [x0]
0x0000043c58              str        d2, [x0, #0x20]
0x0000043c5c              ret      
```

Note that this function is relatively far away from its caller's function address, which is why we need to map two .text segments of memory in the first place, since we don't care about all that code in between.

In this decrypted string function, it first reads the last byte of the string and determines whether the byte is `0`. If it is `0`, it means that the string has been decrypted and just return, while if it is not `0`, it needs to jump to the next block to decrypt this string.

As we can see from the assembly code, the logic for decrypting the string is to perform `eor` operations with the ciphertext we just constructed in the `.bss` segment and a secret key in the `.rodata` segment.

```
ciphertext = AC D4 BD D4 44 B2 75 FE  B0 52 65 1D C7 65 87 61
						 43 14 2C 21 8C 38 8D 2F  07 1A 7E 58 A4 50 E2 17
						 40 53 71 09 C5 55 88 87
secretkey	 = EF B5 C9 B1 23 DD 07 87  EF B5 C9 B1 23 DD 07 87
             EF B5 C9 B1 23 DD 07 87  EF B5 C9 B1 23 DD 07 87
						 EF B5 C9 B1 23 DD 07 87
plaintext  = ciphertext ^ secretkey
```

In addition to the eor operation, the last byte of the string must be set to 0 to indicate that the string has been decrypted.

After the simulation is complete, we can view the contents of the decrypted memory by using the `mem_read` command.

```
>>> mem_read 0xFB298 0x28
0x00000fb298  43 61 74 65 67 6F 72 79  5F E7 AC AC E4 B8 80 E6  |Category_.......|
0x00000fb2a8  AC A1 E5 90 AF E5 8A A8  E8 AF B7 E9 87 8D E5 90  |................|
0x00000fb2b8  AF E6 B8 B8 E6 88 8F 00                           |........        |
```

Following the execution of the unicli simulation, we now not only see the plaintext of the decrypted string, but we also fully understand the algorithm for decrypting that string, no more secrets.



