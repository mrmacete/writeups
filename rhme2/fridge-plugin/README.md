# Fridge vm architecture plugin

This is a quick and dirty implementation of a radare2 plugin for assembling, disassembling and doing basic analysis of the bytecode designed by Riscure for rhme2 challenges related to the fridge. I used it to solve FrigeJIT, Hide and Seek and The Weird Machine.

Mnemonic names are choosen arbitrarily by me, i hope they're self-explanatory.

Quick and dirty means all corner cases are not handled, and the assembler works well with well-formed code only.

## Building

```
make install
```

## Example

After building it, run it on the provided `fridge_code.bin` which is extracted from the memory dump of FridgeJIT: `r2 -a fridge fridge_code.bin`

![screenshot](sample.png)

This is the simple code i used to dump the data memory in Hide and Seek (included here in dumpmem.asm file):

```
MOVL R5, 0x0100

forever:

    XOR BS, BS
    XOR BS, R3
    LD R2, R0
    OUT R2
    ADD R3, R5
    JMP forever
```

You can assemble it and obtain the hex bytecode to use in the challenge like this:

```
$ rasm2 -a fridge -f dumpmem.asm
045001000a880a8306201c200835140001
```