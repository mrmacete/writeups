GTKSOR's 1337_ARM - mrmacete's solution
---------------------------------------

1. Identification of executable
-------------------------------

    $ file 1337ARM.bin 
      1337ARM.bin: ELF 32-bit LSB executable, ARM, version 1 (SYSV), statically linked, for GNU/Linux 2.6.16, not stripped
  
    $ shasum 1337ARM.bin 
      df1c6ae68a3b35144a445b114e9ea25f90d5a577  1337ARM.bin


2. Running the executable
-------------------------

This time i literally followed the instructions provided by:

https://developer.mozilla.org/en-US/docs/Mozilla/Developer_guide/Virtual_ARM_Linux_environment

and managed to get an ubuntu-arm distro from Linaro running inside qemu (macos version, installed using brew):

    $ qemu-system-arm -M vexpress-a9 -cpu cortex-a9 -kernel ./vmlinuz -initrd ./initrd.img -redir tcp:2200::22 -m 512 -append "root=/dev/mmcblk0p2 vga=normal mem=512M devtmpfs.mount=0 rw" -drive file=vexpress.img,if=sd,cache=writeback


The only missing thing was strace, easily installed with the command:

    root@linaro-ubuntu-desktop:~# apt-get install strace

Ah, another thing: this ubuntu's default root password is "root".


3. Static analisys
------------------

Radare2 opens this binary quite smoothly:

    $ r2 1337ARM.bin 
    Warning: Cannot initialize dynamic section
     -- ♥ --
    [0x00008150]> aaa
    Function too big at 0x661a4
    Function at 0xf484 was not analyzed
    
    [0x00008150]> s main
    [0x00008290]> VVV

The VVV command directly spawns the function graph, from which the ascii art below is directly copy-pasted ;)

If you get lost, just press the usual ? key and get the help:

    Visual Ascii Art graph keybindings:
     .      - center graph to the current node
     !      - toggle scr.color
     hjkl   - move node
     HJKL   - scroll canvas
     tab    - select next node
     TAB    - select previous node
     t/f    - follow true/false edges
     e      - toggle edge-lines style (diagonal/square)
     O      - toggle disasm mode
     r      - relayout
     R      - randomize colors
     o      - go/seek to given offset
     u/U    - undo/redo seek
     p      - toggle mini-graph
     b      - select previous node
     V      - toggle basicblock / call graphs
     w      - toggle between movements speed 1 and graph.scroll
     x/X    - jump to xref/ref
     z/Z    - step / step over
     +/-/0  - zoom in/out/default

Ok, let's examine the main() function.

The first thing the main() does, is to allocate an array of 8 arrays on the heap, each one to contain 32 chars, filling them with the value 0xa:

      ; local variables legenda
      ;   -0x1c: counter
      ;   -0x20: outer array (8 pointers)
      
                                      =----------------------=          
                                      |  0x82c0              |          
                                      | mov r3, 0            |          
                                      | str r3, [fp, -0x1c]  |          
                                      | mov r0, 0x20         |          
                                      | bl sym.xmalloc       |          
                                      | mov r3, r0           |           
                                      | str r3, [fp, -0x20]  |           
                                      | b 0x832c             |           
                                      =----------------------=           
                                          v                              
                                      .---'                              
                                      |                                  
                                      |                                  
                                  =---------------------=                
                                  |  0x832c             |                
                                  | ldr r3, [fp, -0x1c] |                
                                  | cmp r3, 8           |                
                                  | bne 0x82dc          |                
                                  =---------------------=                
                                      | t f                              
              .-----------------------|-' '-------------.                
              |                       |                 |                
              |                       |                 |                
        =----------------------=      |         =----------------------= 
        |  0x82dc              |      |         | [0x8338]             | 
        | ldr r3, [fp, -0x1c]  |      |         | ldr r3, [fp, -0x1c]  | 
        | lsl r2, r3, 2        |      |         | lsl r2, r3, 2        | 
        | ldr r3, [fp, -0x20]  |      |         | ldr r3, [fp, -0x20]  | 
        | add r4, r3, r2       |      |         | add r2, r3, r2       | 
        | mov r0, 0x20         |      |         | mov r3, 0            | 
        | bl sym.xmalloc       |      |         | str r3, [r2]         | 
        | mov r3, r0           |      |         | mov r3, 0            | 
        | str r3, [r4]         |      |         | str r3, [fp, -0x1c]  | 
        | ldr r3, [fp, -0x1c]  |      |         | mov r3, 0x41         | 
        | lsl r2, r3, 2        |      |         | str r3, [fp, -0x18]  | 
        | ldr r3, [fp, -0x20]  |      |         | b 0x839c             | 
        | add r3, r3, r2       |      |         =----------------------= 
        | ldr r3, [r3]         |      |             v                    
        | mov r0, r3           |      |             |                    
        | mov r1, 0xa          |      |             |                    
        | mov r2, 0x20         |      |             |                    
        | bl sym.memset        |      |             |                    
        | ldr r3, [fp, -0x1c]  |      |             |                    
        | add r3, r3, 1        |      |    .--------'                    
        | str r3, [fp, -0x1c]  |      |    |                             
        =----------------------=      |    |                             
            `-------------------------'    |                             
                                           |                             

Only one of these arrays (the fourth) is initialized with a sequence of chars, starting with 0x41 (see the block [0x8338] above) and continuing with the following character codes, resulting in the string:

'ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`'

Here is the generator loop:

    ; local variables legenda:
    ;   -0x1c: counter
    ;   -0x20: outer array (8 pointers)
    ;   -0x18: increasing char, initialised with 0x41
    
                          =---------------------=                     
                          |  0x839c             |                     
                          | ldr r3, [fp, -0x1c] |                     
                          | cmp r3, 0x1f        |                     
                          | bne 0x8364          |                     
                          =---------------------=                     
                              | t f                                   
           .------------------|-' |                                   
           |                  |   |                                   
           |                  |   |                                   
     =----------------------= |   '------------------.                
     |  0x8364              | |                      |                
     | ldr r3, [fp, -0x20]  | |                      |                
     | add r3, r3, 0xc      | |                      |                
     | ldr r2, [r3]         | |                      |                
     | ldr r3, [fp, -0x1c]  | |              =----------------------= 
     | add r2, r2, r3       | |              | [0x83a8]             | 
     | ldr r3, [fp, -0x18]  | |              | ldr r3, [fp, -0x20]  | 
     | and r3, r3, 0xff     | |              | add r3, r3, 0xc      | 
     | strb r3, [r2]        | |              | ldr r2, [r3]         | 
     | ldr r3, [fp, -0x18]  | |              | ldr r3, [fp, -0x1c]  | 
     | add r3, r3, 1        | |              | add r2, r2, r3       | 
     | str r3, [fp, -0x18]  | |              | mov r3, 0            | 
     | ldr r3, [fp, -0x1c]  | |              | strb r3, [r2]        | 
     | add r3, r3, 1        | |              | mov r3, 0            | 
     | str r3, [fp, -0x1c]  | |              | str r3, [fp, -0x1c]  | 
     =----------------------= |              | b 0x8420             | 
         `--------------------'              =----------------------= 



This is the core of the checking function, which compares all the chars given in argv[1] with the ones found in the preloaded string, in the same order:

    ; local variables legenda
    ;   -0x2c:  argv
    ;   -0x1c:  counter
    ;   -0x20:  outer array (8 pointers)
    ;   -0x30:  return value
    
                         =----------------------=                    
                         | [0x8420]             |                    
                         | ldr r3, [fp, -0x2c]  |                    
                         | add r3, r3, 4        |                    
                         | ldr r2, [r3]         |                    
                         | ldr r3, [fp, -0x1c]  |                    
                         | add r3, r2, r3       |                    
                         | ldrb r3, [r3]        |                    
                         | cmp r3, 0            |                    
                         | bne 0x83d0           |                    
                         =----------------------=                    
                               t f   |                               
             .-----------------' '---|------------.                  
             |                       |            |                  
             |                       |            |                  
       =----------------------=      |    =----------------------=   
       |  0x83d0              |      |    |  0x8440              |   
       | ldr r3, [fp, -0x2c]  |      |    | ldr r3, [pc, 0x10]   |   
       | add r3, r3, 4        |      |    | str r3, [fp, -0x30]  |   
       | ldr r2, [r3]         |      |    =----------------------=   
       | ldr r3, [fp, -0x1c]  |      |        v                      
       | add r3, r2, r3       |      |        |                      
       | ldrb r1, [r3]        |      |        |                      
       | ldr r3, [fp, -0x20]  |      |        |                      
       | add r3, r3, 0xc      |      |        |                      
       | ldr r2, [r3]         |      |        |                      
       | ldr r3, [fp, -0x1c]  |      |        |                      
       | add r3, r2, r3       |      |        '-------------------.  
       | ldrb r3, [r3]        |      |                            |  
       | cmp r1, r3           |      |                            |  
       | beq 0x8414           |      |                            |  
       =----------------------=      |                            |  
               f t                   |                            |  
              .' '-------------------|----.                       |  
              |                      |    |                       |  
              |                      |    |                       |  
      =----------------------=      =----------------------=      |  
      |  0x8408              |      || 0x8414              |      |  
      | mvn r3, 0            |      ||ldr r3, [fp, -0x1c]  |      |  
      | str r3, [fp, -0x30]  |      ||add r3, r3, 1        |      |  
      | b 0x8448             |      ||str r3, [fp, -0x1c]  |      |  
      =----------------------=      =----------------------=      |  
          v                          `--'                         |  
          '-------------------------------.-----------------------+
                                          |
                                          |
                                      =---------------------------=
                                      |  0x8448                   |
                                      | ldr r3, [fp, -0x30]       |
                                      | mov r0, r3                |
                                      | sub sp, fp, 0x10          |
                                      | ldm sp, {r4, fp, sp, pc}  |
                                      =---------------------------=


If the argv[1] string ends and all its chars was contained at the same position inside the preloaded string, the success is triggered:

The instruction:
  
    0x8440 ldr r3, [pc, 0x10]

is responsible for loading the 1337 as the return value for main(), let's check it with r2:

    :> pxw 4@0x8440+8+16
    0x00008458  0x00000539

actually 0x539 is the hex for 1337. In all other cases main() will return 0.

Therefore the accepted passwords are all the starting subsequences of the preloaded string, for example:

    A
    AB
    ABC

etc...

4. Dynamic analisys
-------------------

Despite what the author told in the description of the crackme, it doesn't appear to print anything at all, instead the value 1337 is returned from the main() function and passed to the exit() call. The problem here is that since the return value is always cropped to the least significant byte, 1337 is transformed to 57 (1337 & 0xff) and that is what bash will tell us using `echo $?`.

To see it more clearly, is fun to look at strace output during a couple of runs:

    root@linaro-ubuntu-desktop:~# strace ./1337ARM.bin A
      execve("./1337ARM.bin", ["./1337ARM.bin", "A"], [/* 19 vars */]) = 0
      uname({sys="Linux", node="linaro-ubuntu-desktop", ...}) = 0
      brk(0)                                  = 0xc7a000
      brk(0xc7ace0)                           = 0xc7ace0
      set_tls(0xc7a4a0, 0x83fc4, 0, 0x1, 0xc7a4a0) = 0
      brk(0xc9bce0)                           = 0xc9bce0
      brk(0xc9c000)                           = 0xc9c000
      exit_group(1337)                        = ?
    
    
    root@linaro-ubuntu-desktop:~# strace ./1337ARM.bin AB
      execve("./1337ARM.bin", ["./1337ARM.bin", "AB"], [/* 19 vars */]) = 0
      uname({sys="Linux", node="linaro-ubuntu-desktop", ...}) = 0
      brk(0)                                  = 0x1d3f000
      brk(0x1d3fce0)                          = 0x1d3fce0
      set_tls(0x1d3f4a0, 0x83fc4, 0, 0x1, 0x1d3f4a0) = 0
      brk(0x1d60ce0)                          = 0x1d60ce0
      brk(0x1d61000)                          = 0x1d61000
      exit_group(1337)                        = ?
    
    root@linaro-ubuntu-desktop:~# strace ./1337ARM.bin MORTE
      execve("./1337ARM.bin", ["./1337ARM.bin", "MORTE"], [/* 19 vars */]) = 0
      uname({sys="Linux", node="linaro-ubuntu-desktop", ...}) = 0
      brk(0)                                  = 0x5a8000
      brk(0x5a8ce0)                           = 0x5a8ce0
      set_tls(0x5a84a0, 0x83fc4, 0, 0x1, 0x5a84a0) = 0
      brk(0x5c9ce0)                           = 0x5c9ce0
      brk(0x5ca000)                           = 0x5ca000
      exit_group(-1)                          = ?

The first two runs are valid passwords, while the last one not.

5. Solution and "keygen"
------------------------

This is the solution, which is a python one-liner printing all valid passwords:

    print '\n'.join([''.join([chr(0x41+i) for i in xrange(j)]) for j in xrange(1,32)])

Beware that the above code doesn't escape the backslash char, so keep it in mind when pasting to bash, for example the password:

    ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_

must be escaped like this in order to work on the command line:

    root@linaro-ubuntu-desktop:~# ./1337ARM.bin ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_
