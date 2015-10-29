Kwisatz Haderach's berkeley - mrmacete's solution
=================================================

Original challange is [here](http://crackmes.de/users/kwisatz_haderach/berkeley/).

I know this challange has been already solved by the great @acru3l, but i wanted to do it my way.

Identification
--------------

	# file berkeley 
		berkeley: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.26, BuildID[sha1]=89742e827532233ed6374b94e205dff08580594e, stripped
	
This is a 32 bit executable, i tested it successfully on my ubuntu bitch:
	
	# uname -a
		Linux pooper 3.19.0-25-generic #26-Ubuntu SMP Fri Jul 24 21:16:27 UTC 2015 i686 i686 i686 GNU/Linux


Reconnaissance with r2
----------------------

I'll try to reduce this section to the bone, here's the relevant lines in main():

	 0x08048648   mov dword [esp], 0x8049bc0
	 0x0804864f   call fcn.080485ac

Basically it calls a function passing a pointer to it. Let's see the core of the function:

	; following block is equivalent to:
	; sock = socket(AF_PACKET, SOCK_RAW, htons(3) )

	 0x080485af   sub esp, 0x38
	 0x080485b2   mov dword [esp], 3
	 0x080485b9   call sym.imp.htons
	 0x080485be   movzx eax, ax
	 0x080485c1   mov dword [esp + 8], eax
	 0x080485c5   mov dword [esp + 4], 3
	 0x080485cd   mov dword [esp], 0x11
	 0x080485d4   call sym.imp.socket

	 ; following block is equivalent to:
	 ; setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, arg_2, 8)

	 0x080485f5   mov dword [esp + 0x10], 8
	 0x080485fd   mov eax, dword [ebp+arg_2]
	 0x08048600   mov dword [esp + 0xc], eax
	 0x08048604   mov dword [esp + 8], 0x1a
	 0x0804860c   mov dword [esp + 4], 1
	 0x08048614   mov eax, dword [ebp-local_3]
	 0x08048617   mov dword [esp], eax
	 0x0804861a   call sym.imp.setsockopt


In order to find the proper values for constants in `socket()` call, after freaking out not finding them using google, i ended up using `grep` in `/usr/include`, like this:

1. where are the socket "domains" defined?
	
		mrmacete@pooper:/usr/include$ grep -r AF_INET * | grep "#define"
		i386-linux-gnu/bits/socket.h:#define AF_INET		PF_INET

2. where are the socket "types" defined?

		mrmacete@pooper:/usr/include$ grep -r SOCK_STREAM * | grep "#define"
		i386-linux-gnu/bits/socket_type.h:#define SOCK_STREAM SOCK_STREAM

3. where are the socket "protocols" defined? No answer, in fact i accepted to content myself with `htons(3)` for now.

Same procedure for constant names in the `setsockopt()` call:

1. where are "levels" defined?

		mrmacete@pooper:/usr/include$ grep -r SOL_SOCKET * | grep "#define"
		asm-generic/socket.h:#define SOL_SOCKET	1

It turns out also "optnames" are defined in the same file, fortunately.

Following the white rabbit
--------------------------

Well, what the hell is `SO_ATTACH_FILTER` ? This time i asked it directly to google, and the answer was this really interesting thing:

[https://www.kernel.org/doc/Documentation/networking/filter.txt](https://www.kernel.org/doc/Documentation/networking/filter.txt)

Apparently it's there since 1993, it's a compiled language (called BPF) to build packet filters from userland, letting the kernel apply them to raw sockets, but it seems used also for some type general purpose computation.

Here is how it is used in the crackme, in a nutshell:

1. Somewhere in the binary exist the filter array, i.e. the compiled filter code, expressed as an array of these structs:

```c
	struct sock_filter {	/* Filter block */
		__u16	code;   /* Actual filter code */
		__u8	jt;	/* Jump true */
		__u8	jf;	/* Jump false */
		__u32	k;      /* Generic multiuse field */
	};
```

2. using `setsockopt()`, this is bound to the socket of choice by passing a pointer to a struct of this type:

```c
	struct sock_fprog {			/* Required for SO_ATTACH_FILTER. */
		unsigned short		   len;	/* Number of filter blocks */
		struct sock_filter __user *filter;
	};
```
Interestingly at some point at that paper there's this snippet, which is almost the same of what found inside the crackme binary:

```c
	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock < 0)
		/* ... bail out ... */

	ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
	if (ret < 0)
		/* ... bail out ... */
```

This means we have a name for that disturbing `htons(3)` above!

In our case, the `sock_fprog` struct lives in the `arg_2`, at address `0x8049bc0`. Let's see it with r2:

	:> pxw 8 @ 0x8049bc0
	0x08049bc0  0x00000030 0x08049a40

So there are 48 `sock_filter` structs starting at `0x08049a40`, here they are:

	:> pxc 8*48 @ 0x08049a40
	- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
	0x08049a40  2800 0000 0c00 0000 1500 002d 0008 0000  (..........-....
	0x08049a50  3000 0000 1700 0000 1500 002b 1100 0000  0..........+....
	0x08049a60  2000 0000 1a00 0000 1500 0029 0100 a8c0   ..........)....
	0x08049a70  2800 0000 1400 0000 b100 0000 0e00 0000  (...............
	0x08049a80  4800 0000 1000 0000 1500 0025 f787 0000  H..........%....
	0x08049a90  4800 0000 0e00 0000 1500 0023 c843 0000  H..........#.C..
	0x08049aa0  4800 0000 1200 0000 1500 0021 2800 0000  H..........!(...
	0x08049ab0  4000 0000 1600 0000 0400 0000 1185 2415  @.............$.
	0x08049ac0  1400 0000 46e7 5776 1500 001d 0000 0000  ....F.Wv........
	0x08049ad0  4000 0000 1a00 0000 0400 0000 4864 7512  @...........Hdu.
	0x08049ae0  1400 0000 8095 ae73 1500 0019 0000 0000  .......s........
	0x08049af0  4000 0000 1e00 0000 0400 0000 1257 8843  @............W.C
	0x08049b00  1400 0000 47bb ea77 1500 0015 0000 0000  ....G..w........
	0x08049b10  4000 0000 2200 0000 0400 0000 8264 1197  @..."........d..
	0x08049b20  1400 0000 b5ca 47d0 1500 0011 0000 0000  ......G.........
	0x08049b30  4000 0000 2600 0000 0400 0000 4389 5571  @...&.......C.Uq
	0x08049b40  1400 0000 a9be 88a2 1500 000d 0000 0000  ................
	0x08049b50  4000 0000 2a00 0000 0400 0000 5386 4421  @...*.......S.D!
	0x08049b60  1400 0000 88ea 7d57 1500 0009 0000 0000  ......}W........
	0x08049b70  4000 0000 2e00 0000 0400 0000 2019 2300  @........... .#.
	0x08049b80  1400 0000 8252 5634 1500 0005 0000 0000  .....RV4........
	0x08049b90  4000 0000 3200 0000 0400 0000 8695 3471  @...2.........4q
	0x08049ba0  1400 0000 b7ca 66a1 1500 0001 0000 0000  ......f.........
	0x08049bb0  0600 0000 ffff 0000 0600 0000 0000 0000  ................

Now let's carve them out in a binary file by its own:

	:> pr 8*48 @ 0x08049a40 > bpf.bin

Disassembling BPF
-----------------

In the above cited kernel's doc resource, there is also mention to the bpf_dbg tool which is capable of disassembling compiled filters, let's go get it in my ubuntu bitch:

	$ apt-get linux-source
	$ apt-get install binutils-dev libreadline-dev bison flex 
	$ mkdir kernel
	$ tar xvf /usr/src/linux-source-3.19.0.tar.bz2
	$ cd linux-source-3.19.0/tools/net/
	$ make
	$ sudo make install

Now there's a shiny bpf_dbg executable, but first it is necessary to convert the binary dump to the funny comma separated integer tuple format, i made the [translate.py](translate.py) script to do exactly that:

	$ python translate.py bpf.bin 
	48,40 0 0 12,21 0 45 2048,48 0 0 23,21 0 43 17,32 0 0 26,21 0 41 3232235521,40 0 0 20,177 0 0 14,72 0 0 16,21 0 37 34807,72 0 0 14,21 0 35 17352,72 0 0 18,21 0 33 40,64 0 0 22,4 0 0 354714897,20 0 0 1985472326,21 0 29 0,64 0 0 26,4 0 0 309683272,20 0 0 1940821376,21 0 25 0,64 0 0 30,4 0 0 1133008658,20 0 0 2011872071,21 0 21 0,64 0 0 34,4 0 0 2534499458,20 0 0 3494365877,21 0 17 0,64 0 0 38,4 0 0 1901431107,20 0 0 2726870697,21 0 13 0,64 0 0 42,4 0 0 558138963,20 0 0 1467869832,21 0 9 0,64 0 0 46,4 0 0 2300192,20 0 0 878072450,21 0 5 0,64 0 0 50,4 0 0 1899271558,20 0 0 2707868343,21 0 1 0,6 0 0 65535,6 0 0 0

Let's disassemble it:

	$ bpf_dbg 
	> load bpf 48,40 0 0 12,21 0 45 2048,48 0 0 23,21 0 43 17,32 0 0 26,21 0 41 3232235521,40 0 0 20,177 0 0 14,72 0 0 16,21 0 37 34807,72 0 0 14,21 0 35 17352,72 0 0 18,21 0 33 40,64 0 0 22,4 0 0 354714897,20 0 0 1985472326,21 0 29 0,64 0 0 26,4 0 0 309683272,20 0 0 1940821376,21 0 25 0,64 0 0 30,4 0 0 1133008658,20 0 0 2011872071,21 0 21 0,64 0 0 34,4 0 0 2534499458,20 0 0 3494365877,21 0 17 0,64 0 0 38,4 0 0 1901431107,20 0 0 2726870697,21 0 13 0,64 0 0 42,4 0 0 558138963,20 0 0 1467869832,21 0 9 0,64 0 0 46,4 0 0 2300192,20 0 0 878072450,21 0 5 0,64 0 0 50,4 0 0 1899271558,20 0 0 2707868343,21 0 1 0,6 0 0 65535,6 0 0 0
	> disassemble

Before commenting the disassembly, a bit of context: 
	
* all addresses are offsets inside the raw packet
* ok but which packet? the root packet! here is assumed to be an [ETHERNET frame](https://en.wikipedia.org/wiki/Ethernet_frame)
* the main functionality and structure of the language are described in the kernel doc above, while the examples are poorly commented
* here is a resource with some commented examples, to let regular humans like me understand it (thanks ellzey!): [https://gist.github.com/ellzey/1111503](https://gist.github.com/ellzey/1111503)

Ok, this is the commented disassembly of the packet filter code:

	; load the ehtertype value out of the ethernet frame
	
	l0:		ldh [12]

	; it must be 0x800 to proceed, namely ipv4
	; see here: https://en.wikipedia.org/wiki/EtherType#Examples
	
	l1:		jeq #0x800, l2, l47

	; get the ip.protocol field (https://en.wikipedia.org/wiki/IPv4#Header)
	; yeah because 23 is 14 (the start of ip header in the ethernet frame)
	; plus 9

	l2:		ldb [23] ; ip[23-14] -> ip[9] ip.protocol field 

	; check if the protocol is UDP (https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)

	l3:		jeq #0x11, l4, l47

	; get the ip source address

	l4:		ld [26] ; ip[26-14] -> ip[12] ip source address

	; source ip must be 192.168.0.1 (note, it's big endian)

	l5:		jeq #0xc0a80001, l6, l47

	; the following instruction is apparently useless

	l6:		ldh [20]

	; load the start of UDP header (relative to start of ip header)
	; calculated as ip.IHL * 4 into X register

	l7:		ldxb 4*([14]&0xf)

	; get udp dest port at 14+x+2 (https://it.wikipedia.org/wiki/User_Datagram_Protocol)

	l8:		ldh [x+16]

	; dest port must be 34807

	l9:		jeq #0x87f7, l10, l47 ; destination port should be equal to 34807
	
	; get udp source port (14+x+0)

	l10:	ldh [x+14]

	; source port must be 17352

	l11:	jeq #0x43c8, l12, l47 ; origin port should be 17352

	; get udp length field

	l12:	ldh [x+18]

	; length must be 40 (head+payload)

	l13:	jeq #0x28, l14, l47 ; length = 40

	; payload constraints: the 32 bytes payload is checked
	; with constraint of type payload[x] + Y - Z = 0
	; therefore the payload value that passes the test
	; must be payload[x] = Z - Y
	; represented as unsigned 32 bits little endian

	l14:	ld [x+22]
	l15:	add #354714897
	l16:	sub #1985472326
	l17:	jeq #0, l18, l47
	l18:	ld [x+26]
	l19:	add #309683272
	l20:	sub #1940821376
	l21:	jeq #0, l22, l47
	l22:	ld [x+30]
	l23:	add #1133008658
	l24:	sub #2011872071
	l25:	jeq #0, l26, l47
	l26:	ld [x+34]
	l27:	add #-1760467838
	l28:	sub #-800601419
	l29:	jeq #0, l30, l47
	l30:	ld [x+38]
	l31:	add #1901431107
	l32:	sub #-1568096599
	l33:	jeq #0, l34, l47
	l34:	ld [x+42]
	l35:	add #558138963
	l36:	sub #1467869832
	l37:	jeq #0, l38, l47
	l38:	ld [x+46]
	l39:	add #2300192
	l40:	sub #878072450
	l41:	jeq #0, l42, l47
	l42:	ld [x+50]
	l43:	add #1899271558
	l44:	sub #-1587098953
	l45:	jeq #0, l46, l47

	; reaching this means ACCEPT packet
	l46:	ret #0xffff

	; DROP the packet

	l47:	ret #0

Defeating the crackme using nping
---------------------------------

Here is the python code to generate the payload string, using the constants derived as described above:

	import binascii
	
	with open("payload.txt", "w") as f:
		payload = binascii.unhexlify("%x%x%x%x%x%x%x%x" % (1630757429,1631138104,878863413,959866419,825439590,909730869,875772258,808596785))
		f.write(payload)


In order to try it out, let's spawn the binary in one terminal:

	# ./berkeley 
		[+] Transmission channel inited! Waiting for connections ...


then in another terminal let's use nping (https://nmap.org/book/nping-man.html) to send the crafted packet:

	$ nping --send-eth -S 192.168.0.1 --dest-ip 127.0.0.1 --udp -g 17352 -p 34807 --data-string a3b5a9184bd596f3135f69d5439b0251 -e eth0

And see it congratulate us in the first terminal:

	[+] Good job!

As a side note, the nping util is part of the nmap package, on ubuntu get it using `apt-get install nmap`


External references
-------------------

Here are again all the resources i found which are helpful to understand all of the above:

https://www.kernel.org/doc/Documentation/networking/filter.txt

https://gist.github.com/ellzey/1111503

https://en.wikipedia.org/wiki/Ethernet_frame

https://en.wikipedia.org/wiki/EtherType#Examples

https://en.wikipedia.org/wiki/IPv4#Header

https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

https://it.wikipedia.org/wiki/User_Datagram_Protocol

https://nmap.org/book/nping-man.html



