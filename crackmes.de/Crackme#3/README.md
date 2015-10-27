#S!x0r's Crackme#3 - mrmacete's solution

The original challange is [here](http://crackmes.de/users/sx0r/crackme3_by_sx0r/)

Identification
--------------

	# file Crackme3 
		Crackme3: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, stripped
	
	# sha1sum Crackme3 
		06db7ba0dfd10d95f0bb043b38741720f6977025  Crackme3


Analyzing entry point
---------------------

This crackme is written directly in assembly, so the interesting code starts immediately at the entry point. Here is the entry point code along with my comments. I renamed the functions in radare2 (in visual mode, press '_' and then "rename function") in order to make this more readable:

	; print welcome message
	
	0x08048080   mov ecx, str.Crackme3_by_S_x0r_n_nUsername:
	0x08048085   mov edx, 0x13
	0x0804808a   call puts
	
	
	; ask username
	
	0x0804808f   mov ecx, 0x804931b                                                                                                                  
	0x08048094   mov edx, 0xb                                                                                                                        
	0x08048099   call puts
	
	; get username into 0x804937c global buffer
	
	0x0804809e   mov ecx, 0x804937c
	0x080480a3   mov edx, 0x32
	0x080480a8   call gets
	
	
	; ask serial 
	
	0x080480ad   mov ecx, str.Serial:
	0x080480b2   mov edx, 9
	0x080480b7   call puts
	
	; get serial in 0x80493ae global buffer
	
	0x080480bc   mov ecx, 0x80493ae
	0x080480c1   mov edx, 0x32
	0x080480c6   call gets
	
	; check the serial
	
	│           0x080480cb   call check_serial
	
	
	; print success or fail message based on outcome
	
	     0x080480d0   cmp eax, 1
	 ┌─< 0x080480d3   jne 0x80480e1
	 │   0x080480d5   mov ecx, 0x8049354
	 │   0x080480da   mov edx, 0x26
	┌──< 0x080480df   jmp 0x80480eb
	│└─> 0x080480e1   mov ecx, str.Invalid_Username_Serial_combination__nCorrect__now_write_a_Keygen_Tutorial__n
	│    0x080480e6   mov edx, 0x25
	└──> 0x080480eb   call puts
	     0x080480f0   call exit


Here are the utility functions, implemented by calling the corresponding linux system calls:

	╒ (fcn) puts
	
	; call write() system call
	
	│           0x080480f5   mov eax, 4
	│           0x080480fa   mov ebx, 1
	│           0x080480ff   int 0x80
	╘           0x08048101   ret
	
	╒ (fcn) gets
	
	; call read() system call
	
	│           0x08048102   mov eax, 3
	│           0x08048107   mov ebx, 1
	│           0x0804810c   int 0x80
	╘           0x0804810e   ret
	
	╒ (fcn) exit
	
	; call exit(0) system call
	
	│           0x080482fb   mov eax, 1
	│           0x08048300   mov ebx, 0
	╘           0x08048305   int 0x80

Note that since it's not using the standard C library, the strings are not zero-terminated and explicit lengths are passed in order to print only a part of the string at a time.


The serial checking
-------------------




	[0x0804810f 24% 255 Crackme3]> pd $r @ check_serial                                                                                                       
	
	; calculate length of username, by searching for newline
	
		 0x0804810f   mov eax, 0xa
		 0x08048114   mov ecx, 0xffffffff
		 0x08048119   mov edi, 0x804937c
		 0x0804811e   repne scasb al, byte es:[edi]
		 0x08048120   not ecx
		 0x08048122   dec ecx
	
	; fail if username is less than 5 chars
	
		 0x08048123   cmp ecx, 5
		 0x08048126   jb 0x804826d
	
	
	; calculate length of serial
	
		 0x0804812c   mov eax, 0xa
		 0x08048131   mov ecx, 0xffffffff
		 0x08048136   mov edi, 0x80493ae
		 0x0804813b   repne scasb al, byte es:[edi]
		 0x0804813d   not ecx
		 0x0804813f   dec ecx
	
	; fail if length is not 9
	
		 0x08048140   cmp ecx, 9
		 0x08048143   jne 0x804826d
	
	; fail if '-' is not present in serial
	; at fifth position
	
		 0x08048149   mov eax, 0x2d                                 ; '-'                                                                              
		 0x0804814e   mov edi, 0x80493ae
		 0x08048153   repne scasb al, byte es:[edi]
		 0x08048155   cmp ecx, 4
		 0x08048158   jne 0x804826d
	
	; compute a magic number starting from 0x7e4c9e32
	; by accumulate using multiplication all chars of
	; the username and save it in 0x80493e0 (renamed in "magic")
	
		 0x0804815e   xor eax, eax
		 0x08048160   mov esi, 0x804937c
		 0x08048165   mov edx, 0x7e4c9e32
		 0x0804816a   lodsb al, byte [esi]
		 0x0804816b   imul edx, eax
		 0x0804816e   cmp byte [esi], 0xa
		 0x08048171   jne 0x804816a
		 0x08048173   mov dword [magic], edx
	
	; from now on things becomes a little twisted, i'll
	; use python code to explain each block
	
	; convert the first 4 chars of serial in a number
	; using the mangle_string function and save the result
	; in the 0x80493f0 global
	
	; mm = [magic & 0xff]
	; a = mangle_string(ss[0], mm)
	
		 0x08048179   mov esi, 0x80493ae
		 0x0804817e   mov edi, 0x80493ae
		 0x08048183   call mangle_string
		 0x08048188   mov dword [0x80493f0], eax
	
	; do the same with the last 4 chars in serial
	; and save it in 0x8049400
	; b = mangle_string(ss[1], mm)
		 
		 0x0804818d   mov esi, 0x80493b3
		 0x08048192   mov edi, 0x80493b3
		 0x08048197   call mangle_string
		 0x0804819c   mov dword [0x8049400], eax
	
	; x = gen_num(0xf2a5, b, 0xf2a7)
	
		 0x080481a1   xchg eax, ebx
		 0x080481a2   mov ecx, 0xf2a7
		 0x080481a7   sub ecx, 2
		 0x080481aa   mov esi, 0xf2a7
		 0x080481af   call gen_num
	
	; xa = float_mod(x, magic, 0xf2a7)
	
		 0x080481b4   mov dword [0x8049410], eax
		 0x080481b9   mov dword [0x8049470], eax
		 0x080481be   mov eax, dword [magic]
		 0x080481c3   mov dword [0x8049480], eax
		 0x080481c8   mov dword [0x8049490], 0xf2a7
		 0x080481d2   call float_mod
	
	; xb = float_mod(a, x, 0xf2a7)
	
		 0x080481d7   mov dword [0x8049420], eax
		 0x080481dc   mov eax, dword [0x80493f0]
		 0x080481e1   mov dword [0x8049470], eax
		 0x080481e6   mov eax, dword [0x8049410]
		 0x080481eb   mov dword [0x8049480], eax
		 0x080481f0   mov dword [0x8049490], 0xf2a7
		 0x080481fa   call float_mod
	
	; y = gen_num(xa, 0x15346, 0x3ca9d)
	
		 0x080481ff   mov dword [0x8049430], eax
		 0x08048204   mov ebx, 0x15346
		 0x08048209   mov ecx, dword [0x8049420]
		 0x0804820f   mov esi, 0x3ca9d
		 0x08048214   call gen_num
	
	; z = gen_num(xb, 0x307c7, 0x3ca9d)
	
		 0x08048219   mov dword [0x8049450], eax
		 0x0804821e   mov ebx, 0x307c7
		 0x08048223   mov ecx, dword [0x8049430]
		 0x08048229   mov esi, 0x3ca9d
		 0x0804822e   call gen_num
	
	; w = float_mod(z, y, 0x3ca9d)
	
		 0x08048233   mov dword [0x8049460], eax
		 0x08048238   mov dword [0x8049470], eax
		 0x0804823d   mov eax, dword [0x8049450]
		 0x08048242   mov dword [0x8049480], eax
		 0x08048247   mov dword [0x8049490], 0x3ca9d
		 0x08048251   call float_mod
	
	; success if (w % 0xf2a7) == a
	
		 0x08048256   xor edx, edx
		 0x08048258   mov edi, 0xf2a7
		 0x0804825d   div edi
		 0x0804825f   cmp edx, dword [0x80493f0]
		 0x08048265   jne 0x804826d
		 0x08048267   mov eax, 1                                                                                                                       
		 0x0804826c   ret


Finally here are the primitives used in the above code:


mangle_string
-------------

	                   =----------------------------------------------=
	                   | [0x80482c3]                                  |
	                   | push ebx                                     |
	                   | push esi                                     |
	                   | push edi                                     |
	                   | mov esi, 4                                   |
	                   | xor ebx, ebx                                 |
	                   =----------------------------------------------=
	                       v
	                       '.
	                        |     .----------------------------------------------.
	                        |                                                    |
	                    =--------------------------------------------=           |
	                    |  0x80482cd                                 |           |
	                    | mov al, byte [edi]                         |           |
	                    | cmp al, 0x41 ; 'A'                         |           |
	                    | jb 0x80482df                               |           |
	                    =--------------------------------------------=           |
	                          t f                                                |
	       .------------------' '--------------------------------.               |
	       |                                                     |               |
	       |                                                     |               |
	 =---------------=                                   =----------------=      |
	 |  0x80482df    |                                   |  0x80482d3     |      |
	 | sub al, 0x30  |                                   | sub al, 0x57   |      |
	 =---------------=                                   | adc dl, 0      |      |
	     v                                               | shl dl, 5      |      |
	     |                                               | add al, dl     |      |
	     |                                               | jmp 0x80482e1  |      |
	     |                                               =----------------=      |
	     '------------------.                                v                   |
	                        .--------------------------------'                   |
	                        |                                                    |
	                        |                                                    |
	                    =--------------------------------------------=           |
	                    |  0x80482e1                                 |           |
	                    | lea ecx, [esi - 1]                         |           |
	                    | and eax, 0xf                               |           |
	                    | shl ecx, 2                                 |           |
	                    | shl eax, cl                                |           |
	                    | add ebx, eax                               |           |
	                    | inc edi                                    |           |
	                    | dec esi                                    |           |
	                    | cmp esi, 0                                 |           |
	                    | jne 0x80482cd                              |           |
	                    =--------------------------------------------=           |
	                            f `----------------------------------------------'
	                            '-------------.
	                                          |
	                                          |
	                                  =----------------=
	                                  |  0x80482f5     |
	                                  | mov eax, ebx   |
	                                  | pop edi        |
	                                  | pop esi        |
	                                  | pop ebx        |
	                                  | ret            |
	                                  =----------------=

The value of `dl` register comes initially from the least significant byte of the computed magic, and the is always updated in this function.

Here is the equivalent in python:

```python
def mangle_string(somestring, dl):
	cc = [12, 8, 4, 0]
	res = 0
	for i in xrange(4):
		c = ord(somestring[i])
		n = 0
		if c < ord('A'):
			n = c - ord('0')
		else:
			dl[0] = (dl[0] << 5) & 0xff
			n = c - ord('W') + dl[0]

		res += (n & 0xf) << cc[i]

	return res
```


gen_num
-------
	
	                   =----------------------------------------=
	                   | [0x8048270]                            |
	                   | push edx                               |
	                   | push edi                               |
	                   | mov edi, 1                             |
	                   =----------------------------------------=
	                       v
	                       '.
	                        .------------------------------------------------.
	                        |                                                |
	                    =--------------------------------------=             |
	                    |  0x8048277                           |             |
	                    | cmp ecx, 0                           |             |
	                    | jle 0x804829a                        |             |
	                    =--------------------------------------=             |
	                          t f                                            |
	         .----------------' '----------------------------.               |
	         |                                               |               |
	         |                                               |               |
	   =--------------------------------------=      =----------------=      |
	   |  0x804829a                           |      |  0x804827c     |      |
	   | mov eax, edi                         |      | mov edx, ecx   |      |
	   | pop edi                              |      | and edx, 1     |      |
	   | pop edx                              |      | cmp edx, 0     |      |
	   | ret                                  |      | je 0x804828e   |      |
	   =--------------------------------------=      =----------------=      |
	                                                         f t             |
	                                                         | |             |
	                                                   .-----' '-------.     |
	                                                   |               |     |
	                                                   |               |     |
	                                           =----------------=      |     |
	                                           |  0x8048286     |      |     |
	                                           | mov eax, edi   |      |     |
	                                           | mul ebx        |      |     |
	                                           | div esi        |      |     |
	                                           | mov edi, edx   |      |     |
	                                           =----------------=      |     |
	                                               v                   |     |
	                                           .---' .-----------------'     |
	                                           |     |                       |
	                                           |     |                       |
	                                       =--------------------------------------=
	                                       |  0x804828e                      |    |
	                                       | shr ecx, 1                      |    |
	                                       | mov eax, ebx                    |    |
	                                       | mul ebx                         |    |
	                                       | div esi                         |    |
	                                       | mov ebx, edx                    |    |
	                                       | jmp 0x8048277                   |    |
	                                       =--------------------------------------=
	                                           `-----------------------------'

Here is the equivalent in python:

```python
def gen_num(a,b,c):
	res = 1
	while a > 0:
		lsb = a & 1
		if lsb == 1:
			res = (res * b) % c
		
		a = a >> 1
		b = (b * b) % c

	return res
````

float_mod
---------

	╒ (fcn) float_mod 36        
	
	; convert a to float and push it to floating stack
	
	│           0x0804829f   fild qword [0x8049470]
	
	; convert b to float and push it to floating stack
	
	│           0x080482a5   fild qword [0x8049480]
	
	; a * b in floating point 
	
	│           0x080482ab   fmulp st(1)
	
	; convert c to float and put it on stack
	
	│           0x080482ad   fild qword [0x8049490]
	
	; perform (a*b) mod c
	
	│           0x080482b3   fxch st(1)
	│           0x080482b5   fprem
	
	; convert the result to int and return it
	
	│           0x080482b7   fist dword [0x8049490]
	│           0x080482bd   mov eax, dword [0x8049490]
	╘           0x080482c2   ret

This is the equivalent python code:

```python
def fmod(a,b,c):
	return (a*b) % c
```

Generating a serial
-------------------

I decided to use bruteforce to do it, because even if there might be smarter and more efficient algorithms to invert the logic, bruteforce is really simple and it takes seconds (or less) anyways, the bruteforcing stuff is provided in the [solution.py](solution.py) script

