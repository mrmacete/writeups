esteve's ARM kgme1 - mrmacete's solution
===============================

Original challange is [here](http://crackmes.de/users/esteve/arm_kgme1/).

Although this crackme dates back to 2008, nobody wrote a proper solution for it. Reversing VMs is my favourite hobby, so i did it.

1. Identification of executable
-------------------------------
```bash
$ file arm_kgme1 
	arm_kgme1: ELF 32-bit LSB executable, ARM, version 1 (SYSV), for GNU/Linux 2.4.17, dynamically linked (uses shared libs), stripped
```

2. Running and debugging
------------------------

The first obstacle to reverse this binary is the exotic platform it is designed for. I tried several combinations of emulators and images found around the internet (avoid the Mozilla tutorial, it's way too modern) but i kept failing all the time. Finally i followed the advice of the author to use maemo's scratchbox, so here is a description of how i managed to get it work:

+ i'm on a mac, so i installed ubuntu on virtualbox, gave it 2GB of ram and 16GB hdd
+ got this script, executed it: [http://repository.maemo.org/stable/5.0/maemo-scratchbox-install_5.0.sh](http://repository.maemo.org/stable/5.0/maemo-scratchbox-install_5.0.sh)
+ after this finished (don't do the error of setting up virtualbox with 512MB of ram, it will not finish), logged out and in again
+ started scratchbox with the command:

	```
	/scratchbox/login
	```
+ created a sandbox using sb-menu with ARM toolchain
+ copied the binary into the sandbox
+ now the execution is easy, using gdb is slightly more complex:
	+ run the binary with the command:
	
		```
		> qemu-arm-sb -g 6969 ./arm_kgme1 
		```
	+ in another scratchbox terminal:
	
		```
		> gdb ./arm_kgme1
		(gdb) target remote 127.0.0.1:6969
		```
	+ you're in

3. Static analisys
------------------

First of all, the author warns us that there's a virtual machine inside, so let's do the shopping list of what we'll have to find:

* a program, i.e. an array of data representing a sequence of virtual instructions to be executed by the VM
* an instruction set, typically in the form of a big switch construct or some form of jump table, used by instruction decoder to actually perform single instructions, which are usually implemented as functions
* data structures to hold the state, i.e. registers array, a stack and/or a memory area
* an execution loop, which acts as a virtual processor executing one instruction at a time and coordinating all the state machinery

Let's spawn [radare2](http://www.radare.org/r/) as usual:

```r2
$ r2 arm_kgme1
	 -- Thank you for using radare2. Have a nice night!
	[0x00008368]> aa
	[0x00008368]> s main
	[0x00008cf8]> V
```

To have the renamable local variables, i did `af` command manually because radare2 failed to recognize main as a function.

After seeing the greeting printf and the only one read() to get the serial, by hasty visual inspection, it is easy to find the target addresses of the instruction set jump table:

	; allocate a buffer 1024-bytes wide

	0x00008d68    010ba0e3       mov r0, 0x400                                                   
	0x00008d6c    6efdffeb       bl sym.imp.malloc              ;[1]                             
	0x00008d70    84000be5       str r0, [fp-jump_table]                                         
	0x00008d74    84201be5       ldr r2, [fp-jump_table]                                         
	
	; load and store the first target address: 0x8494

	0x00008d78    a8329fe5       ldr r3, [pc, 0x2a8]            ; [0x9028:4]=0x8494              
	0x00008d7c    003082e5       str r3, [r2]                                                    
	0x00008d80    0420a0e3       mov r2, 4                                                       
	0x00008d84    84301be5       ldr r3, [fp-jump_table]                                         
	0x00008d88    032082e0       add r2, r2, r3  

	; load and store the second                                                

	0x00008d8c    98329fe5       ldr r3, [pc, 0x298]            ; [0x902c:4]=0x8544              

	; and so on
	[...]


In total there are apparently 11 different instructions, let's note the addresses of the functions for further inspection and go on to find the other things in our shopping list.

Suddenly, there is an sscanf():

	; r0 is the string to scan from: our input

	0x00008e70    7c004be2       sub r0, fp, 0x7c     

	; put the variable arguments in the stack, these are
	; the capture variables of sscanf

	0x00008e74    94301be5       ldr r3, [fp-registers]                                          
	0x00008e78    04c083e2       add ip, r3, 4                                                   
	0x00008e7c    94301be5       ldr r3, [fp-registers]                                          
	0x00008e80    083083e2       add r3, r3, 8                                                   
	0x00008e84    00308de5       str r3, [sp]                                                    
	0x00008e88    94301be5       ldr r3, [fp-registers]                                          
	0x00008e8c    0c3083e2       add r3, r3, 0xc                                                 
	0x00008e90    04308de5       str r3, [sp, 4]                                                 
	0x00008e94    94301be5       ldr r3, [fp-registers]                                          
	0x00008e98    103083e2       add r3, r3, 0x10                                                
	0x00008e9c    08308de5       str r3, [sp, 8]                                                 
	0x00008ea0    94301be5       ldr r3, [fp-registers]                                          
	0x00008ea4    143083e2       add r3, r3, 0x14                                                
	0x00008ea8    0c308de5       str r3, [sp, 0xc]        

	; the format string: "%x,%x,%x,%x,%x,%x"
	; the string is retrievable using the command:
	; iz~9138

	0x00008eac    a0119fe5       ldr r1, [pc, 0x1a0]            ; [0x9054:4]=0x9138 str._x__x__x
	0x00008eb0    94201be5       ldr r2, [fp-registers]                                          
	0x00008eb4    0c30a0e1       mov r3, ip                                                      
	0x00008eb8    1efdffeb       bl sym.imp.sscanf              ;[1]                             
	0x00008ebc    a0000be5       str r0, [fp-local_40]                                           
	0x00008ec0    a0301be5       ldr r3, [fp-local_40]     

	; check that parsed items are exacly six 

	0x00008ec4    060053e3       cmp r3, 6                                                       
	0x00008ec8    0000000a       beq 0x8ed0                     ;[2]      

	; otherwise fail        

	0x00008ecc    4d0000ea       b 0x9008                       ;[3]                             



From this we can start to figure out which is the input format: a list of six hexadecimal numbers, comma separated.

Note that i called the array "registers". This is a little spoiler, but our six numbers are set as values of the first six registers (r0-r5).

By following the successful path, after a couple of register initializations (registers[8]=0, registers[13]=32), we incur in the following visual clue:

	; a call to a function

	0x00008ef8    94004be2       sub r0, fp, 0x94                                                
	0x00008efc    43fdffeb       bl 0x8410                       ; fcn.00008404+0xc ;[3]     

	; a scary-looking grave of madness:

	0x00008f00    00062037       strlo r0, [r0, -r0, lsl 12]!                                    
	0x00008f04    0007b979       ldmibvc sb!, {r8, sb, sl}                                       
	0x00008f08    0106c6ef       svc 0xc60601                                                    
	0x00008f0c    01079e37       ldrlo r0, [lr, r1, lsl 14]                                      
	0x00008f10    05000001       invalid                                                         
	0x00008f14    06090101       mrseq r0, apsr                                                  
	0x00008f18    08090501       mrseq r0, apsr                                                  
	0x00008f1c    02090905       streq r0, [sb, -0x902]                                          
	0x00008f20    020a0006       streq r0, [r0], -r2, lsl 20                                     
	0x00008f24    05000301       mrseq r0, apsr                                                  
	0x00008f28    060b0101       invalid                                                         
	0x00008f2c    080b0400       andeq r0, r4, r8, lsl 22
	[...] ; continuing until 0x00008fc4

This means that maybe we've found the virtual program, which radare is incorrectly interpreting as ARM. Let's take note of start and end address, for further analisys. 

To view it in a way that permits us to copy-paste the whole program, the commands are:

	:> e hex.cols=4
	:> pxw 0xc8 @ 0x8f00

The called function, instead, ends up being our virtual processor. The main loop does:

	     0x00008414    00a0a0e1       mov sl, r0                                                      
	     0x00008418    04009ae5       ldr r0, [sl, 4]                                                 
	     0x0000841c    00608ee0       add r6, lr, r0                                                  
	     0x00008420    00009ae5       ldr r0, [sl]   

	     ; store the instruction pointer into registers[31]
	     ; (31 because is 0x7c/4, assuming all 32-bits registers)

	     0x00008424    7ce080e5       str lr, [r0, 0x7c]                                              

	     ; store a previously allocated buffer in registers[30]
	     ; that may be a stack

	     0x00008428    08109ae5       ldr r1, [sl, 8]                                                 
	     0x0000842c    781080e5       str r1, [r0, 0x78]  

	     ; start of the loop: fetch the 32-bit instruction from
	     ; current instruction pointer

	 ┌─> 0x00008430    00009ae5       ldr r0, [sl]                                                    
	 │   0x00008434    7c4090e5       ldr r4, [r0, 0x7c]                                              
	 │   0x00008438    004094e5       ldr r4, [r4]         

	 	 ; use the lower bit to index the jump_table of
	 	 ; the instruction set

	 │   0x0000843c    ff3004e2       and r3, r4, 0xff                                                
	 │   0x00008440    10009ae5       ldr r0, [sl, 0x10]                                              
	 │   0x00008444    033180e0       add r3, r0, r3, lsl 2 

	 	 ; split the rest of the instruction bytes in 3
	 	 ; 1-byte values, these will be the instruction's params

	 │   0x00008448    4404a0e1       asr r0, r4, 8                                                   
	 │   0x0000844c    ff0000e2       and r0, r0, 0xff                                                
	 │   0x00008450    4418a0e1       asr r1, r4, 0x10                                                
	 │   0x00008454    ff1001e2       and r1, r1, 0xff                                                
	 │   0x00008458    442ca0e1       asr r2, r4, 0x18                                                
	 │   0x0000845c    ff2002e2       and r2, r2, 0xff   

	 	 ; load the jump_table target address for the current
	 	 ; instruction

	 │   0x00008460    00c093e5       ldr ip, [r3]                                                    
	 │   0x00008464    0a30a0e1       mov r3, sl 

	 	 ; save the state and jump      

	 │   0x00008468    00402de9       stmdb sp!, {lr}                                                 
	 │   0x0000846c    0fe0a0e1       mov lr, pc                                                      
	 │   0x00008470    04e08ee2       add lr, lr, 4    
	 │   0x00008474    0cf0a0e1       mov pc, ip        

	 	 ; cleanup, as nothing happened        

	 │   0x00008478    0040bde8       ldm sp!, {lr}                                                   
	 │   0x0000847c    00009ae5       ldr r0, [sl]     

	 	 ; check the instuction pointer, go on if the virtual program
	 	 ; is not finished

	 │   0x00008480    7c4090e5       ldr r4, [r0, 0x7c]                                              
	 │   0x00008484    060054e1       cmp r4, r6                                                      
	 └─< 0x00008488    e8ffff1a       bne 0x8430                     ;[1]                             
	     0x0000848c    ff1fbde8       pop {r0, r1, r2, r3, r4, r5, r6, r7, r8, sb, sl, fp, ip}   

	     ; virtual program is finished, go to the epilogue

	┌──< 0x00008490    cc0200ea       b 0x8fc8                        ; main+0x2d0 ;[2]    

The epilogue simply checks that registers[0] and registers[1] are both ones, if so SUCCESS, otherwise FAIL.

3.1 The instruction set
-----------------------

Now that we have the big picture, let's dive into the promised 11 instructions one by one. This is long, so feel free to skip to section 4 if you're busy.

The names of the instructions are invented by me, roughly taking their semantic equivalents from x86 or - in some cases - from mips dialects. In examples and disassembly, the order of operands is the INTEL syntax (destination, left, right).

When talking about "instruction byte-wide params" i refer to the three bytes of the instruction code other than the index in the jump table, in little endian order.

### 3.1.1 LLI - load lower immediate

This instruction replaces the lower 16-bits of destination register with the provided 16-bits constant.

Example: `lli  r6, 0x3720`

Code:

	[...] ; cut: initialize local variables
	; with arg1, arg2, arg3 and the pointer to
	; the pointer to the registers array
	; this will be the same for all instructions, so
	; i will omit it

	0x000084c0   ldr r1, [fp-registers_ptr_ptr]
	0x000084c4   ldrb r3, [fp-arg1]            
	0x000084c8   lsl r2, r3, 2                 
	0x000084cc   ldr r3, [r1]

	; store in r0 a pointer to the destination
	; register

	0x000084d0   add r0, r2, r3    

	; load the register value in r3

	0x000084d4   ldr r1, [fp-registers_ptr_ptr]
	0x000084d8   ldrb r3, [fp-arg1]            
	0x000084dc   lsl r2, r3, 2                 
	0x000084e0   ldr r3, [r1]                  
	0x000084e4   add r3, r2, r3                
	0x000084e8   ldr r3, [r3]      

	; clean the lower 16 bits   

	0x000084ec   lsr r2, r3, 0x10              
	0x000084f0   lsl r2, r2, 0x10              
	
	; load and combine the two arguments
	; into one 16-bit value
	
	0x000084f4   ldrb r1, [fp-arg2]            
	0x000084f8   ldrb r3, [fp-arg3]            
	0x000084fc   lsl r3, r3, 8                 
	0x00008500   orr r3, r1, r3                
	
	; fill the previously cleaned register's bits

	0x00008504   orr r3, r2, r3          

	; store it back

	0x00008508   str r3, [r0]       

	; increment the instruction pointer by 4 and return
	; this is the same for all instruction implementations,
	; so i will omit it when obvious

	0x0000850c   ldr r3, [fp-registers_ptr_ptr]
	0x00008510   mov r2, 0x7c                  
	0x00008514   ldr r3, [r3]                  
	0x00008518   add r1, r2, r3                
	0x0000851c   ldr r3, [fp-registers_ptr_ptr]
	0x00008520   mov r2, 0x7c                  
	0x00008524   ldr r3, [r3]                  
	0x00008528   add r3, r2, r3                
	0x0000852c   ldr r3, [r3]                  
	0x00008530   add r3, r3, 4                 
	0x00008534   str r3, [r1]                  
	0x00008538   mov r0, 0xc                   
	0x0000853c   sub sp, fp, 0xc     
	0x00008540   ldm sp, {fp, sp, pc}                        


### 3.1.2 LUI - load upper immediate

This instruction replaces the higher 16-bits of destination register with the provided 16-bits constant.

Example: `lui  r6, 0xc6ef`

Code:
	
	[...]

	0x00008570   ldr r1, [fp-registers_ptr_ptr] 
	0x00008574   ldrb r3, [fp-arg1]             
	0x00008578   lsl r2, r3, 2                  
	0x0000857c   ldr r3, [r1] 
	
	; ip will hold a pointer to the destination register                  

	0x00008580   add ip, r2, r3                 

	; load and combine args to a single 16-bit number

	0x00008584   ldrb r2, [fp-arg3]             
	0x00008588   ldrb r3, [fp-arg2]             
	0x0000858c   lsl r3, r3, 8                  
	0x00008590   orr r3, r2, r3                 

	; move the 16-bits to the upper half

	0x00008594   lsl r0, r3, 0x10       

	; load register value        

	0x00008598   ldr r1, [fp-registers_ptr_ptr] 
	0x0000859c   ldrb r3, [fp-arg1]             
	0x000085a0   lsl r2, r3, 2                  
	0x000085a4   ldr r3, [r1]                   
	0x000085a8   add r3, r2, r3                 
	0x000085ac   ldr r3, [r3]     
	
	; clean the upper half              
	
	0x000085b0   lsl r3, r3, 0x10               
	0x000085b4   lsr r3, r3, 0x10  
	
	; merge the provided constant             
	
	0x000085b8   orr r3, r0, r3  
	
	; store it back

	0x000085bc   str r3, [ip]      

	[...]             

### 3.1.3 ADD - yeah, the add

Adds two registers and place the result in the destination register.

Example: `add  r9, r9, r5`

Code:

	[...]

	0x00008c10   ldr r1, [fp-registers_ptr_ptr]
	0x00008c14   ldrb r3, [fp-arg1]            
	0x00008c18   lsl r2, r3, 2                 
	0x00008c1c   ldr r3, [r1]      

	; ip holds a pointer to dst

	0x00008c20   add ip, r2, r3                
	0x00008c24   ldr r1, [fp-registers_ptr_ptr]
	0x00008c28   ldrb r3, [fp-arg2]            
	0x00008c2c   lsl r2, r3, 2                 
	0x00008c30   ldr r3, [r1]   

	; r0 holds a pointer to arg2

	0x00008c34   add r0, r2, r3                
	0x00008c38   ldr r1, [fp-registers_ptr_ptr]
	0x00008c3c   ldrb r3, [fp-arg3]            
	0x00008c40   lsl r2, r3, 2                 
	0x00008c44   ldr r3, [r1]       

	; r3 holds a pointer to arg3           
	
	0x00008c48   add r3, r2, r3 

	; load arg2 and arg3 values               
	
	0x00008c4c   ldr r2, [r0]                  
	0x00008c50   ldr r3, [r3]  

	; add them

	0x00008c54   add r3, r2, r3  

	; store the result in dst

	0x00008c58   str r3, [ip]  

	[...]                

### 3.1.4 JE/JNE - jump if equal/not-equal

Jump to a 16-bit relative address, defined by first 2 byte-params. The behaviour equal/not-equal is decided by the third parameter. The zero flag is checked to decide the equality state.

Example: `jne  0x00000004`

Code:

			  [...]

			  ; combine arg2 and arg3 in a single
			  ; 16 bit (relative, signed) address
			  ; and save it to jmp_offset

	          0x00008624   ldrb r3, [fp-arg3]
	          0x00008628   mov r2, r3
	          0x0000862c   ldrb r3, [fp-arg2]
	          0x00008630   lsl r3, r3, 8
	          0x00008634   orr r3, r2, r3
	          0x00008638   strh r3, [fp-jmp_offset]

	          ; arg1 will decide eq/not-eq in this way:
	          ; the sign bit will decide equality, while the
	          ; rest of bits apparently decide which flag to test

	          0x0000863c   ldr r1, [fp-registers_ptr_ptr]
	          0x00008640   ldrb r3, [fp-arg1]
	          0x00008644   and r3, r3, 0x7f
	          0x00008648   lsl r2, r3, 2

	          ; flags array

	          0x0000864c   ldr r3, [r1, 0xc]
	          0x00008650   add r3, r2, r3

	          ; read the flag value (indexed by lower 7 bits of arg1)

	          0x00008654   ldr r3, [r3]
	          0x00008658   cmp r3, 1
	      ┌─< 0x0000865c   bne 0x86d4 

	      	  ; flag is one, let's check arg1 sign

	      │   0x00008660   ldrsb r3, [fp-arg1]
	      │   0x00008664   cmp r3, 0
	     ┌──< 0x00008668   bge 0x869c 

	     	  ; flag is one and sign is negative, don't jump:
	     	  ; increment the instruction pointer by 4 as usual

	     ││   0x0000866c   ldr r3, [fp-registers_ptr_ptr]
	     ││   0x00008670   mov r2, 0x7c
	     ││   0x00008674   ldr r3, [r3]
	     ││   0x00008678   add r1, r2, r3
	     ││   0x0000867c   ldr r3, [fp-registers_ptr_ptr]
	     ││   0x00008680   mov r2, 0x7c
	     ││   0x00008684   ldr r3, [r3]
	     ││   0x00008688   add r3, r2, r3
	     ││   0x0000868c   ldr r3, [r3]
	     ││   0x00008690   add r3, r3, 4
	     ││   0x00008694   str r3, [r1]
	    ┌───< 0x00008698   b 0x8744                                     

	    	  ; flag is one and sign is positive; jump

	    │└──> 0x0000869c   ldr r3, [fp-registers_ptr_ptr]
	    │ │   0x000086a0   mov r2, 0x7c
	    │ │   0x000086a4   ldr r3, [r3]
	    │ │   0x000086a8   add r0, r2, r3
	    │ │   0x000086ac   ldr r3, [fp-registers_ptr_ptr]
	    │ │   0x000086b0   mov r2, 0x7c
	    │ │   0x000086b4   ldr r3, [r3]
	    │ │   0x000086b8   add r1, r2, r3

	    	  ; increment the instruction pointer by the 
	    	  ; previously calculated jmp_offset

	    │ │   0x000086bc   ldrsh r3, [fp-jmp_offset]
	    │ │   0x000086c0   lsl r2, r3, 2
	    │ │   0x000086c4   ldr r3, [r1]
	    │ │   0x000086c8   add r3, r3, r2
	    │ │   0x000086cc   str r3, [r0]
	   ┌────< 0x000086d0   b 0x8744                                     

	   		  ; flag is zero, let's check arg1 sign

	   ││ └─> 0x000086d4   ldrsb r3, [fp-arg1]
	   ││     0x000086d8   cmp r3, 0
	  ┌─────< 0x000086dc   bge 0x8718  

	  		  ; flag is zero and sign is negative, jump!

	  │││     0x000086e0   ldr r3, [fp-registers_ptr_ptr]
	  │││     0x000086e4   mov r2, 0x7c
	  │││     0x000086e8   ldr r3, [r3]
	  │││     0x000086ec   add r0, r2, r3
	  │││     0x000086f0   ldr r3, [fp-registers_ptr_ptr]
	  │││     0x000086f4   mov r2, 0x7c
	  │││     0x000086f8   ldr r3, [r3]
	  │││     0x000086fc   add r1, r2, r3

	  		  ; increment the instruction pointer by the
	  		  ; previously calculated jmp_offset

	  │││     0x00008700   ldrsh r3, [fp-jmp_offset]
	  │││     0x00008704   lsl r2, r3, 2
	  │││     0x00008708   ldr r3, [r1]
	  │││     0x0000870c   add r3, r3, r2
	  │││     0x00008710   str r3, [r0]
	 ┌──────< 0x00008714   b 0x8744                                     

	 		  ; flag is zero and arg1 is positive, don't jump

	 │└─────> 0x00008718   ldr r3, [fp-registers_ptr_ptr]
	 │ ││     0x0000871c   mov r2, 0x7c
	 │ ││     0x00008720   ldr r3, [r3]
	 │ ││     0x00008724   add r1, r2, r3
	 │ ││     0x00008728   ldr r3, [fp-registers_ptr_ptr]
	 │ ││     0x0000872c   mov r2, 0x7c
	 │ ││     0x00008730   ldr r3, [r3]
	 │ ││     0x00008734   add r3, r2, r3
	 │ ││     0x00008738   ldr r3, [r3]

	 		  ; increment by 4 as usual

	 │ ││     0x0000873c   add r3, r3, 4
	 │ ││     0x00008740   str r3, [r1]

	 		  ; cleanup & return

	 └─└└───> 0x00008744   mov r0, 0xc
	          0x00008748   sub sp, fp, 0xc
	          0x0000874c   ldm sp, {fp, sp, pc}

### 3.1.5 CMP - comparison

If the two provided registers are the same, the zero flag is raised, otherwise cleared. This is the only instruction with flag effects.

Example: `cmp  r8, r13`

Code:

		  [...]

		  ; radare2 failed in recognizing the local
		  ; variable for arg3 because it's stored but
		  ; never used. If this is a bug, it's a useful one.

	      0x00008774   mov r3, r2                     
	      0x00008778   strb r3, [fp, -0xf]     

	      ; load a pointer to the left register in r0

	      0x0000877c   ldr r1, [fp-registers_ptr_ptr] 
	      0x00008780   ldrb r3, [fp-arg1]             
	      0x00008784   lsl r2, r3, 2                  
	      0x00008788   ldr r3, [r1]                   
	      0x0000878c   add r0, r2, r3                 

	      ; load also the right register

	      0x00008790   ldr r1, [fp-registers_ptr_ptr] 
	      0x00008794   ldrb r3, [fp-arg2]             
	      0x00008798   lsl r2, r3, 2                  
	      0x0000879c   ldr r3, [r1]                   
	      0x000087a0   add r3, r2, r3     

	      ; load values

	      0x000087a4   ldr r2, [r0]                   
	      0x000087a8   ldr r3, [r3]    

	      ; do the comparison

	      0x000087ac   cmp r2, r3                     
	  ┌─< 0x000087b0   bne 0x87d0    

	  	  ; they are equal, set the flag

	  │   0x000087b4   ldr r3, [fp-registers_ptr_ptr] 
	  │   0x000087b8   mov r2, 4                      
	  │   0x000087bc   ldr r3, [r3, 0xc]              
	  │   0x000087c0   add r2, r2, r3                 
	  │   0x000087c4   mov r3, 1                      

	  	  ; store one in flags[1], the sign flag

	  │   0x000087c8   str r3, [r2]                   
	 ┌──< 0x000087cc   b 0x87e8                       

	 	  ; they are not equal, store 0 in flags[1]

	 │└─> 0x000087d0   ldr r3, [fp-registers_ptr_ptr] 
	 │    0x000087d4   mov r2, 4                      
	 │    0x000087d8   ldr r3, [r3, 0xc]              
	 │    0x000087dc   add r2, r2, r3                 
	 │    0x000087e0   mov r3, 0                      
	 │    0x000087e4   str r3, [r2]                   

	 	  [...]

### 3.1.6 PUSH - push a register to the stack

Yeah, it pushes a register to the stack. And increase the stack pointer.

Code:

	[...]

	; load the stack base pointer in r0

	0x0000884c   ldr r3, [fp-registers_ptr_ptr]
	0x00008850   mov r2, 0x78                  
	0x00008854   ldr r3, [r3]                  
	0x00008858   add r3, r2, r3                
	0x0000885c   ldr r0, [r3]   

	; load the register value in r3

	0x00008860   ldr r1, [fp-registers_ptr_ptr]
	0x00008864   ldrb r3, [fp-arg1]            
	0x00008868   lsl r2, r3, 2                 
	0x0000886c   ldr r3, [r1]                  
	0x00008870   add r3, r2, r3                
	0x00008874   ldr r3, [r3]     

	; put the value on the stack

	0x00008878   str r3, [r0]             

	; increment the stack pointer by 4 
	; and store it back   

	0x0000887c   ldr r3, [fp-registers_ptr_ptr]
	0x00008880   mov r2, 0x78                  
	0x00008884   ldr r3, [r3]                  
	0x00008888   add r1, r2, r3                
	0x0000888c   ldr r3, [fp-registers_ptr_ptr]
	0x00008890   mov r2, 0x78                  
	0x00008894   ldr r3, [r3]                  
	0x00008898   add r3, r2, r3                
	0x0000889c   ldr r3, [r3]                  
	0x000088a0   add r3, r3, 4                 
	0x000088a4   str r3, [r1]      

	[...]

### 3.1.7 POP - pop a register for the stack

Decreases the stack pointer and pops a register off the stack.

Cumulative example (this is the replacement of the missing MOV):

	push r0
	pop  r9

Code:

	[...]

	; load the address of stack pointer r3

	0x0000890c   ldr r3, [fp-registers_ptr_ptr]   
	0x00008910   mov r2, 0x78           
	0x00008914   ldr r3, [r3]           
	0x00008918   add r1, r2, r3    

	; decrement the stack pointer and store it back

	0x0000891c   ldr r3, [fp-registers_ptr_ptr]   
	0x00008920   mov r2, 0x78           
	0x00008924   ldr r3, [r3]           
	0x00008928   add r3, r2, r3         
	0x0000892c   ldr r3, [r3]           
	0x00008930   sub r3, r3, 4          
	0x00008934   str r3, [r1]    

	; load a pointer to dst register in r1       

	0x00008938   ldr r1, [fp-registers_ptr_ptr]   
	0x0000893c   ldrb r3, [fp-arg1]
	0x00008940   lsl r2, r3, 2          
	0x00008944   ldr r3, [r1]           
	0x00008948   add r1, r2, r3         

	; read the stack value and store it in dst

	0x0000894c   ldr r3, [fp-registers_ptr_ptr]   
	0x00008950   mov r2, 0x78           
	0x00008954   ldr r3, [r3]           
	0x00008958   add r3, r2, r3         
	0x0000895c   ldr r3, [r3]           
	0x00008960   ldr r3, [r3]           
	0x00008964   str r3, [r1]    

	[...]

### 3.1.8 SUB - the mainstream subtraction

Subtracts the second register from the first, placing the result in the destination register.

Example: `sub  r1, r1, r12`

Code:
	
	[...]

	; pointer to dst in ip

	0x00008b60   ldr r1, [fp-registers_ptr_ptr]
	0x00008b64   ldrb r3, [fp-arg1]            
	0x00008b68   lsl r2, r3, 2                 
	0x00008b6c   ldr r3, [r1]                  
	0x00008b70   add ip, r2, r3   

	; pointer to left operand in r0

	0x00008b74   ldr r1, [fp-registers_ptr_ptr]
	0x00008b78   ldrb r3, [fp-arg2]            
	0x00008b7c   lsl r2, r3, 2                 
	0x00008b80   ldr r3, [r1]                  
	0x00008b84   add r0, r2, r3  

	; pointer to right operand in r3

	0x00008b88   ldr r1, [fp-registers_ptr_ptr]
	0x00008b8c   ldrb r3, [fp-arg3]            
	0x00008b90   lsl r2, r3, 2                 
	0x00008b94   ldr r3, [r1]                  
	0x00008b98   add r3, r2, r3    

	; load left and right values

	0x00008b9c   ldr r2, [r0]                  
	0x00008ba0   ldr r3, [r3]     

	; subract (left-right)

	0x00008ba4   rsb r3, r3, r2     

	; store the result in dst

	0x00008ba8   str r3, [ip]                  

	[...]

### 3.1.9 SHL/SHR - shift left/right

Shifts a register by a byte-wide constant. The direction is decided by the third parameter.

Example: `shr  r9, 0x05`

Code:

		  [...]

		  ; arg3 encodes the direction of the shift

	      0x000089cc   ldrb r3, [fp-arg3]            
	      0x000089d0   cmp r3, 1                     
	  ┌─< 0x000089d4   bne 0x8a14                    

	  	  ; direction is one, means "shift right"

		  ; load a pointer to dst in r0  

	  │   0x000089d8   ldr r1, [fp-registers_ptr_ptr]
	  │   0x000089dc   ldrb r3, [fp-arg1]            
	  │   0x000089e0   lsl r2, r3, 2                 
	  │   0x000089e4   ldr r3, [r1]                  
	  │   0x000089e8   add r0, r2, r3  

	  	  ; load the value of dst in r3, and the shift
	  	  ; amount from arg2

	  │   0x000089ec   ldr r1, [fp-registers_ptr_ptr]
	  │   0x000089f0   ldrb r3, [fp-arg1]            
	  │   0x000089f4   lsl r2, r3, 2                 
	  │   0x000089f8   ldr r3, [r1]                  
	  │   0x000089fc   add r3, r2, r3                
	  │   0x00008a00   ldrb r2, [fp-arg2]            
	  │   0x00008a04   ldr r3, [r3]       

	  	  ; perform the right shift

	  │   0x00008a08   lsr r3, r3, r2                

	  	  ; store it back to dst

	  │   0x00008a0c   str r3, [r0]                  
	 ┌──< 0x00008a10   b 0x8a4c                      

	 	  ; direction is not one, it means "shift left"

	 │└─> 0x00008a14   ldr r1, [fp-registers_ptr_ptr]
	 │    0x00008a18   ldrb r3, [fp-arg1]            
	 │    0x00008a1c   lsl r2, r3, 2                 
	 │    0x00008a20   ldr r3, [r1]                  
	 │    0x00008a24   add r0, r2, r3                
	 │    0x00008a28   ldr r1, [fp-registers_ptr_ptr]
	 │    0x00008a2c   ldrb r3, [fp-arg1]            
	 │    0x00008a30   lsl r2, r3, 2                 
	 │    0x00008a34   ldr r3, [r1]                  
	 │    0x00008a38   add r3, r2, r3                
	 │    0x00008a3c   ldrb r2, [fp-arg2]            
	 │    0x00008a40   ldr r3, [r3]   

	 	  ; this time shift left

	 │    0x00008a44   lsl r3, r3, r2                

	 	  ; and store it back

	 │    0x00008a48   str r3, [r0]                  

	 	  [...]

### 3.1.10 XOR - exclusive or

XORs two registers and place the result in the destination register.

Example: `xor  r12, r11, r10`

Code:

	[...]

	; pointer to dst, in ip

	0x00008ab0   ldr r1, [fp-registers_ptr_ptr]
	0x00008ab4   ldrb r3, [fp-arg1]            
	0x00008ab8   lsl r2, r3, 2                 
	0x00008abc   ldr r3, [r1]                  
	0x00008ac0   add ip, r2, r3     

	; pointer to left operand in r0  

	0x00008ac4   ldr r1, [fp-registers_ptr_ptr]
	0x00008ac8   ldrb r3, [fp-arg2]            
	0x00008acc   lsl r2, r3, 2                 
	0x00008ad0   ldr r3, [r1]                  
	0x00008ad4   add r0, r2, r3    

	; pointer to right operand in r3

	0x00008ad8   ldr r1, [fp-registers_ptr_ptr]
	0x00008adc   ldrb r3, [fp-arg3]            
	0x00008ae0   lsl r2, r3, 2                 
	0x00008ae4   ldr r3, [r1]                  
	0x00008ae8   add r3, r2, r3     

	; load values and do the XOR    

	0x00008aec   ldr r2, [r0]                  
	0x00008af0   ldr r3, [r3]                  
	0x00008af4   eor r3, r2, r3  

	; store result in dst

	0x00008af8   str r3, [ip]                  

	[...]

### 3.1.11 NOP - do nothing

But it increases the instruction pointer.

Example: `nop`

Code:

	; load (unused) args and register pointer

	0x00008c94   mov ip, sp           
	0x00008c98   push {fp, ip, lr, pc}
	0x00008c9c   sub fp, ip, 4        
	0x00008ca0   sub sp, sp, 8        
	0x00008ca4   str r3, [fp-local_5] 
	0x00008ca8   mov r3, r0           
	0x00008cac   strb r3, [fp, -0xd]  
	0x00008cb0   mov r3, r1           
	0x00008cb4   strb r3, [fp, -0xe]  
	0x00008cb8   mov r3, r2           
	0x00008cbc   strb r3, [fp, -0xf]  

	; increment instruction pointer by 4 and return

	0x00008cc0   ldr r3, [fp-local_5] 
	0x00008cc4   mov r2, 0x7c         
	0x00008cc8   ldr r3, [r3]         
	0x00008ccc   add r1, r2, r3       
	0x00008cd0   ldr r3, [fp-local_5] 
	0x00008cd4   mov r2, 0x7c         
	0x00008cd8   ldr r3, [r3]         
	0x00008cdc   add r3, r2, r3       
	0x00008ce0   ldr r3, [r3]         
	0x00008ce4   add r3, r3, 4        
	0x00008ce8   str r3, [r1]         
	0x00008cec   mov r0, 0xc          
	0x00008cf0   sub sp, fp, 0xc      
	0x00008cf4   ldm sp, {fp, sp, pc} 

4. The virtual program
----------------------

I wrote a primitive disassembler, which is part of the solution ([disassembler.py](disassembler.py)). The commented disassembled source reveals the serial checking routine:


	; init a couple of constants
	; r6 = 0xc6ef3720
    ; r7 = 0x9e3779b9

    0x00000000     lli  r6, 0x3720
    0x00000001     lli  r7, 0x79b9
    0x00000002     lui  r6, 0xc6ef
    0x00000003     lui  r7, 0x9e37


    ; r9 = (serial[0] >> 5) + serial[5]

    0x00000004     push r0
    0x00000005     pop  r9
    0x00000006     shr  r9, 0x05
    0x00000007     add  r9, r9, r5


    ; r10 = serial[0] + r6

    0x00000008     add  r10, r0, r6


    ; r11 = (serial[0] << 4) + serial[4]

    0x00000009     push r0
    0x0000000a     pop  r11
    0x0000000b     shl  r11, 0x04
    0x0000000c     add  r11, r11, r4

    
    ; r12 = r11 | r10 | r9
    
    0x0000000d     xor  r12, r11, r10
    0x0000000e     xor  r12, r12, r9


    ; serial[1] = serial[1] - r12

    0x0000000f     sub  r1, r1, r12


    ; r9 = (serial[1] >> 5) + serial[3]

    0x00000010     push r1
    0x00000011     pop  r9
    0x00000012     shr  r9, 0x05
    0x00000013     add  r9, r9, r3

    
    ; r10 = serial[1] + r6 

    0x00000014     add  r10, r1, r6

    
    ; r11 = (serial[1] << 4) + serial[2]

    0x00000015     push r1
    0x00000016     pop  r11
    0x00000017     shl  r11, 0x04
    0x00000018     add  r11, r11, r2


    ; r12 = r11 | r10 | r9 

    0x00000019     xor  r12, r11, r10
    0x0000001a     xor  r12, r12, r9


    ; serial[0] = serial[0] - r12

    0x0000001b     sub  r0, r0, r12

    ; r14 = 1

    0x0000001c     lli  r14, 0x0001
    0x0000001d     lui  r14, 0x0000

    ; r8 = r8 + r14 (r8 was set to 0 out of band)
    0x0000001e     add  r8, r8, r14

    ; if r8 != r13, go to 4 (r13 was set to 32 out of band)
    0x0000001f     cmp  r8, r13

    ; anyways r6 = r6 - r7

    0x00000020     sub  r6, r6, r7
    0x00000021     jne  0x00000004


    ; check serial[0] and serial[1] to be equal to
    ; another couple of constants

    ; r2 = 0xba01aafe
    ; r3 = 0xbbff31a3

    0x00000022     lli  r2, 0xaafe
    0x00000023     lli  r3, 0x31a3
    0x00000024     lui  r2, 0xba01
    0x00000025     lui  r3, 0xbbff

    ; r2 == serial[0] ?

    0x00000026     cmp  r2, r0
    0x00000027     jne  0x0000002a

    ; serial[0] passed, let's replace it with 1
    0x00000028     lli  r0, 0x0001
    0x00000029     lui  r0, 0x0000

    ; r3 == serial[1] ?

    0x0000002a     cmp  r3, r1
    0x0000002b     jne  0x0000002e

    ; serial[1] passed, replace with 1
    0x0000002c     lli  r1, 0x0001
    0x0000002d     lui  r1, 0x0000
    0x0000002e     nop 

The out-of-band real-machine epilogue then checks r0 and r1 for equality with 1 to succeed the check.

5. The keygen
-------------

This algorythm is easily reversible, by starting from the last state (the one which is checked for validity) and proceding backwards to the beginning. The only constraints are on the first two numbers of the serial, while the rest can be chosen at random. This is the python code at the heart of my solution:

```python
	def combine(seed, a,b,c):
		r9 = ((a >> 5) + b) & 0xffffffff
		r10 = (a + seed) & 0xffffffff
		r11 = (((a << 4) & 0xffffffff)+ c) & 0xffffffff
		return r11 ^ r10 ^ r9

	def keygen():
		serial = [0] * 6

		# start from the end
		serial[0] = 0xba01aafe
		serial[1] = 0xbbff31a3

		# all the rest can be random
		serial[4] = random.randint(0, 0xffffffff)
		serial[5] = random.randint(0, 0xffffffff)
		serial[2] = random.randint(0, 0xffffffff)
		serial[3] = random.randint(0, 0xffffffff)

		r6 = 0x9e3779b9

		for i in xrange(32):
			r12 = combine(r6, serial[1], serial[3], serial[2])
			serial[0] = (serial[0] + r12) & 0xffffffff

			r12 = combine(r6, serial[0], serial[5], serial[4])
			serial[1] = (serial[1] + r12) & 0xffffffff

			r6 = (r6 + 0x9e3779b9) & 0xffffffff
		
		return serial
```

The full keygen is included in the solution ([keygen.py](keygen.py)), and it creates 100 random valid keys. It can be tuned to generate any number of them.



