MOVL R5, 0x0100

forever:

    XOR BS, BS
    XOR BS, R3
    LD R2, R0
    OUT R2
    ADD R3, R5
    JMP forever
