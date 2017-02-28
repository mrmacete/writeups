/* Copyright 2017 - mrmacete <mrmacete@protonmail.ch>
 * Licensed under the GNU General Public License, version 2.0 (GPLv2)
 */
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

enum RFridgeOperators {
    FRI_OP_NOP,
    FRI_OP_PUSH,
    FRI_OP_POP,
    FRI_OP_MOV,
    FRI_OP_MOVL,
    FRI_OP_MOVH,
    FRI_OP_LOAD,
    FRI_OP_STORE,
    FRI_OP_ADD,
    FRI_OP_SUB,
    FRI_OP_XOR,
    FRI_OP_AND,
    FRI_OP_OR,
    FRI_OP_INV,
    FRI_OP_LSL,
    FRI_OP_LSR,
    FRI_OP_ROL,
    FRI_OP_ROR,
    FRI_OP_CALL,
    FRI_OP_RET,
    FRI_OP_JMP_IMM,
    FRI_OP_JMP_REG,
    FRI_OP_CMP,
    FRI_OP_JZ_IMM,
    FRI_OP_JNZ_IMM,
    FRI_OP_JZ_REG,
    FRI_OP_JNZ_REG,
    FRI_OP_INCHAR,
    FRI_OP_OUTCHAR,
    FRI_OP_DFAIL,
    FRI_OP_TFAIL,
    FRI_OP_HLT
};

#define FRI_OP_INVALID 0xff

static const char * operators[] = {
    "NOP",
    "PUSH %s",
    "POP %s",
    "MOV %s, %s",
    "MOVL %s, 0x%04x",
    "MOVH %s, 0x%04x",
    "LD %s, %s",
    "ST %s, %s",
    "ADD %s, %s",
    "SUB %s, %s",
    "XOR %s, %s",
    "AND %s, %s",
    "OR %s, %s",
    "INV %s",
    "LSL %s, %s",
    "LSR %s, %s",
    "ROL %s, %s",
    "ROR %s, %s",
    "CALL %s",
    "RET",
    "JMP 0x%04x",
    "JMP %s",
    "CMP %s, %s",
    "JZ 0x%04x",
    "JNZ 0x%04x",
    "JZ %s",
    "JNZ %s",
    "IN %s",
    "OUT %s",
    "DFAIL",
    "TFAIL",
    "HLT"
};

static const char * reg_names[] = {
    "R0",
    "R1",
    "R2",
    "R3",
    "R4",
    "R5",
    "R6",
    "R7",
    "R8",
    "R9",
    "R10",
    "R11",
    "R12",
    "R13",
    "R14",
    "R15"
};

static int get_opsize (ut8 opcode) {
    if (opcode == 0 || opcode == 0x13 || opcode >= 0x1d) {
        return 1;
    }
    if (opcode == 0x14 || opcode == 0x17 || opcode == 0x18) {
        return 3;
    }
    if (opcode == 4 || opcode == 5) {
        return 4;
    }
    return 2;
}

static int count_percents(const char * s) {
    int i,j;
    for (i=0, j=0; s[i+j]; s[i+j]=='%' ? i++ : j++);
    return i;
}

static int dst_num_restricted(ut8 encoded) {
    return (encoded & 0x70) >> 4;
}

static int dst_num(ut8 encoded) {
    return (encoded & 0xf0) >> 4;
}

static int src_num(ut8 encoded) {
    return encoded & 0xf;
}

static const char * get_reg_name(ut8 reg_num) {
    if (reg_num == 6) {
        return "SP";
    }
    if (reg_num == 7) {
        return "PC";
    }
    if (reg_num == 8) {
        return "BS";
    }
    if (reg_num > 15) {
        return "INVALID";
    }
    return reg_names[reg_num];
}

static bool is_dst_restricted (ut8 opcode) {
    switch (opcode) {
    case FRI_OP_XOR:
        return false;
    default:
        return true;
    }
}

static int disassemble(RAsm *a, RAsmOp *r_op, const ut8 *buf, int len) {
	const char *op, *dst, *src;
    int opsize = 1;
    ut16 imm;
    bool restricted;

    if (*buf > 31) {
        sprintf (r_op->buf_asm, "invalid");
        return r_op->size = 1;
    }

    opsize = get_opsize (buf[0]);
    op = operators[*buf];
    restricted = is_dst_restricted (buf[0]);

    switch (opsize) {
    case 1:
        sprintf (r_op->buf_asm, "%s", op);
        break;
    case 2:
        if (count_percents (op) == 1) {
            if (restricted) {
                dst = get_reg_name (dst_num_restricted (buf[1]));
            } else {
                dst = get_reg_name (dst_num (buf[1]));
            }
            sprintf (r_op->buf_asm, op, dst);
        } else {
            if (restricted) {
                dst = get_reg_name (dst_num_restricted (buf[1]));
            } else {
                dst = get_reg_name (dst_num (buf[1]));
            }
            src = get_reg_name (src_num (buf[1]));
            sprintf (r_op->buf_asm, op, dst, src);
        }
        break;
    case 3:
        imm = (buf[2] | ((ut16) buf[1] << 8)) * 4;
        sprintf (r_op->buf_asm, op, imm);
        break;
    case 4:
        imm = buf[3] | ((ut16) buf[2] << 8);
        dst = get_reg_name (dst_num_restricted (buf[1]));
        sprintf (r_op->buf_asm, op, dst, imm);
        break;
    default:
        break;
    }

	return r_op->size = opsize;
}

/* start of ASSEMBLER code */

static void upper_op(char *c) {
	if ((c[0] <= 'z') && (c[0] >= 'a')) {
		c[0] -= 0x20;
	}
}

static void normalize(char* buf_asm) {
	int i;
	if (!buf_asm) return;

	/* this normalization step is largely sub-optimal */

	i = strlen (buf_asm);
	r_str_replace_in (buf_asm, (ut32)i, ",", " ", R_TRUE);
	while (strstr (buf_asm, "  ")) {
		r_str_replace_in (buf_asm, (ut32)i, "  ", " ", R_TRUE);
	}
	r_str_do_until_token (upper_op, buf_asm, '\0');
}

#define PARSER_MAX_TOKENS 3

#define PARSE_FAILURE(message, arg...) \
	{ eprintf("PARSE FAILURE: "message"\n", ##arg);\
	return -1;}

#define CMP5(n, x, y, z, w, q) \
	(tok[n][0] == x && tok[n][1] == y && tok[n][2] == z && tok[n][3] == w && tok[n][4] == q)

#define CMP4(n, x, y, z, w) \
	(tok[n][0] == x && tok[n][1] == y && tok[n][2] == z && tok[n][3] == w)

#define CMP3(n, x, y, z) \
	(tok[n][0] == x && tok[n][1] == y && tok[n][2] == z)

#define CMP2(n, x, y) \
	(tok[n][0] == x && tok[n][1] == y)

#define COPY_AND_RET() \
    opsize = get_opsize (buf[0]);\
	memcpy(op->buf, &buf[0], opsize);\
    op->size = opsize;\
	return 0;

#define DEFAULT_2REGS_RET() \
    dstnum = assemble_dst_reg (tok[1]);\
    srcnum = assemble_src_reg (tok[2]);\
    buf[1] = dstnum | srcnum;\
    COPY_AND_RET ();

#define DEFAULT_1REG_RET() \
    dstnum = assemble_dst_reg (tok[1]);\
    buf[1] = dstnum;\
    COPY_AND_RET ();

static int assemble_reg_name (const char * reg_name) {
    if (strncmp(reg_name, "SP", 2) == 0) {
        return 6;
    }
    if (strncmp(reg_name, "PC", 2) == 0) {
        return 7;
    }
    if (strncmp(reg_name, "BS", 2) == 0) {
        return 8;
    }
    eprintf ("Unresolved reg name: %s\n", reg_name);
    return -1;
}

static int assemble_src_reg (const char * reg_name) {
    if (isdigit (reg_name[1])) {
        return strtol (reg_name + 1, NULL, 10) & 0xf;
    } else {
        return assemble_reg_name (reg_name) & 0xf;
    }
}

static int assemble_dst_reg (const char * reg_name) {
    if (isdigit (reg_name[1])) {
        return (strtol (reg_name + 1, NULL, 10) & 0xf) << 4;
    } else {
        return (assemble_reg_name (reg_name) & 0xf) << 4;
    }
}

static int assemble_tok(RAsm *a, RAsmOp *op,
	char *tok[PARSER_MAX_TOKENS], int count) {
	char *end;
	int oplen = 0;
    ut8 buf[4] = {FRI_OP_INVALID,0,0,0};
    int opsize = 0;
    int srcnum, dstnum, immval;

	oplen = strnlen(tok[0], 6);

	if (oplen < 2 || oplen > 5) {
		PARSE_FAILURE ("mnemonic length not valid");
	}

    if (CMP3 (0, 'M', 'O', 'V') && count == 3) {
        if (tok[0][3] == 0) {
            buf[0] = FRI_OP_MOV;
            DEFAULT_2REGS_RET ();
        } else {
            if (tok[0][3] == 'L') {
                buf[0] = FRI_OP_MOVL;
            } else {
                buf[0] = FRI_OP_MOVH;
            }
            dstnum = assemble_dst_reg (tok[1]);
            buf[1] = dstnum;
            immval = strtol (tok[2], NULL, 0) & 0xffff;
            buf[2] = (immval & 0xff00) >> 8;
            buf[3] = immval & 0xff;
            COPY_AND_RET ();
        }
    }

    if (CMP2 (0, 'P', 'U') && count == 2) {
        buf[0] = FRI_OP_PUSH;
        dstnum = assemble_dst_reg (tok[1]);
        buf[1] = dstnum;
        COPY_AND_RET ();
    }

    if (CMP2 (0, 'P', 'O') && count == 2) {
        buf[0] = FRI_OP_POP;
        dstnum = assemble_dst_reg (tok[1]);
        buf[1] = dstnum;
        COPY_AND_RET ();
    }

    if (CMP2 (0, 'L', 'D') && count == 3) {
        buf[0] = FRI_OP_LOAD;
        DEFAULT_2REGS_RET ();
    }

    if (CMP2 (0, 'S', 'T') && count == 3) {
        buf[0] = FRI_OP_STORE;
        DEFAULT_2REGS_RET ();
    }

    if (CMP2 (0, 'A', 'D') && count == 3) {
        buf[0] = FRI_OP_ADD;
        DEFAULT_2REGS_RET ();
    }

    if (CMP2 (0, 'S', 'U') && count == 3) {
        buf[0] = FRI_OP_SUB;
        DEFAULT_2REGS_RET ();
    }

    if (CMP2 (0, 'X', 'O') && count == 3) {
        buf[0] = FRI_OP_XOR;
        DEFAULT_2REGS_RET ();
    }

    if (CMP2 (0, 'A', 'N') && count == 3) {
        buf[0] = FRI_OP_AND;
        DEFAULT_2REGS_RET ();
    }

    if (CMP2 (0, 'O', 'R') && count == 3) {
        buf[0] = FRI_OP_OR;
        DEFAULT_2REGS_RET ();
    }

    if (CMP3 (0, 'I', 'N', 'V') && count == 2) {
        buf[0] = FRI_OP_INV;
        DEFAULT_1REG_RET ();
    }

    if (CMP3 (0, 'L', 'S', 'L') && count == 3) {
        buf[0] = FRI_OP_LSL;
        DEFAULT_2REGS_RET ();
    }

    if (CMP3 (0, 'L', 'S', 'R') && count == 3) {
        buf[0] = FRI_OP_LSR;
        DEFAULT_2REGS_RET ();
    }

    if (CMP3 (0, 'R', 'O', 'L') && count == 3) {
        buf[0] = FRI_OP_ROL;
        DEFAULT_2REGS_RET ();
    }

    if (CMP3 (0, 'R', 'O', 'R') && count == 3) {
        buf[0] = FRI_OP_ROR;
        DEFAULT_2REGS_RET ();
    }

    if (CMP3 (0, 'C', 'A', 'L') && count == 2) {
        buf[0] = FRI_OP_CALL;
        DEFAULT_1REG_RET ();
    }

    if (CMP2 (0, 'R', 'E')) {
        buf[0] = FRI_OP_RET;
        COPY_AND_RET ();
    }

    if (tok[0][0] == 'J' && count == 2) {
        if (tok[1][0] == 'R') {
            // is register
            if (tok[0][1] == 'M') {
                buf[0] = FRI_OP_JMP_REG;
            } else if (tok[0][1] == 'Z') {
                buf[0] = FRI_OP_JZ_REG;
            } else {
                buf[0] = FRI_OP_JNZ_REG;
            }
            DEFAULT_1REG_RET();
        } else {
            if (tok[0][1] == 'M') {
                buf[0] = FRI_OP_JMP_IMM;
            } else if (tok[0][1] == 'Z') {
                buf[0] = FRI_OP_JZ_IMM;
            } else {
                buf[0] = FRI_OP_JNZ_IMM;
            }

            immval = strtol (tok[1], NULL, 0);
            if ((immval & 3) == 0) {
                immval = (immval >> 2) & 0xffff;
                buf[1] = (immval & 0xff00) >> 8;
                buf[2] = immval & 0xff;
                COPY_AND_RET ();
            } else {
                eprintf ("Unaligned jump\n");
            }
        }
    }

    if (CMP2 (0, 'C', 'M') && count == 3) {
        buf[0] = FRI_OP_CMP;
        DEFAULT_2REGS_RET ();
    }

    if (CMP3 (0, 'I', 'N', 0) && count == 2) {
        buf[0] = FRI_OP_INCHAR;
        DEFAULT_1REG_RET ();
    }

    if (CMP2 (0, 'O', 'U') && count == 2) {
        buf[0] = FRI_OP_OUTCHAR;
        DEFAULT_1REG_RET ();
    }

    if (CMP2 (0, 'D', 'F')) {
        buf[0] = FRI_OP_DFAIL;
        COPY_AND_RET ();
    }

    if (CMP2 (0, 'T', 'F')) {
        buf[0] = FRI_OP_TFAIL;
        COPY_AND_RET ();
    }

    if (CMP2 (0, 'H', 'L')) {
        buf[0] = FRI_OP_HLT;
        COPY_AND_RET ();
    }

    if (CMP2 (0, 'N', 'O')) {
        buf[0] = FRI_OP_NOP;
        COPY_AND_RET ();
    }

    return -1;
}

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	char *tok[PARSER_MAX_TOKENS];
	char tmp[128];
	int i, j, l;
	const char *p = NULL;
	if (!a || !op || !buf) {
		return 0;
	}

	strncpy (op->buf_asm, buf, R_ASM_BUFSIZE-1);
	op->buf_asm[R_ASM_BUFSIZE-1] = 0;
	normalize(op->buf_asm);


	// tokenization, copied from profile.c
	j = 0;
	p = op->buf_asm;

	// For every word
	while (*p) {
		// Skip the whitespace
		while (*p == ' ' || *p == '\t') {
			p++;
		}
		// Skip the rest of the line is a comment is encountered
		if (*p == ';') {
			while (*p != '\0') {
				p++;
			}
		}
		// EOL ?
		if (*p == '\0') {
			break;
		}
		// Gather a handful of chars
		// Use isgraph instead of isprint because the latter considers ' ' printable
		for (i = 0; isgraph ((const unsigned char)*p) && i < sizeof(tmp) - 1;) {
			tmp[i++] = *p++;
		}
		tmp[i] = '\0';
		// Limit the number of tokens
		if (j > PARSER_MAX_TOKENS - 1) {
			break;
		}
		// Save the token
		tok[j++] = strdup (tmp);
	}

	if (j) {
		if (assemble_tok(a, op, tok, j) < 0) {
            eprintf ("ERROR in: %s\n", op->buf_asm);
			return -1;
		}

		// Clean up
		for (i = 0; i < j; i++) {
			free(tok[i]);
		}
	}

	return op->size;
}

RAsmPlugin r_asm_plugin_fridge = {
	.name = "fridge",
	.desc = "RHME2 fridge disassembler",
	.license = "GPLv2",
	.arch = "fridge",
	.bits = 32,
	.disassemble = &disassemble,
	.assemble = &assemble
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_fridge,
	.version = R2_VERSION
};
#endif
