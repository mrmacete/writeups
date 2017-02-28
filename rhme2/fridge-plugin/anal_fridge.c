/*
 *
 * Copyright 2017 - mrmacete <mrmacete@protonmail.ch>
 * Licensed under the GNU General Public License, version 2.0 (GPLv2)
 */
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

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

static int get_opsize (ut8 opcode) {
    if (opcode == 0 || opcode == 13 || opcode >= 0x1d) {
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

static int fridge_anal(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	memset (op, '\0', sizeof (RAnalOp));
	op->jump = UT64_MAX;
	op->fail = UT64_MAX;
	op->ptr = op->val = UT64_MAX;
	op->type = R_ANAL_OP_TYPE_UNK;
	op->size = get_opsize (buf[0]);
	op->addr = addr;

    switch (buf[0]) {
    case FRI_OP_RET:
        op->type = R_ANAL_OP_TYPE_RET;
        break;
    case FRI_OP_MOV:
    case FRI_OP_MOVL:
    case FRI_OP_MOVH:
        op->type = R_ANAL_OP_TYPE_MOV;
        break;
    case FRI_OP_JMP_IMM:
    case FRI_OP_JZ_IMM:
    case FRI_OP_JNZ_IMM:
        if (buf[0] == FRI_OP_JMP_IMM) {
            op->type = R_ANAL_OP_TYPE_JMP;
        } else {
            op->type = R_ANAL_OP_TYPE_CJMP;
            op->fail = addr + op->size;
        }

        op->jump = (buf[2] | ((ut16) buf[1] << 8)) * 4;
        break;
    case FRI_OP_ADD:
        op->type = R_ANAL_OP_TYPE_ADD;
        break;
    case FRI_OP_SUB:
        op->type = R_ANAL_OP_TYPE_SUB;
        break;
    case FRI_OP_XOR:
        op->type = R_ANAL_OP_TYPE_XOR;
        break;
    case FRI_OP_AND:
        op->type = R_ANAL_OP_TYPE_AND;
        break;
    case FRI_OP_OR:
        op->type = R_ANAL_OP_TYPE_OR;
        break;
    case FRI_OP_INV:
        op->type = R_ANAL_OP_TYPE_NOT;
        break;
    case FRI_OP_LSL:
        op->type = R_ANAL_OP_TYPE_SHL;
        break;
    case FRI_OP_LSR:
        op->type = R_ANAL_OP_TYPE_SHR;
        break;
    case FRI_OP_ROL:
        op->type = R_ANAL_OP_TYPE_ROL;
        break;
    case FRI_OP_ROR:
        op->type = R_ANAL_OP_TYPE_ROR;
        break;
    case FRI_OP_NOP:
        op->type = R_ANAL_OP_TYPE_NOP;
        break;
    case FRI_OP_LOAD:
        op->type = R_ANAL_OP_TYPE_LOAD;
        break;
    case FRI_OP_STORE:
        op->type = R_ANAL_OP_TYPE_STORE;
        break;
    case FRI_OP_INCHAR:
        op->type = R_ANAL_OP_TYPE_IO;
        break;
    case FRI_OP_OUTCHAR:
        op->type = R_ANAL_OP_TYPE_IO;
        break;
    }

    return op->size;
}

static int set_reg_profile(RAnal *anal) {
	const char *p =
	"=PC    PC\n"
	"=SP    SP\n"
	"gpr    R0        .32 0    0\n"
	"gpr    R1        .32 4    0\n"
	"gpr    R2        .32 8    0\n"
	"gpr    R3        .32 12    0\n"
	"gpr    R4        .32 16    0\n"
	"gpr    R5        .32 20    0\n"
	"gpr    R6        .32 24    0\n"
	"gpr    R7        .32 28    0\n"
	"gpr    R8        .32 32    0\n"
	"gpr    SP        .32 24    0\n"
	"gpr    PC        .32 28    0\n"
	"gpr    BS        .32 32    0\n"
	"gpr    R9        .32 36    0\n"
	"gpr    R10        .32 40    0\n"
	"gpr    R11        .32 44    0\n"
	"gpr    R12       .32 48    0\n"
	"gpr    R13        .32 52    0\n"
	"gpr    R14        .32 56    0\n"
	"gpr    R15        .32 60    0\n";
	return r_reg_set_profile_string (anal->reg, p);
}

struct r_anal_plugin_t r_anal_plugin_fridge = {
	.name = "fridge",
	.desc = "RHME2 fridge analysis plugin",
	.license = "GPLv2",
	.arch = "fridge",
	.bits = 32,
	.esil = true,
	.init = NULL,
	.fini = NULL,
	.reset_counter = NULL,
	.archinfo = NULL,
	.op = &fridge_anal,
	.bb = NULL,
	.fcn = NULL,
	.analyze_fns = NULL,
	.op_from_buffer = NULL,
	.bb_from_buffer = NULL,
	.fn_from_buffer = NULL,
	.analysis_algorithm = NULL,
	.set_reg_profile = &set_reg_profile,
	.fingerprint_bb = NULL,
	.fingerprint_fcn = NULL,
	.diff_bb = NULL,
	.diff_fcn = NULL,
	.diff_eval = NULL,
	.pre_anal = NULL,
	.pre_anal_fn_cb = NULL,
	.pre_anal_op_cb = NULL,
	.post_anal_op_cb = NULL,
	.pre_anal_bb_cb = NULL,
	.post_anal_bb_cb = NULL,
	.post_anal_fn_cb = NULL,
	.post_anal = NULL,
	.revisit_bb_anal = NULL,
	.cmd_ext = NULL,
	.esil_init = NULL,
	.esil_post_loop = NULL,
	.esil_intr = NULL,
	.esil_trap = NULL,
	.esil_fini = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_fridge,
	.version = R2_VERSION
};
#endif
