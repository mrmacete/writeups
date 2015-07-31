
"""
output templates
"""
def output_const_32(const):
	return "0x%08x" % (const & 0xffffffff)

def output_const_16(const):
	return "0x%04x" % (const & 0xffff)

def output_const_8(const):
	return "0x%02x" % (const & 0xff)

def output_separator():
	return "   "

def output_mnemonic(mnemonic):
	return (mnemonic + (" " * (4-len(mnemonic)))).lower()

def output_register(idx):
	return "r%d" % idx

def output_comma():
	return ","

def output_3r(ip, mnemonic, r1, r2, r3):
	comps = [
		output_separator(),
		output_const_32(ip),
		output_separator(),
		output_mnemonic(mnemonic),
		output_register(r1) + output_comma(),
		output_register(r2) + output_comma(),
		output_register(r3)
	]
	return " ".join(comps)

def output_2r(ip, mnemonic, r1, r2):
	comps = [
		output_separator(),
		output_const_32(ip),
		output_separator(),
		output_mnemonic(mnemonic),
		output_register(r1) + output_comma(),
		output_register(r2)
	]
	return " ".join(comps)

def output_1r(ip, mnemonic, r1):
	comps = [
		output_separator(),
		output_const_32(ip),
		output_separator(),
		output_mnemonic(mnemonic),
		output_register(r1)
	]
	return " ".join(comps)

def output_1r_imm16(ip, mnemonic, r1, imm16):
	comps = [
		output_separator(),
		output_const_32(ip),
		output_separator(),
		output_mnemonic(mnemonic),
		output_register(r1) + output_comma(),
		output_const_16(imm16)
	]
	return " ".join(comps)

def output_1r_imm8(ip, mnemonic, r1, imm8):
	comps = [
		output_separator(),
		output_const_32(ip),
		output_separator(),
		output_mnemonic(mnemonic),
		output_register(r1) + output_comma(),
		output_const_8(imm8)
	]
	return " ".join(comps)

def output_0r(ip, mnemonic):
	comps = [
		output_separator(),
		output_const_32(ip),
		output_separator(),
		output_mnemonic(mnemonic)
	]
	return " ".join(comps)

def output_0r_imm32(ip, mnemonic, imm16):
	comps = [
		output_separator(),
		output_const_32(ip),
		output_separator(),
		output_mnemonic(mnemonic),
		output_const_32(imm16)
	]
	return " ".join(comps)

def to_signed16(number):
	if (number >> 15) != 0:
		return number - 0x10000
	return number


"""
instruction set
"""

def i8494_replace_lower_16(ip, idx, lower8, higher8):
	return output_1r_imm16(ip, "lli", idx, (higher8<<8) | lower8 )

def i8544_replace_higher_16(ip, idx, higher8, lower8):
	return output_1r_imm16(ip, "lui", idx, (higher8<<8) | lower8)

def i8be4_add_r1_r2_r3(ip, r1, r2, r3):
	return output_3r(ip, "add", r1, r2, r3)

def i85f8_jmp_if_eq_neq(ip, arg1, arg2, arg3):
	negative = arg1 >> 7

	target = ip + to_signed16((arg2<<8) | arg3)

	if negative == 1:
		return output_0r_imm32(ip, "jne", target)
	else:
		return output_0r_imm32(ip, "je", target)
	# if arg1 is < 0 is jne else is je

def i8750_cmp_r1_r2(ip, r1, r2, r3):
	return output_2r(ip, "cmp", r1, r2)

def i8820_push_r1(ip, r1, r2, r3):
	return output_1r(ip, "push", r1)

def i88e0_pop_r1(ip, r1, r2, r3):
	return output_1r(ip, "pop", r1)


def i8b34_sub_r1_r2_r3(ip, r1, r2, r3):
	return output_3r(ip, "sub", r1, r2, r3)

def i89a0_shift_r1_const8_lR(ip, r1, const8, direction):
	
	if direction == 1:
		return output_1r_imm8(ip, "shr", r1, const8)
	else:
		return output_1r_imm8(ip, "shl", r1, const8)


def i8a84_xor_r1_r2_r3(ip, r1, r2, r3):
	return output_3r(ip, "xor", r1, r2, r3)

def i0x8c94_nop(ip):
	return output_0r(ip, "nop")

def print_disassembly():

	"""
	this program is directly ripped from binary starting at vaddr 0x8f00
	all instructions are 32-bit wide
	"""
	program = [
		0x37200600,
		0x79b90700,
		0xefc60601,
		0x379e0701,
		0x01000005,
		0x01010906,
		0x01050908,
		0x05090902,
		0x06000a02,
		0x01030005,
		0x01010b06,
		0x00040b08,
		0x040b0b02,
		0x0a0b0c09,
		0x090c0c09,
		0x0c010107,
		0x09000105,
		0x08080906,
		0x01050908,
		0x03090902,
		0x06010a02,
		0x04020105,
		0x01010b06,
		0x00040b08,
		0x020b0b02,
		0x0a0b0c09,
		0x090c0c09,
		0x0c000007,
		0x00010e00,
		0x00000e01,
		0x0e080802,
		0x010d0804,
		0x07060607,
		0xe3ff8103,
		0xaafe0200,
		0x31a30300,
		0x01ba0201,
		0xffbb0301,
		0x00000204,
		0x03008103,
		0x00010000,
		0x00000001,
		0x01010304,
		0x03008103,
		0x00010100,
		0x00000101,

		0x01010263,
		0x01010263,
		0x01010263,
		0x01010263
	]
	

	jumptab = [
		i8494_replace_lower_16, 	#0x8494,
		i8544_replace_higher_16, 	#0x8544,
		i8be4_add_r1_r2_r3,		    #0x8be4,     
		i85f8_jmp_if_eq_neq,		#0x85f8     
		i8750_cmp_r1_r2, 			#0x8750,     
		i8820_push_r1, 				#0x8820,
		i88e0_pop_r1, 				#0x88e0,     
		i8b34_sub_r1_r2_r3, 		#0x8b34,     
		i89a0_shift_r1_const8_lR, 	#0x89a0,
		i8a84_xor_r1_r2_r3,			#0x8a84,

		i0x8c94_nop,				#0x8c94,     
		i0x8c94_nop,     
		i0x8c94_nop
	]

	for pc in xrange(len(program)):
		instruction = program[pc]

		# split instruction in bytes
		ibytes = [(instruction & (0xff << ib * 8)) >> (ib*8) for ib in xrange(4)]
		if ibytes[0] > len(jumptab):
			print i0x8c94_nop(pc)
			break

		# instruction set lookup
		jmp_addr = jumptab[ibytes[0]]

		# print disassembly for this instruction
		print jmp_addr(pc, ibytes[1], ibytes[2], ibytes[3])


if __name__ == "__main__":
	print_disassembly()