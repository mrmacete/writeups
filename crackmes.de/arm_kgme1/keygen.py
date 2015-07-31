import random

def combine(seed, a,b,c):
	r9 = ((a >> 5) + b) & 0xffffffff
	r10 = (a + seed) & 0xffffffff
	r11 = (((a << 4) & 0xffffffff)+ c) & 0xffffffff
	return r11 ^ r10 ^ r9


def validate(serial):
	r6 = 0xc6ef3720
	r7 = 0x9e3779b9

	for i in xrange(32):
		r12 = combine(r6, serial[0], serial[5], serial[4])
		serial[1] = (serial[1] - r12) & 0xffffffff
		r12 = combine(r6, serial[1], serial[3], serial[2])
		serial[0] = (serial[0] - r12) & 0xffffffff
		r6 = (r6 - r7) & 0xffffffff

	return serial[0] == 0xba01aafe and serial[1] == 0xbbff31a3


def keygen():
	"""
	this is the reverse of the above validate()
	"""
	
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



if __name__ == "__main__":

	# generate 100 random valid serials
	for i in xrange(100):
		s = keygen()
		print ",".join(["%x" % c for c in s])
			
