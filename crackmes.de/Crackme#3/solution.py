import string
import random

def random4():
	chars = 'ABCDEFGHIJKLMNOPQRSTUVW' + string.digits
	return ''.join(random.choice(chars) for _ in range(4))

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

def gen_num(a,b,c):
	res = 1
	while a > 0:
		lsb = a & 1
		if lsb == 1:
			res = (res * b) % c
		
		a = a >> 1
		b = (b * b) % c

	return res

def fmod(a,b,c):
	return (a*b) % c

def check_serial(username, serial):
	ss = serial.split('-')

	magic = 0x7e4c9e32
	for c in username:
		magic = (ord(c) * magic) & 0xffffffff

	mm = [magic & 0xff]

	a = mangle_string(ss[0], mm)

	b = mangle_string(ss[1], mm)

	x = gen_num(0xf2a5, b, 0xf2a7)
	xa = fmod(x, magic, 0xf2a7)
	xb = fmod(a, x, 0xf2a7)

	y = gen_num(xa, 0x15346, 0x3ca9d)
	z = gen_num(xb, 0x307c7, 0x3ca9d)

	w = fmod(z, y, 0x3ca9d)

	return (w % 0xf2a7) == a


def generate_serial(username):
	while True:
		ss = [random4(), random4()]
		if check_serial(username, '-'.join(ss)):
			print '-'.join(ss)
			break

	
if __name__ == "__main__":
	generate_serial("porcodio")