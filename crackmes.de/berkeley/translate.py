import struct, sys

def translate(bfile):
	with open(bfile, 'r') as f:
		raw = f.read()

		l = len(raw) / 8

		res = [' '.join([str(x) for x in struct.unpack("<HBBL", raw[i*8:i*8+8])]) for i in xrange(l)]

		print ','.join([str(l)] + res)

if __name__ == "__main__":

	if len(sys.argv) < 2:
		translate("bpf.bin")
	else:
		translate(sys.argv[1])