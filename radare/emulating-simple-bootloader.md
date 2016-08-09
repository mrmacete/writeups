# Emulating a simple bootloader

## Introduction

Generally speaking, emulating a bootloader is simpler than it is for regular binaries, because they lack external libraries and usually have direct access to memory and hardware.

In this case, the bootloader is a binary for x86 architecture which runs in 16-bits real mode using [BIOS calls](http://www.ctyme.com/intr/int.htm) to perform its loading duties and textual input/output.

The idea here is to emulate [Cropta1 crackme](http://crackmes.de/users/cropta/cropta_1/) using radare2 ESIL emulation, providing the needed BIOS via a trivial quick & dirty python implementation of just what it's needed to run the crackme code.

There are several ways to do it, I tried two of them and here is the story.

## Take one, use r2pipe

Whenever i use r2pipe i feel home, moreover there's an example (in nodejs) of a similar case - [the emulation of syscalls](https://github.com/radare/radare2-bindings/tree/master/r2pipe/nodejs/examples/syscall) - that's why it's the first thing i tried.

My bios looked like this:

```python
import r2pipe, sys, os, json

r2 = r2pipe.open('#!pipe')

# just the hdd params stolen from bochsrc
cylinders=20
heads=16
spt=63
bps=512

# function to read a key from stdin
def wait_key():
	result = None
	if os.name == 'nt':
		import msvcrt
		result = msvcrt.getch()
	else:
		import termios
		fd = sys.stdin.fileno()
		oldterm = termios.tcgetattr(fd)
		newattr = termios.tcgetattr(fd)
		newattr[3] = newattr[3] & ~termios.ICANON & ~termios.ECHO
		termios.tcsetattr(fd, termios.TCSANOW, newattr)
		try:
			result = sys.stdin.read(1)
		except:
			pass
		finally:
			termios.tcsetattr(fd, termios.TCSAFLUSH, oldterm)
		return result


# this handles the interrupts
def handle_intr(intNum):
	regs = json.loads(r2.cmd('arj'))

	# helper funcs to read/write hi and low parts of regs
	def xh(regName, setValue = None):
		val = regs[regName]
		if setValue == None:
			return (val & 0xff00)>>8
		else:
			val = (val & 0xff) | ((setValue & 0xff) << 8)
			r2.cmd('ar ' + regName + '=' + hex(val))
			return val

	def xl(regName, setValue = None):
		val = regs[regName]
		if setValue == None:
			return val & 0xff
		else:
			val = (val & 0xff00) | (setValue & 0xff)
			r2.cmd('ar ' + regName + '=' + hex(val))
			return val

	# command is in ah
	command = xh('ax') 

	# read/write disk
	if intNum == 0x13: 
		# read from disk to memory
		if command == 2:
			# al, number of sectors to read
			nSectors = xl('ax')
			
			# ch, cylinder
			cylinder = xh('cx')
			
			# cl, sector
			firstSector = xl('cx')
			
			# dh, head
			head = xh('dx') 
			
			# bx, buffer in memory
			destination = regs['bx'] & 0xffff

			# hdd math
			source = (firstSector - 1 + (head + cylinder * heads) * spt ) * bps
			length = nSectors * bps

			# do the actual writing in r2
			r2.cmd('e io.cache=true')
			r2.cmd('wd ' + hex(source) + ' ' + hex(length) + ' @ ' + hex(destination))
			
			# success -> carry flag = 0
			r2.cmd('ar cf=0')
		
		# geometry query
		elif command == 8: 
			# dl drive number
			driveNum = xl('dx')
			
			if driveNum != 0x80:
				# if not first drive, error -> carry flag = 1
				r2.cmd('ar cf=1')
			else:
				# success, return geometry
				r2.cmd('ar cf=0')
				r2.cmd('ar ax=0')
				r2.cmd('ar dx=' + hex(((heads-1) << 8) | 1))
				r2.cmd('ar cx=' + hex(spt | (cylinders << 8)))

	# keyboard i/o
	elif intNum == 0x16: 
		# read extended key
		if command == 0x10:
			result = ord(wait_key())
			high = 0
			if result == 10:
				high = 0x1c
			elif result == 127:
				high = 0xe
			r2.cmd('ar ax=' + hex(result | (high << 8)))

	# screen output
	elif intNum == 0x10:
		# print char
		if command == 0xe:
			char = chr(xl('ax'))
			sys.stdout.write(char)
			sys.stdout.flush()

# call it, with parameter coming from r2
handle_intr(int(sys.argv[1], 0))
```

The above code is far from being a complete BIOS implementation, or even to be a correct subset: it's just what the crackme uses in its interesting part - the initial.

Running this in radare2 is as easy as doing:

```r2
$ r2 -b 16 HardDisk
 -- Choose your architecture by typing: 'e asm.arch=<arch>'
[0000:0000]> aei
[0000:0000]> aeim 0x2000 0xffff
[0000:0000]> aeip
[0000:0000]> e io.cache=true
[0000:0000]> "e cmd.esil.intr=#!pipe python bios_pipe.py"
[0000:0000]> e esil.gotolimit=0xffff
[0000:0000]> ! (sleep 30 && killall -3 r2)&
[0000:0000]> aec
```

The following paragraph (Emulation setup) is an explosion of the above r2 commands with a lengthy explanation of each, feel free to skip it if the above r2 passage is obvious to you.

### Emulation setup
--

```r2
[0000:0000]> aei
```
`aei` initializes the ESIL VM state (as stated in `ae?` help) which means if there was a previous ESIL context is destroyed here and a new ESIL stack gets deployed.

--

```r2
[0000:0000]> aeim 0x2000 0xffff
```
`aeim` allocates the memory for mem read / write operations, basically needed for the stack pointer to point somewhere harmless.

Here i'm placing the start of it at address `0x2000` with a length of `0xffff` bytes. The value for the start value is exactly the size of the binary, so that memory writes will likely not overwrite the code.

At the beginning of the bootloader code the stack pointer is placed at address `0x7c00`, so it can grow for `23552` bytes before potentially overlapping to the code. It may or may not be enough, hopefully it is for this simple case.

In more complex cases of boot loader, maybe it's necessary to keep the memory in one file descriptor and the code in another. This is possible for example by using temporary file descriptor seeks in r2 read / write commands.

--

```r2
[0000:0000]> aeip
```
This will set the ESIL instruction pointer (and the IP alias register of the current architecture, as specified in the register profile of the anal plugin) to the current seek, namely `0`.

--

```r2
[0000:0000]> e io.cache=true
```
This let us write in the current session's memory without having r2 to write it back to the binary file.

--

```r2
[0000:0000]> "e cmd.esil.intr=#!pipe python bios_pipe.py"
```
This, in pseudo english, means: "Every time there's an ESIL interrupt (`$` instruction), spawn this python script and pass it the number of the interrupt as argument". This will load and execute the bios depicted above.

--

```r2
[0000:0000]> e esil.gotolimit=0xffff
```
This one. It took me a couple of hours to figure out what that `ESIL infinite loop detected` error message did mean.

The failing instruction was: `rep movsb byte es:[di], byte ptr [si]` which is known to be bounded by the `cx` value, which was itself conveniently set to the very finite value of `0x1e5` just few bytes above... so?

It turns out that the `gotolimit` is the maximum allowed count of single ESIL instructions which can be executed in a statement - and that's great. In this case, the esil statement for the above failing instruction is: 

```esil
cx,!,?{,BREAK,},si,[1],di,=[1],df,?{,1,si,-=,1,di,-=,},df,!,?{,1,si,+=,1,di,+=,},cx,--=,cx,?{,5,GOTO,}
```

which is composed by `35` esil instructions, so doing the rough math `?v 35*0x1e5` = `0x424f` which is clearly greater than the default `esil.gotolimit = 0x00001000` even if we ignore the fact that the `GOTO` jumps to instruction 5 and not to the beginning of the statement.

--

```r2
[0000:0000]> ! (sleep 30 && killall -3 r2)&
```
At the end of the emulated code, the bootloader code enters an infinite loop. This is a dirty trick to schedule r2 quit at 30 seconds from now whatever happens (included that you may have closed an r2 session and opened another one in the meantime...).

This particular one needs a posix shell to work.

--

```r2
[0000:0000]> aec
```
Starts the emulation until CTRL+C is pressed, if you have a chance to, if CTRL+C is honored by both radare2 and the spawned python code which may be running continuously at that time. Basically, in this case, it means run the emulation forever (due to the final infinite loop) or until r2 is killed by the dirty trick above.

### Cinema of take one

[![asciicast](https://asciinema.org/a/88nezce35db4uo28qvlk4y5vc.png)](https://asciinema.org/a/88nezce35db4uo28qvlk4y5vc)

This demonstration shows all the above actually works, but - unless you're shooting an 1980s sci-fi B-movie - it's spectacularly slow for every real world use case.

## Take two, using r2lang + python RCore plugin

At that point, also after talking to pancake about this, there could be several reasons for it to be so slow, sorted by probability (more probable first):

* spawning python intepreter at each interrupt is slow
* my shitty python code is slow
* python in general is slow
* ESIL emulation is slow

Starting to address the more probable issue, an alternative way to do this - while still using my python BIOS - is to define an RCore plugin which accepts a new 'bios' command. In this way the python code is loaded only once and then at each interrupt the command itself gets executed, reusing the same python context.

Here is the modifications to the python code above:

1 - instead of importing `r2pipe`, let's import `r2lang`:

```python
import r2lang, sys, os, json
r2 = r2lang
```

2 - replace missing `cmdj` with native python `json.loads` in bios code:

```python
# this handles the interrupts
def handle_intr(intNum):
	regs = json.loads(r2.cmd('arj'))
	...
```

3 - register the core plugin:

```python
def bioscore(a):
	def _call(s):
		if s == "bios":
			ip = int(r2.cmd("ar ip"),0) - 2
			num = int(r2.cmd("?v $v@" + hex(ip)),0)
			handle_intr(num)
			return 1
		return 0

	return {
		"name" : "BiosCore",
		"license": "WTFPL",
		"desc": "toy bios",
		"call": _call
	}


r2lang.plugin("core", bioscore)
```

The most evident issue so far is that the custom commands defined in RCore plugins don't accept parameters, therefore here is another dirty trick.

In order to get the numeric value of the interrupt, i decided to use the `$v` variable which returns the immediate value of the instruction at the current seek. The problem here is that during emulation, the instruction pointer has been already incremented by the time the interrupt gets executed. So, assuming that x86 16-bit encoding of `INT XX` instructions is always 2 bytes long, i just subtracted `2` to current `ip` value in order to get the seek for the immediate value to extract.

And again, the execution sequence:

```r2
$ r2 -i bios.py -b 16 HardDisk
 -- You are probably using an old version of r2, go checkout the git!
[0000:0000]> aei
[0000:0000]> aeim 0x2000 0xffff
[0000:0000]> aeip
[0000:0000]> e io.cache=true
[0000:0000]> (orpo, bios)
[0000:0000]> "e cmd.esil.intr=` `;.(orpo)"
[0000:0000]> e esil.gotolimit=0xffff
[0000:0000]> ! (sleep 30 && killall -3 r2)&
[0000:0000]> aec
```

### Emulation setup (differences)

--

```r2
[0000:0000]> (orpo, bios)
```
Again, custom commands do not accept parameters. More: if they're called with a parameter, they don't get executed at all.

To overcome this limitation, i just defined a macro named `orpo`. In this way, the extra unusable parameter which r2 pass to the `intr` handler is just ignored and the custom command is called.

--

```r2
[0000:0000]> "e cmd.esil.intr=` `;.(orpo)"
```
Here is the modified `intr` handler which in turn calls our macro, which in turn calls our custom command.

Buried in the above command line there's also another mystery i lost an interesting hour to workaround. That space in backticks. By removing that, each char which is output from my BIOS command gets prepended by what it seems the output of a `printf("0x%x\n", somevalue);` buried somewhere along the r2 code path around the interrupt handling / r2lang io piping (i guess, but actually i was unable to find it).

### Cinema of take two

[![asciicast](https://asciinema.org/a/6q6cvq2i1xdwsjrq2o5we4vad.png)](https://asciinema.org/a/6q6cvq2i1xdwsjrq2o5we4vad)

Hey! This time is faster. Still there's space for improvements, i guess it's possible to go down the list of slowdown probability unrolled above until rewriting the BIOS in C, for example. Honestly enough, though, the python RCore plugin seems pretty fast to me.

(by mrmacete)
