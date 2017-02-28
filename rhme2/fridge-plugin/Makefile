R2_PLUGIN_PATH=$(shell r2 -hh|grep plugins|grep user|awk '{print $$2}')
R2_INCLUDE_PATH=$(shell r2 -hh|grep INCDIR|awk '{print $$2}')
R2_LIB_PATH=$(shell r2 -hh|grep LIBDIR|awk '{print $$2}')
CFLAGS=-g -fPIC
CFLAGS+=-I$(R2_INCLUDE_PATH)
SUDO=sudo

LDFLAGS=-shared -L$(R2_LIB_PATH) -lr_util -lr_parse

EXT_SO=$(shell r2 -hh|grep LIBEXT|awk '{print $$2}')

CC_ASM=$(CC) $(CFLAGS) $(LDFLAGS) $(shell pkg-config --libs r_asm)
CC_ANA=$(CC) $(CFLAGS) $(LDFLAGS) $(shell pkg-config --libs r_anal)

all:
	$(CC_ASM) -o asm_fridge.$(EXT_SO) asm_fridge.c
	$(CC_ANA) -o anal_fridge.$(EXT_SO) anal_fridge.c

install: all
	cp -f *.$(EXT_SO) $(R2_PLUGIN_PATH)

uninstall:
	for a in *.$(EXT_SO) ; do rm -f $(R2_PLUGIN_PATH)/$$a ; done

clean:
	rm -f *.$(EXT_SO)
	rm -rf *.$(EXT_SO).dSYM
