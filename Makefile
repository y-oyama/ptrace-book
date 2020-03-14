CC	= gcc

ARCH = $(shell arch)

ifeq ($(ARCH),x86_64)
NBITS	= 64
else
ifeq ($(ARCH),arm)
NBITS	= 32
else
NBITS	= 64
endif
endif

ifeq ($(NBITS),64)
CFLAGS	= -Wall -g
else
ifeq ($(NBITS),32)
# To silence warning of "%d" and "%ld"
CFLAGS	= -Wall -g -Wno-format
else
CFLAGS	= -Wall -g
endif
endif

OBJS	= ntrace.o sandbox.o util.o
TARGETS	= ntrace sandbox

all: ntrace sandbox

ntrace: ntrace.o util.o
	$(CC) -o ntrace ntrace.o util.o
ntrace.o: ntrace.c syscall_table.h

sandbox: sandbox.o util.o
	$(CC) -o sandbox sandbox.o util.o
sandbox.o: sandbox.c syscall_table.h

ifeq ($(ARCH),x86_64)
syscall_table.h: gen_syscall_table_x64.py
	cat /usr/include/x86_64-linux-gnu/asm/unistd_64.h | ./gen_syscall_table_x64.py > syscall_table.h
else
ifeq ($(ARCH),arm)
syscall_table.h: gen_syscall_table_arm.py
	cat /usr/include/arm-linux-gnueabihf/asm/unistd.h | ./gen_syscall_table_arm.py > syscall_table.h
else
endif
endif

clean:
	rm -f $(OBJS) $(TARGETS)
superclean:
	rm -f $(OBJS) $(TARGETS) syscall_table.h
