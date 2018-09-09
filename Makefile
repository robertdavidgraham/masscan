#use llvm by default, GNU C otherwise
CC=clang

PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
SYS := $(shell $(CC) -dumpmachine)
GITVER := $(shell git describe --tags)
INSTALL_DATA := -pDm755

ifeq ($(GITVER),)
GITVER = "unknown"
endif

# LINUX
# The automated regression tests run on Linux, so this is the one
# environment where things likely will work -- as well as anything
# works on the bajillion of different Linux environments
ifneq (, $(findstring linux, $(SYS)))
LIBS = -lm -lrt -ldl -lpthread
INCLUDES =
FLAGS2 = 
endif

# MAC OS X
# I occassionally develope code on Mac OS X, but it's not part of
# my regularly regression-test environment. That means at any point
# in time, something might be minorly broken in Mac OS X.
ifneq (, $(findstring darwin, $(SYS)))
LIBS = -lm 
INCLUDES = -I.
FLAGS2 = 
INSTALL_DATA = -pm755
endif

# MinGW on Windows
# I develope on Visual Studio 2010, so that's the Windows environment
# that'll work. However, 'git' on Windows runs under MingGW, so one
# day I acccidentally typed 'make' instead of 'git, and felt compelled
# to then fix all the errors, so this kinda works now. It's not the
# intended environment, so it make break in the future.
ifneq (, $(findstring mingw, $(SYS)))
INCLUDES = -Ivs10/include
LIBS = -L vs10/lib -lIPHLPAPI -lWs2_32
FLAGS2 = -march=i686
endif

# Cygwin
# I hate Cygwin, use Visual Studio or MingGW instead. I just put this
# second here for completeness, or in case I gate tired of hitting my
# head with a hammer and want to feel a different sort of pain.
ifneq (, $(findstring cygwin, $(SYS)))
INCLUDES = -I.
LIBS = 
FLAGS2 = 
endif

# OpenBSD
ifneq (, $(findstring openbsd, $(SYS)))
LIBS = -lm -lpthread
INCLUDES = -I.
FLAGS2 = 
endif

# FreeBSD
ifneq (, $(findstring freebsd, $(SYS)))
LIBS = -lm -lpthread
INCLUDES = -I.
FLAGS2 =
endif


DEFINES = 
CFLAGS = -g -ggdb $(FLAGS2) $(INCLUDES) $(DEFINES) -Wall -O3
.SUFFIXES: .c .cpp

all: bin/masscan 


tmp/main-conf.o: src/main-conf.c src/*.h
	$(CC) $(CFLAGS) -c $< -o $@ -DGIT=\"$(GITVER)\"


# just compile everything in the 'src' directory. Using this technique
# means that include file dependencies are broken, so sometimes when
# the program crashes unexpectedly, 'make clean' then 'make' fixes the
# problem that a .h file was out of date
tmp/%.o: src/%.c src/*.h
	$(CC) $(CFLAGS) -c $< -o $@


SRC = $(sort $(wildcard src/*.c))
OBJ = $(addprefix tmp/, $(notdir $(addsuffix .o, $(basename $(SRC))))) 


bin/masscan: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS) $(LIBS)

clean:
	rm -f tmp/*.o
	rm -f bin/masscan

regress: bin/masscan
	bin/masscan --selftest

test: regress

install: bin/masscan
	install $(INSTALL_DATA) bin/masscan $(DESTDIR)$(BINDIR)/masscan
	
default: bin/masscan
