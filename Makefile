

SYS := $(shell gcc -dumpmachine)

# LINUX
# The automated regression tests run on Linux, so this is the one
# environment where things likely will work -- as well as anything
# works on the bajillion of different Linux environments
ifneq (, $(findstring linux, $(SYS)))
LIBS = -lpcap -lm -lrt -ldl -rdynamic
INCLUDES = -I. -I../PF_RING/userland/lib
FLAGS2 = 
endif

# MAC OS X
# I occassionally develope code on Mac OS X, but it's not part of
# my regularly regression-test environment. That means at any point
# in time, something might be minorly broken in Mac OS X.
ifneq (, $(findstring darwin, $(SYS)))
LIBS = -lpcap -lm -rdynamic
INCLUDES = -I.
FLAGS2 = 
endif

# MinGW on Windows
# I develope on Visual Studio 2010, so that's the Windows environment
# that'll work. However, 'git' on Windows runs under MingGW, so one
# day I acccidentally typed 'make' instead of 'git, and felt compelled
# to then fix all the errors, so this kinda works now. It's not the
# intended environment, so it make break in the future.
ifneq (, $(findstring mingw, $(SYS)))
INCLUDES = -I. -Ivs10/include
LIBS = -L vs10/lib -lwpcap -lIPHLPAPI
FLAGS2 = -march=i686
endif

# Cygwin
# I hate Cygwin, use Visual Studio or MingGW instead. I just put this
# second here for completeness, or in case I gate tired of hitting my
# head with a hammer and want to feel a different sort of pain.
ifneq (, $(findstring cygwin, $(SYS)))
INCLUDES = -I.
LIBS = -lwpcap
FLAGS2 = 
endif


# this works on llvm or real gcc
CC = gcc

DEFINES = 
CFLAGS = -g $(FLAGS2) $(INCLUDES) $(DEFINES) -Wall -O3 -Wno-format
.SUFFIXES: .c .cpp

# just compile everything in the 'src' directory. Using this technique
# means that include file dependencies are broken, so sometimes when
# the program crashes unexpectedly, 'make clean' then 'make' fixes the
# problem that a .h file was out of date
tmp/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

SRC = $(wildcard src/*.c)
OBJ = $(addprefix tmp/, $(notdir $(addsuffix .o, $(basename $(SRC))))) 

bin/masscan: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LIBS)

clean:
	rm tmp/*.o
	rm bin/masscan

regress: bin/masscan
	bin/masscan --selftest

install: bin/masscan
	echo "No install, binary is bin/masscan"
	
default: bin/masscan
