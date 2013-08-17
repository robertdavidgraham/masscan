
LIBS = -lpcap -lm -lrt
INCLUDES = -I.
DEFINES = 
CC = gcc
CFLAGS = -g $(INCLUDES) $(DEFINES) -Wall -O3 -rdynamic
.SUFFIXES: .c .cpp

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
