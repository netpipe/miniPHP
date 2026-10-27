# Define the compiler to use
CC = gcc

# Define compiler flags
# -Wall turns on most compiler warnings
# -g adds debugging information to the executable
CFLAGS = -Wall -g

# SQLite is bundled (sqlite/sqlite3.c, the official single-file amalgamation).
#   THREADSAFE=0          each CGI request is one process, one thread
#   OMIT_LOAD_EXTENSION   SQL cannot load native code, even through an
#                         SQL-injection bug in a script
#   MATH_FUNCTIONS, FTS5  sqrt(), full-text search -- as in PHP's SQLite
# To build without SQLite: make nosqlite
SQLITE_FLAGS = -O2 -DSQLITE_THREADSAFE=0 -DSQLITE_OMIT_LOAD_EXTENSION \
               -DSQLITE_DEFAULT_MEMSTATUS=0 -DSQLITE_OMIT_DEPRECATED \
               -DSQLITE_ENABLE_MATH_FUNCTIONS -DSQLITE_ENABLE_FTS5

# libsodium is optional: PHP's sodium_* functions and SODIUM_* constants.
#   make SODIUM=1        the bundled copy in libsodium/ (1.0.22, signature-
#                        checked, see libsodium/README.md); no install needed
#   make SODIUM=system   the system's own (apt install libsodium-dev)
#   make                 without it: sodium_* are undefined functions, as in
#                        a PHP built without ext/sodium
SODIUM ?= 0
# Portable C for every CPU (no SIMD, no assembly); randomness from the kernel
SODIUM_CFLAGS = -O2 -DCONFIGURED=1 -D_GNU_SOURCE -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 \
                -Ilibsodium/include -Ilibsodium/include/sodium
SODIUM_SRC = $(shell find libsodium -name '*.c' 2>/dev/null)
SODIUM_OBJ = $(SODIUM_SRC:.c=.o)

ifeq ($(SODIUM),1)
  CFLAGS += -DMINIPHP_SODIUM -Ilibsodium/include
  SODIUM_LIB = libsodium/libsodium.a
  SODIUM_LINK = libsodium/libsodium.a
else ifeq ($(SODIUM),system)
  CFLAGS += -DMINIPHP_SODIUM
  SODIUM_LINK = -lsodium
endif

# Define the final executable name
TARGET = miniPHP

# The first rule is the default target executed when you just run 'make'
all: $(TARGET)

# Rule to link the object files and create the final executable
$(TARGET): main.o sqlite/sqlite3.o $(SODIUM_LIB)
	$(CC) $(CFLAGS) -o $(TARGET) main.o sqlite/sqlite3.o $(SODIUM_LINK) -lm

# Rule to compile main.c into main.o
main.o: main.c sqlite/sqlite3.h .cflags
	$(CC) $(CFLAGS) -c main.c

# main.o is rebuilt whenever the flags change, so going from make to
# make SODIUM=1 (or back) cannot link a stale main.o
.cflags: FORCE
	@echo '$(CFLAGS)' | cmp -s - $@ || echo '$(CFLAGS)' > $@

# SQLite takes a while to compile (it is ~270,000 lines); make only
# rebuilds it when sqlite3.c itself changes
sqlite/sqlite3.o: sqlite/sqlite3.c sqlite/sqlite3.h
	$(CC) $(SQLITE_FLAGS) -c sqlite/sqlite3.c -o sqlite/sqlite3.o

# libsodium: ~140 small files, built once into a static library
libsodium/libsodium.a: $(SODIUM_OBJ)
	ar rcs $@ $(SODIUM_OBJ)

libsodium/%.o: libsodium/%.c
	$(CC) $(SODIUM_CFLAGS) -c $< -o $@

# main.c on its own, as before SQLite: sqlite_* functions are then undefined
nosqlite: $(SODIUM_LIB)
	$(CC) $(CFLAGS) -DMINIPHP_NO_SQLITE -o $(TARGET) main.c $(SODIUM_LINK) -lm

# Target to clean up the directory by removing built files
.PHONY: clean nosqlite FORCE
clean:
	rm -f $(TARGET) *.o sqlite/*.o libsodium/libsodium.a .cflags
	find libsodium -name '*.o' -delete
