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

# Define the final executable name
TARGET = miniPHP

# The first rule is the default target executed when you just run 'make'
all: $(TARGET)

# Rule to link the object files and create the final executable
$(TARGET): main.o sqlite/sqlite3.o
	$(CC) $(CFLAGS) -o $(TARGET) main.o sqlite/sqlite3.o -lm

# Rule to compile main.c into main.o
main.o: main.c sqlite/sqlite3.h
	$(CC) $(CFLAGS) -c main.c

# SQLite takes a while to compile (it is ~270,000 lines); make only
# rebuilds it when sqlite3.c itself changes
sqlite/sqlite3.o: sqlite/sqlite3.c sqlite/sqlite3.h
	$(CC) $(SQLITE_FLAGS) -c sqlite/sqlite3.c -o sqlite/sqlite3.o

# main.c on its own, as before SQLite: sqlite_* functions are then undefined
nosqlite:
	$(CC) $(CFLAGS) -DMINIPHP_NO_SQLITE -o $(TARGET) main.c -lm

# Target to clean up the directory by removing built files
.PHONY: clean nosqlite
clean:
	rm -f $(TARGET) *.o sqlite/*.o
