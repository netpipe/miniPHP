# Define the compiler to use
CC = gcc

# Define compiler flags
# -Wall turns on most compiler warnings
# -g adds debugging information to the executable
CFLAGS = -Wall -g

# Define the final executable name
TARGET = miniPHP

# The first rule is the default target executed when you just run 'make'
all: $(TARGET)

# Rule to link the object files and create the final executable
$(TARGET): main.o
	$(CC) $(CFLAGS) -o $(TARGET) main.o


# Rule to compile main.c into main.o
main.o: main.c
	$(CC) $(CFLAGS) -c main.c

# Target to clean up the directory by removing built files
.PHONY: clean
clean:
	rm -f $(TARGET) *.o
