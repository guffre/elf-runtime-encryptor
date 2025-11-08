# Compiler and target
CC = gcc
TARGET = sample
SRC = enc.c sample.c

COMMON_FLAGS = -Wall -Wextra -finstrument-functions
CFLAGS = $(COMMON_FLAGS) -O2

# Default target
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) -ldl

# Debug build (no optimization, debug info)
debug: CFLAGS = $(COMMON_FLAGS) -O0 -g -DDEBUG
debug: clean $(TARGET)

# Clean target
clean:
	rm -f $(TARGET)
