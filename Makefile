# compiler and flags
CC = gcc
CFLAGS = Unknown still

# Name of output program
OUTPUT = packet_sniffer

# Source files
SRC = src/packet_sniffer.c

# Bootstrap
bootstrap:
  @echo "Project bootstrap commencing..."
  mkdir -p src logs
  @echo "Directories created :src/ and logs/"


# Build target
build: Unknown still
