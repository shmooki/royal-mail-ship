CC := gcc
CFLAGS := -std=c11 -Wall -Wextra -O2 -g
LDFLAGS := -pthread

SRCS_COMMON := rsa.c utility.c
SRCS_SERVER := server.c
SRCS_CLIENT := client.c

OBJS_COMMON := $(SRCS_COMMON:.c=.o)
OBJS_SERVER := $(SRCS_SERVER:.c=.o)
OBJS_CLIENT := $(SRCS_CLIENT:.c=.o)

.PHONY: all clean

all: server client

server: $(OBJS_COMMON) $(OBJS_SERVER)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

client: $(OBJS_COMMON) $(OBJS_CLIENT)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Generic rule to build .o from .c
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS_COMMON) $(OBJS_SERVER) $(OBJS_CLIENT) server client
