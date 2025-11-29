CC = gcc
CFLAGS = -Wall -g -pthread

# Targets
SERVER = server
CLIENT = client

# Object Files
SERVER_OBJS = server.o
CLIENT_OBJS = client.o

# Default Targets
all: $(SERVER) $(CLIENT)

# Link Rules
$(SERVER): $(SERVER_OBJS)
	$(CC) $(CFLAGS) -o $@ $(SERVER_OBJS)

$(CLIENT): $(CLIENT_OBJS)
	$(CC) $(CFLAGS) -o $@ $(CLIENT_OBJS)

# Generic rule for .c -> .o
%.o: %.c
	$(CC) $(CFLAGS) -c $<

# QOL
run_server: $(SERVER)
	./$(SERVER)

run_client: $(CLIENT)
	./$(CLIENT)

# Clean Rule
.PHONY: all clean run_server run_client
clean:
	rm -f $(SERVER) $(CLIENT) $(SERVER_OBJS) $(CLIENT_OBJS)
