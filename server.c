#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <pthread.h>

#define CONNECTIONS_LIMIT 5
#define MAX_CLIENTS 10

int clients[MAX_CLIENTS] = {0};
pthread_mutex_t clients_lock = PTHREAD_MUTEX_INITIALIZER;

int setup(int port) {
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        printf("Failed to create socket.\n");
        return -1;
    }

    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int)) < 0) {
        printf("Failed to set socket options.\n");
        return -1;
    }

    if (bind(server_socket, (struct sockaddr *)&server, sizeof(server)) < 0) {
        printf("Failed to bind socket fd with server address.\n");
        return -1;
    }

    if (listen(server_socket, CONNECTIONS_LIMIT) < 0) {
        printf("Failed to start server listener.\n");
        return -1;
    }

    return server_socket;
}

void *client_handler(void *arg) {
    int client = *(int *)arg;
    free(arg);

    printf("<=> Client Connected: Thread = [%lu], Client = [%d]\n", pthread_self(), client);

    for (;;) {
        int selection;
        ssize_t bytes = recv(client, &selection, sizeof(selection), 0);

        if (bytes == 0) {
            break;
        }

        if (bytes < 0) {
            printf("Failed to receive data.\n");
            break;
        }

        if (selection == 1) {
            char msg[100];
            ssize_t msg_bytes = recv(client, msg, sizeof(msg) - 1, 0);
            if (msg_bytes <= 0) {
                if (msg_bytes < 0)
                    printf("Failed to receive data.\n");
                break;
            }

            msg[msg_bytes] = '\0';
            printf("Message from [%d]: %s\n", client, msg);
        } else {
            printf("Test Information: Thread = [%lu], Client = [%d], Selection = [%d]\n",
                   pthread_self(), client, selection);
        }
    }

    close(client);

    pthread_mutex_lock(&clients_lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] == client) {
            clients[i] = 0;
            break;
        }
    }
    pthread_mutex_unlock(&clients_lock);

    printf("</> Client Disconnected: Thread = [%lu], Client = [%d]\n", pthread_self(), client);
    pthread_exit(NULL);
}

int main(void) {
    int port;
    printf("[Server]: Port to start server on?\n");
    scanf("%d", &port);

    int server_socket = setup(port);
    if (server_socket < 0) {
        printf("Failed to set server up.\n");
        return 1;
    }

    printf("[Server]: Listening on port %d\n", port);

    while (1) {
        int *client = malloc(sizeof(int));
        if (!client) {
            printf("Failed to allocate memory for the client.\n");
            continue;
        }

        *client = accept(server_socket, NULL, NULL);
        if (*client < 0) {
            printf("Failed to accept client.\n");
            free(client);
            continue;
        }

        pthread_mutex_lock(&clients_lock);
        int slot_found = 0;
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i] == 0) {
                clients[i] = *client;
                slot_found = 1;
                break;
            }
        }
        pthread_mutex_unlock(&clients_lock);

        if (!slot_found) {
            printf("[Server]: Max client limit reached, rejecting [%d]...\n", *client);
            close(*client);
            free(client);
            continue;
        }

        pthread_t tid;
        if (pthread_create(&tid, NULL, client_handler, client) != 0) {
            printf("Failed to spawn thread.\n");
            close(*client);
            free(client);
            continue;
        }

        pthread_detach(tid);
    }

    close(server_socket);
    return 0;
}