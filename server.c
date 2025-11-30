// server.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/stat.h>

#include "utility.h"
#include "rsa.h"
#include "server_info.h"
#include "client_info.h"
#include "encrypted_packet.h"

// Server File Descriptor
int server_fd;

// RSA Keys
long s_n, s_e, s_d;
long c_n, c_e;

// Client Management
pthread_mutex_t c_lock = PTHREAD_MUTEX_INITIALIZER;
struct client clients[CLIENTS_LIMIT] = {};
int num_clients = 0;

int insert_client(struct client *new_client) {
    pthread_mutex_lock(&c_lock);

    for (int i = 0; i < CLIENTS_LIMIT; i++) {
        if (clients[i].socket_fd == -1) {
            clients[i] = *new_client;
            num_clients++;
            pthread_mutex_unlock(&c_lock);
            return 0;
        }
    }

    pthread_mutex_unlock(&c_lock);
    return -1;
}

void rsa_handshake(int client_fd) {
    send(client_fd, &s_n, sizeof(long), 0);
    send(client_fd, &s_e, sizeof(long), 0);

    recv(client_fd, &c_n, sizeof(long), 0);
    recv(client_fd, &c_e, sizeof(long), 0);

    printf("\n• RSA Handshake with Client [%d] | Public Key (n, e): (%ld, %ld)\n", client_fd, c_n, c_e);
}

void *worker(void *arg) {
    struct client *c = arg;

    for (;;) {
        struct encrypted_packet p = {0};

        ssize_t r = recv(c->socket_fd, &p, sizeof(p), 0);
        if (r <= 0) {
            printf("• Client %d disconnected.\n", c->socket_fd);
            close(c->socket_fd);
            c->socket_fd = -1;
            return NULL;
        }

        if (p.len == 0 || p.len > MAX_ENCRYPTED_PAYLOAD)
            continue;

        char *plaintext = decrypt(p.encrypted_payload, p.len, s_d, s_n);
        if (!plaintext)
            continue;

        printf("\n• [Client %d] Sender: %lu\n• Message: %s\n\n",
               c->socket_fd, p.sender_id, plaintext);

        free(plaintext);
    }
}

void create_worker_thread(struct client *client) {
    pthread_t t;
    pthread_create(&t, NULL, worker, client);
    pthread_detach(t);
}

int s_init(int port) {
    struct sockaddr_in serv = {0};

    serv.sin_family = AF_INET;
    serv.sin_port = htons(port);
    serv.sin_addr.s_addr = htonl(INADDR_ANY);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(fd, (struct sockaddr *)&serv, sizeof(serv)) < 0)
        return -1;

    if (listen(fd, CLIENTS_LIMIT) < 0)
        return -1;

    for (int i = 0; i < CLIENTS_LIMIT; i++)
        clients[i].socket_fd = -1;

    return fd;
}

int main() {
    srand(time(NULL));
    generate_rsa_keys(&s_n, &s_e, &s_d);

    printf("Generated RSA keys:\n");
    printf("Public Key (n, e): (%ld, %ld)\n", s_n, s_e);
    printf("Private Key d: %ld\n", s_d);

    int port = 8080;
    printf("\n• What port to listen on?\n> ");
    scanf("%d", &port);

    if (port <= 0 || port > 65535) {
        printf("\n• Invalid port number.\n");
        return 1;
    }

    server_fd = s_init(port);
    if (server_fd < 0) {
        printf("\n• Server failed to start.\n");
        return 1;
    }

    flush_buffer();

    printf("\n• Server started on port %d.\n", port);

    for (;;) {
        if (num_clients >= CLIENTS_LIMIT)
            continue;

        struct client *new_client = malloc(sizeof(struct client));
        memset(new_client, 0, sizeof(struct client));

        int fd = accept(server_fd, NULL, NULL);
        if (fd < 0) {
            free(new_client);
            continue;
        }

        new_client->socket_fd = fd;

        if (insert_client(new_client) < 0) {
            printf("\n• Max clients reached, rejecting [%d]\n", fd);
            close(fd);
            free(new_client);
            continue;
        }

        rsa_handshake(fd);
        create_worker_thread(new_client);
    }
}
