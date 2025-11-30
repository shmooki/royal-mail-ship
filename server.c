// server.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include "utility.h"
#include "rsa.h"
#include "server_info.h"
#include "client_info.h"
#include "channel.h"

// Critical Information
int server_fd;

// RSA Keys
long n, e, d;

// Client Management
pthread_mutex_t c_lock = PTHREAD_MUTEX_INITIALIZER;
struct client clients[CLIENTS_LIMIT] = {};
int num_clients = 0;

// Channel Management
struct channel channels[CLIENTS_LIMIT] = {};
int num_channels = 0;

int init(int port) {
    struct sockaddr_in serv = {0};

    serv.sin_family = AF_INET;
    serv.sin_port = htons(port);
    serv.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

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

void *worker(void *arg) {
    struct client *c = (struct client *)arg;



    return NULL;
}

void create_worker_thread(struct client *client) {
    pthread_t t;
    pthread_create(&t, NULL, worker, client);
    pthread_detach(t);
}

void load_channels() {
    // Placeholder for loading channels from a file
    // Implementation would go here
}

int main() {
    srand(time(NULL));
    generate_rsa_keys(&n, &e, &d);

    printf("Generated RSA keys:\n");
    printf("Public Key (n, e): (%ld, %ld)\n", n, e);
    printf("Private Key (d): %ld\n", d);

    int port = 8080;
    printf("\n• What port to listen on?\n> ");
    scanf("%d", &port);

    if (port <= 0 || port > 65535) {
        printf("• Invalid port number.\n");
        return 1;
    }

    server_fd = init(port);
    if (server_fd < 0) {
        printf("• Server failed to start.\n");
        return 1;
    }

    flush_buffer();

    int should_load_channels = 0;
    printf("\n• Load channels from file?\n[1] Yes\n[0] No\n> ");
    scanf("%d", &should_load_channels);

    DIR *saves_dir = opendir("saves");
    if (!saves_dir) {
        mkdir("saves", 0700);
    }

    DIR *channels_dir = opendir("saves/channels");
    if (!channels_dir) {
        mkdir("saves/channels", 0700);
    }

    if (should_load_channels) {
        load_channels();
        printf("• Channels loaded from save.\n");
    } else {
        printf("• Starting with no channels.\n");
    }

    flush_buffer();

    for (;;) {
        if (num_clients >= CLIENTS_LIMIT)
            continue;

        struct client *new_client = malloc(sizeof(struct client));

        int fd = accept(server_fd, NULL, NULL);
        if (fd < 0) {
            free(new_client);
            continue;
        }

        new_client->socket_fd = fd;

        if (insert_client(new_client) < 0) {
            printf("• Max clients reached. Rejecting [%d]...\n", fd);
            close(fd);
            free(new_client);
            continue;
        }

        create_worker_thread(new_client);
    }
}
