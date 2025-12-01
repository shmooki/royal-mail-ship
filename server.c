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
#include "client_info.h"
#include "encrypted_packet.h"

#define CLIENTS_LIMIT 10
#define CRED_FILE "client_credentials"

// Server File Descriptor
int server_fd;

// RSA Keys
long s_n, s_e, s_d;

// Client Management
pthread_mutex_t u_lock = PTHREAD_MUTEX_INITIALIZER;
struct client users[CLIENTS_LIMIT];
int num_users = 0;
FILE *cred_file = NULL;

int insert_user(struct client *new_user) {
    pthread_mutex_lock(&u_lock);
    for (int i = 0; i < CLIENTS_LIMIT; i++) {
        if (users[i].socket_fd == -1) {
            users[i] = *new_user;
            num_users++;
            pthread_mutex_unlock(&u_lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&u_lock);
    return -1;
}

int find_user_index_by_username(const char *username) {
    for (int i = 0; i < CLIENTS_LIMIT; i++) {
        if (strcmp(users[i].username, username) == 0)
            return i;
    }

    return -1;
}

void broadcast(const char *msg, uint64_t sender_id, int exclude_fd) {
    pthread_mutex_lock(&u_lock);
    for (int i = 0; i < CLIENTS_LIMIT; i++) {
        if (users[i].socket_fd == -1 || users[i].socket_fd == exclude_fd) continue;

        struct client *u = &users[i];
        size_t enc_len;
        long *enc = encrypt(msg, u->public_key_e, u->public_key_n, &enc_len);
        if (!enc) continue;

        if (enc_len > MAX_ENCRYPTED_PAYLOAD) enc_len = MAX_ENCRYPTED_PAYLOAD;

        struct encrypted_packet p = {0};
        p.sender_id = sender_id;
        p.len = enc_len;
        strncpy(p.username, u->username, USERNAME_SIZE - 1);

        for (size_t j = 0; j < enc_len; j++)
            p.encrypted_payload[j] = enc[j];

        send(u->socket_fd, &p, sizeof(p), 0);
        free(enc);
    }
    pthread_mutex_unlock(&u_lock);
}

void rsa_handshake(int fd, struct client *u) {
    send(fd, &s_n, sizeof(long), 0);
    send(fd, &s_e, sizeof(long), 0);

    recv(fd, &u->public_key_n, sizeof(long), 0);
    recv(fd, &u->public_key_e, sizeof(long), 0);

    printf("• RSA Handshake with User [%d] | Public Key (n, e): (%ld, %ld)\n",
           fd, u->public_key_n, u->public_key_e);
}

char *recv_decrypted(int fd, long d, long n) {
    struct encrypted_packet p = {0};
    ssize_t r = recv(fd, &p, sizeof(p), 0);
    if (r <= 0 || p.len == 0 || p.len > MAX_ENCRYPTED_PAYLOAD)
        return NULL;

    char *plaintext = decrypt(p.encrypted_payload, p.len, d, n);
    return plaintext;
}

void *worker(void *arg) {
    struct client *u = arg;
    for (;;) {
        char *msg = recv_decrypted(u->socket_fd, s_d, s_n);
        if (!msg) {
            printf("• User %d disconnected.\n", u->socket_fd);
            close(u->socket_fd);
            u->socket_fd = -1;
            return NULL;
        }

        printf("\nUser [%s]:\n%s\n",
               u->username, msg);

        broadcast(msg, u->user_id, u->socket_fd);
        free(msg);
    }
}

void create_worker_thread(struct client *u) {
    pthread_t t;
    pthread_create(&t, NULL, worker, u);
    pthread_detach(t);
}

void load_credentials() {
    printf("\n• Loading credentials from file...\n");

    fseek(cred_file, 0, SEEK_SET);
    char line[128];
    while (fgets(line, sizeof(line), cred_file)) {
        char username[USERNAME_SIZE] = {0};
        char password[PASSWORD_SIZE] = {0};
        sscanf(line, "%31s %31s", username, password);

        struct client u = {0};
        strncpy(u.username, username, USERNAME_SIZE - 1);
        strncpy(u.password, password, PASSWORD_SIZE - 1);
        u.socket_fd = -1;

        if (find_user_index_by_username(username) == -1 && strlen(username) > 0 && strlen(password) > 0) {
            insert_user(&u);
            printf("• Loaded Credential > Username: %s, Password: %s\n", username, password);
        }
    }

    printf("• Finished loading credentials. Total users: %d...\n\n", num_users);
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

    if (bind(fd, (struct sockaddr *)&serv, sizeof(serv)) < 0) return -1;
    if (listen(fd, CLIENTS_LIMIT) < 0) return -1;

    for (int i = 0; i < CLIENTS_LIMIT; i++) users[i].socket_fd = -1;

    cred_file = fopen(CRED_FILE, "a+");
    if (!cred_file) {
        printf("• Failed to open credentials file.\n");
        return -1;
    }

    load_credentials();
    return fd;
}

int main() {
    srand(time(NULL));
    generate_rsa_keys(&s_n, &s_e, &s_d);

    printf("• Generated RSA keys:\n");
    printf("• Public Key (n, e): (%ld, %ld)\n", s_n, s_e);
    printf("• Private Key d: %ld\n", s_d);

    int port = 8080;
    printf("\n• What port to listen on?\n> ");
    scanf("%d", &port);
    flush_buffer();

    if (port <= 0 || port > 65535) {
        printf("• Invalid port number.\n");
        return 1;
    }

    server_fd = s_init(port);
    if (server_fd < 0) {
        printf("\n• Server failed to start.\n");
        return 1;
    }

    printf("\n• Server started on port %d.\n", port);

    for (;;) {
        if (num_users >= CLIENTS_LIMIT) continue;

        struct client *u = malloc(sizeof(struct client));
        memset(u, 0, sizeof(struct client));
        u->socket_fd = -1;

        int fd = accept(server_fd, NULL, NULL);
        if (fd < 0) {
            free(u);
            continue;
        }
        u->socket_fd = fd;

        rsa_handshake(fd, u);

        char *username = recv_decrypted(fd, s_d, s_n);
        char *password = recv_decrypted(fd, s_d, s_n);

        printf("• Received credentials from [%d]: Username='%s', Password='%s'\n",
               fd,
               username ? username : "NULL",
               password ? password : "NULL");

        if (!username || !password || strlen(username) >= USERNAME_SIZE || strlen(password) >= PASSWORD_SIZE) {
            printf("• Invalid username/password from [%d], disconnecting.\n", fd);
            close(fd);
            free(u);
            free(username);
            free(password);
            continue;
        }

        int idx = find_user_index_by_username(username);

        if (idx != -1) {
            if (strcmp(users[idx].password, password) != 0) {
                printf("• Incorrect password for '%s' from [%d], disconnecting.\n", username, fd);
                close(fd);
                free(u);
                free(username);
                free(password);
                continue;
            }

            printf("• User '%s' reconnected from [%d].\n", username, fd);
            *u = users[idx];
            u->socket_fd = fd;
        } else {
            strncpy(u->username, username, USERNAME_SIZE - 1);
            strncpy(u->password, password, PASSWORD_SIZE - 1);
            fprintf(cred_file, "%s %s\n", u->username, u->password);
            fflush(cred_file);

            u->socket_fd = fd;
            printf("• New user '%s' registered from [%d].\n", u->username, fd);
        }

        free(username);
        free(password);

        if (insert_user(u) < 0) {
            printf("• Max users reached, rejecting [%d]\n", fd);
            close(fd);
            free(u);
            continue;
        }

        create_worker_thread(u);
    }
}
