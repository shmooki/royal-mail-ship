#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <time.h>
#include <inttypes.h>
#include <sys/sendfile.h>

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
        if (users[i].socket_fd == -1 && users[i].username[0] == '\0') {
            users[i] = *new_user;
            users[i].socket_fd = new_user->socket_fd;
            num_users++;
            pthread_mutex_unlock(&u_lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&u_lock);
    return -1;
}

int find_user_index_by_username(const char *username) {
    if (!username) return -1;
    pthread_mutex_lock(&u_lock);
    for (int i = 0; i < CLIENTS_LIMIT; i++) {
        if (users[i].username[0] != '\0' && strcmp(users[i].username, username) == 0) {
            pthread_mutex_unlock(&u_lock);
            return i;
        }
    }
    pthread_mutex_unlock(&u_lock);
    return -1;
}

int find_user_index_by_user_id(uint64_t user_id) {
    pthread_mutex_lock(&u_lock);
    for (int i = 0; i < CLIENTS_LIMIT; i++) {
        if (users[i].username[0] != '\0' && users[i].user_id == user_id) {
            pthread_mutex_unlock(&u_lock);
            return i;
        }
    }
    pthread_mutex_unlock(&u_lock);
    return -1;
}

void broadcast(const char *msg, uint64_t sender_id, int exclude_fd) {
    if (!msg) return;

    struct encrypted_packet p = {0};

    int sender_idx = find_user_index_by_user_id(sender_id);
    if (sender_idx != -1) {
        pthread_mutex_lock(&u_lock);
        strncpy(p.username, users[sender_idx].username, USERNAME_SIZE - 1);
        pthread_mutex_unlock(&u_lock);
    }

    pthread_mutex_lock(&u_lock);
    for (int i = 0; i < CLIENTS_LIMIT; i++) {
        if (users[i].socket_fd == -1 || users[i].socket_fd == exclude_fd) continue;

        struct client *recipient = &users[i];

        size_t enc_len;
        long *enc = encrypt(msg, recipient->public_key_e, recipient->public_key_n, &enc_len);
        if (!enc) continue;

        if (enc_len > MAX_ENCRYPTED_PAYLOAD) enc_len = MAX_ENCRYPTED_PAYLOAD;

        p.sender_id = sender_id;
        p.len = enc_len;

        for (size_t j = 0; j < enc_len; j++)
            p.encrypted_payload[j] = enc[j];

        send(recipient->socket_fd, &p, sizeof(p), 0);

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

void send_encrypted(int fd, char *payload, long e, long n) {
    size_t enc_len;
    long *cipher = encrypt(payload, e, n, &enc_len);
    if (!cipher)
        return;

    if (enc_len > MAX_ENCRYPTED_PAYLOAD)
        enc_len = MAX_ENCRYPTED_PAYLOAD;

    struct encrypted_packet p = {0};
    for (size_t i = 0; i < enc_len; i++)
        p.encrypted_payload[i] = cipher[i];

    p.len = enc_len;

    send(fd, &p, sizeof(p), 0);

    free(cipher);
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
    if (!u) return NULL;

    for (;;) {
        char *msg = recv_decrypted(u->socket_fd, s_d, s_n);
        if (!msg) {
            printf("\n• User %d disconnected.\n", u->socket_fd);
            close(u->socket_fd);
            pthread_mutex_lock(&u_lock);
            u->socket_fd = -1;
            pthread_mutex_unlock(&u_lock);
            return NULL;
        }

        printf("\n• User [%s | %lu]:\n%s\n",
               u->username, u->user_id, msg);

        broadcast(msg, u->user_id, u->socket_fd);
        free(msg);
    }
}

void create_worker_thread(struct client *u) {
    pthread_t t;
    int rc = pthread_create(&t, NULL, worker, u);
    if (rc != 0) {
        perror("pthread_create");
        return;
    }
    pthread_detach(t);
}

void load_credentials() {
    printf("\n• Loading credentials from file...\n");

    fseek(cred_file, 0, SEEK_SET);
    char line[256];
    while (fgets(line, sizeof(line), cred_file)) {
        char username[USERNAME_SIZE] = {0};
        char password[PASSWORD_SIZE] = {0};
        unsigned long long user_id = 0;
        if (sscanf(line, "%31s %31s %llu", username, password, &user_id) < 3) {
            continue;
        }

        struct client u = {0};
        strncpy(u.username, username, USERNAME_SIZE - 1);
        strncpy(u.password, password, PASSWORD_SIZE - 1);
        u.user_id = (uint64_t) user_id;
        u.socket_fd = -1;
        u.public_key_e = 0;
        u.public_key_n = 0;

        if (find_user_index_by_username(username) == -1 && strlen(username) > 0 && strlen(password) > 0) {
            if (insert_user(&u) == 0) {
                printf("• Loaded Credential > Username: %s, Password: %s\n", username, password);
            }
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

    for (int i = 0; i < CLIENTS_LIMIT; i++) {
        users[i].socket_fd = -1;
        users[i].username[0] = '\0';
        users[i].password[0] = '\0';
        users[i].public_key_e = 0;
        users[i].public_key_n = 0;
        users[i].user_id = 0;
    }

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
    if (scanf("%d", &port) != 1) {
        fprintf(stderr, "Invalid port input.\n");
        return 1;
    }
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

    printf("• Server started on port %d.\n", port);

    for (;;) {
        int fd = accept(server_fd, NULL, NULL);
        if (fd < 0) {
            perror("accept");
            continue;
        }

        struct client t = {0};
        t.socket_fd = fd;
        t.public_key_e = 0;
        t.public_key_n = 0;

        rsa_handshake(fd, &t);

        char *username = recv_decrypted(fd, s_d, s_n);
        char *password = recv_decrypted(fd, s_d, s_n);

        printf("• Received credentials from [%d]: Username='%s', Password='%s'\n",
               fd,
               username ? username : "NULL",
               password ? password : "NULL");

        if (!username || !password || strlen(username) >= USERNAME_SIZE || strlen(password) >= PASSWORD_SIZE) {
            printf("• Invalid username/password from [%d], disconnecting.\n", fd);
            close(fd);
            free(username);
            free(password);
            continue;
        }

        int idx = find_user_index_by_username(username);

        struct client *u = NULL;

        if (idx != -1) {
            pthread_mutex_lock(&u_lock);
            if (strcmp(users[idx].password, password) != 0) {
                pthread_mutex_unlock(&u_lock);
                printf("• Incorrect password for '%s' from [%d], disconnecting.\n", username, fd);
                close(fd);
                free(username);
                free(password);
                continue;
            }

            if (users[idx].socket_fd != -1) {
                pthread_mutex_unlock(&u_lock);
                printf("• User '%s' already connected, rejecting new connection from [%d].\n", username, fd);
                close(fd);
                free(username);
                free(password);
                continue;
            }

            users[idx].socket_fd = fd;
            users[idx].public_key_e = t.public_key_e;
            users[idx].public_key_n = t.public_key_n;
            pthread_mutex_unlock(&u_lock);

            u = &users[idx];
            printf("• User '%s' reconnected from [%d].\n", username, fd);
        } else {
            strncpy(t.username, username, USERNAME_SIZE - 1);
            strncpy(t.password, password, PASSWORD_SIZE - 1);
            t.user_id = generate_uuid(16);
            t.socket_fd = fd;

            if (insert_user(&t) < 0) {
                printf("• Max users reached, rejecting [%d]\n", fd);
                close(fd);
                free(username);
                free(password);
                continue;
            }

            idx = find_user_index_by_username(username);
            if (idx == -1) {
                printf("• Unexpected insertion error for '%s'.\n", username);
                close(fd);
                free(username);
                free(password);
                continue;
            }

            u = &users[idx];

            pthread_mutex_lock(&u_lock);
            fprintf(cred_file, "%s %s %lu\n", u->username, u->password, (unsigned long)u->user_id);
            fflush(cred_file);
            pthread_mutex_unlock(&u_lock);

            printf("• New user '%s' registered from [%d].\n", username, fd);
        }

        free(username);
        free(password);

        char user_id_str[32];
        snprintf(user_id_str, sizeof(user_id_str), "%lu", (unsigned long)u->user_id);
        send_encrypted(u->socket_fd, user_id_str, u->public_key_e, u->public_key_n);

        create_worker_thread(u);
    }
}
