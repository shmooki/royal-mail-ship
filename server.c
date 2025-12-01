#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "encrypted_packet.h"
#include "rsa.h"
#include "server_info.h"
#include "user.h"
#include "utility.h"

// Server File Descriptor
int server_fd;
long s_n, s_e, s_d;

// User Management
pthread_mutex_t u_lock = PTHREAD_MUTEX_INITIALIZER;
struct user users[USERS_LIMIT] = {};
int num_users = 0;

int insert_user(struct user *new_user) {
    pthread_mutex_lock(&u_lock);
    for (int i = 0; i < USERS_LIMIT; i++) {
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

struct user *find_user_by_username(char *username) {
    pthread_mutex_lock(&u_lock);
    for (int i = 0; i < USERS_LIMIT; i++) {
        if (users[i].socket_fd != -1 && strcmp(users[i].username, username) == 0) {
            pthread_mutex_unlock(&u_lock);
            return &users[i];
        }
    }
    pthread_mutex_unlock(&u_lock);
    return NULL;
}

void rsa_handshake(struct user *u) {
    send(u->socket_fd, &s_n, sizeof(long), 0);
    send(u->socket_fd, &s_e, sizeof(long), 0);

    long c_n, c_e;
    recv(u->socket_fd, &c_n, sizeof(long), 0);
    recv(u->socket_fd, &c_e, sizeof(long), 0);

    u->public_key_n = c_n;
    u->public_key_e = c_e;
}

char *strip_slash(char *str) {
    if (!str || str[0] != '/') return str;
    return str + 1;
}

int command_parser(char *cmd) {
    if (strcmp(cmd, "signup") == 0) return 0;
    if (strcmp(cmd, "login") == 0) return 1;
    return -1;
}

int n = 0;

int handle_signup(struct user *u) {
    long encrypted_username[32];
    long encrypted_password[64];

    if (recv(u->socket_fd, encrypted_username, sizeof(encrypted_username), 0) <= 0) return -1;
    if (recv(u->socket_fd, encrypted_password, sizeof(encrypted_password), 0) <= 0) return -1;

    char *username = decrypt(encrypted_username, sizeof(encrypted_username) / sizeof(long), s_d, s_n);
    char *password = decrypt(encrypted_password, sizeof(encrypted_password) / sizeof(long), s_d, s_n);

    printf("• Decrypted signup data: %s / %s\n", username ? username : "(null)", password ? password : "(null)");

    if (!username || !password || strlen(username) >= MAX_CRED_LEN || strlen(password) >= MAX_CRED_LEN) {
        if (username) free(username);
        if (password) {
            memset(password, 0, strlen(password));
            free(password);
        }
        return -1;
    }

    printf("• Signup attempt: %s\n", username);

    if (find_user_by_username(username)) {
        free(username);
        memset(password, 0, strlen(password));
        free(password);
        return -1;
    }

    struct user new_u = {0};
    new_u.socket_fd = u->socket_fd;
    strncpy(new_u.username, username, sizeof(new_u.username) - 1);
    strncpy(new_u.password, password, sizeof(new_u.password) - 1);
    new_u.public_key_e = u->public_key_e;
    new_u.public_key_n = u->public_key_n;

    pthread_mutex_lock(&u_lock);
    FILE *file = fopen("users", "a");
    if (!file) {
        pthread_mutex_unlock(&u_lock);
        free(username);
        memset(password, 0, strlen(password));
        free(password);
        return -1;
    }
    fprintf(file, "%s\n%s\n", new_u.username, new_u.password);
    fclose(file);
    insert_user(&new_u);
    pthread_mutex_unlock(&u_lock);

    free(username);
    memset(password, 0, strlen(password));
    free(password);
    return 0;
}

int handle_login(struct user *u) {
    long encrypted_username[32];
    long encrypted_password[64];

    if (recv(u->socket_fd, encrypted_username, sizeof(encrypted_username), 0) <= 0) return -1;
    if (recv(u->socket_fd, encrypted_password, sizeof(encrypted_password), 0) <= 0) return -1;

    char *username = decrypt(encrypted_username, sizeof(encrypted_username) / sizeof(long), s_d, s_n);
    char *password = decrypt(encrypted_password, sizeof(encrypted_password) / sizeof(long), s_d, s_n);
    if (!username || !password) return -1;

    pthread_mutex_lock(&u_lock);
    struct user *existing_user = find_user_by_username(username);
    int result = -1;

    if (existing_user && strcmp(existing_user->password, password) == 0) {
        u->socket_fd = existing_user->socket_fd;
        strncpy(u->username, existing_user->username, sizeof(u->username) - 1);
        u->public_key_e = existing_user->public_key_e;
        u->public_key_n = existing_user->public_key_n;
        result = 0;
    }
    pthread_mutex_unlock(&u_lock);

    free(username);
    free(password);
    return result;
}

void command_handler(struct user *u, int cmd) {
    if (cmd == 0) handle_signup(u);
    else if (cmd == 1) handle_login(u);
}

void *worker(void *arg) {
    struct user *u = arg;
    for (;;) {
        struct encrypted_packet p = {0};
        ssize_t r = recv(u->socket_fd, &p, sizeof(p), 0);

        if (r <= 0) {
            printf("• User %s disconnected.\n", u->username);
            close(u->socket_fd);
            u->socket_fd = -1;
            pthread_mutex_lock(&u_lock);
            num_users--;
            pthread_mutex_unlock(&u_lock);
            free(u);
            return NULL;
        }

        if (p.len == 0 || p.len > MAX_ENCRYPTED_PAYLOAD) continue;

        char *plaintext = decrypt(p.encrypted_payload, p.len, s_d, s_n);
        if (!plaintext) continue;

        printf("\n• [User %s] ID: %lu\n• Message: %s\n\n", u->username, p.sender_id, plaintext);

        if (plaintext[0] == '/') {
            char *cmd_str = strip_slash(plaintext);
            int parsed_cmd = command_parser(cmd_str);
            command_handler(u, parsed_cmd);
        }

        free(plaintext);
    }
}

void create_worker_thread(struct user *u) {
    pthread_t t;
    pthread_create(&t, NULL, worker, u);
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

    if (bind(fd, (struct sockaddr *)&serv, sizeof(serv)) < 0) return -1;
    if (listen(fd, USERS_LIMIT) < 0) return -1;

    for (int i = 0; i < USERS_LIMIT; i++) users[i].socket_fd = -1;

    FILE *file = fopen("users", "a+");
    if (!file) return -1;

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\r\n")] = '\0';
        char username_buf[USERNAME_SIZE] = {0};
        strncpy(username_buf, line, sizeof(username_buf) - 1);

        if (!fgets(line, sizeof(line), file)) break;
        line[strcspn(line, "\r\n")] = '\0';
        char password_buf[PASSWORD_SIZE] = {0};
        strncpy(password_buf, line, sizeof(password_buf) - 1);

        struct user u = {0};
        u.socket_fd = -1;
        strncpy(u.username, username_buf, sizeof(u.username) - 1);
        strncpy(u.password, password_buf, sizeof(u.password) - 1);
        insert_user(&u);
    }
    fclose(file);

    return fd;
}

int main() {
    printf("%d\n", n++);
    srand(time(NULL));
    generate_rsa_keys(&s_n, &s_e, &s_d);

    printf("Generated RSA keys:\nPublic Key (n, e): (%ld, %ld)\nPrivate Key (d): (%ld)\n", s_n, s_e, s_d);

    int port = 8080;
    printf("\n• What port to listen on?\n> ");
    scanf("%d", &port);
    if (port <= 0 || port > 65535) return 1;

    server_fd = s_init(port);
    if (server_fd < 0) return 1;
    flush_buffer();
    printf("\n• Server started on port %d.\n", port);

    for (;;) {
        if (num_users >= USERS_LIMIT) {
            sleep(1);
            continue;
        }

        struct user *new_user = malloc(sizeof(struct user));
        memset(new_user, 0, sizeof(struct user));

        int fd = accept(server_fd, NULL, NULL);
        if (fd < 0) {
            free(new_user);
            continue;
        }

        new_user->socket_fd = fd;
        rsa_handshake(new_user);

        printf("%d\n", n++);
        struct encrypted_packet p = {0};
        if (recv(fd, &p, sizeof(p), 0) <= 0) {
            close(fd);
            free(new_user);
            continue;
        }
        printf("%d\n", n++);

        char *plaintext = decrypt(p.encrypted_payload, p.len, s_d, s_n);
        if (!plaintext) {
            close(fd);
            free(new_user);
            continue;
        }

        printf("• Received initial command: %s\n", plaintext);
        printf("%d\n", n++);

        if (plaintext[0] == '/') {
            printf("%d\n", n++);
            char *cmd_str = strip_slash(plaintext);
            int cmd = command_parser(cmd_str);

            if (cmd == 0) handle_signup(new_user);
            else if (cmd == 1 && handle_login(new_user) < 0) {
                printf("• Login failed for socket %d\n", fd);
                close(fd);
                free(new_user);
                free(plaintext);
                continue;
            }
        }

        free(plaintext);

        if (insert_user(new_user) < 0) {
            close(fd);
            free(new_user);
            continue;
        }

        create_worker_thread(new_user);
    }
}