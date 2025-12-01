#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <time.h>
#include "utility.h"
#include "rsa.h"
#include "encrypted_packet.h"

// Server File Descriptor
int server_fd = -1;

// RSA Keys
long s_n, s_e;
long c_n, c_e, c_d;

void rsa_handshake(int fd) {
    recv(fd, &s_n, sizeof(long), 0);
    recv(fd, &s_e, sizeof(long), 0);
    printf("\n• RSA Handshake | Server Public Key (n,e): (%ld,%ld)\n", s_n, s_e);

    send(fd, &c_n, sizeof(long), 0);
    send(fd, &c_e, sizeof(long), 0);
}

int c_init(char *ip, int port) {
    struct sockaddr_in serv = {0};
    serv.sin_family = AF_INET;
    serv.sin_port = htons(port);
    inet_pton(AF_INET, ip, &serv.sin_addr);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (connect(fd, (struct sockaddr *)&serv, sizeof(serv)) < 0) return -1;

    server_fd = fd;
    rsa_handshake(fd);
    return 0;
}

void *message_bar_thread() {
    char input[512];
    for (;;) {
        printf("> ");
        if (!fgets(input, sizeof(input), stdin)) continue;
        input[strcspn(input, "\n")] = 0;
        if (strlen(input) == 0) continue;

        size_t enc_len = 0;
        long *cipher = encrypt(input, s_e, s_n, &enc_len);
        if (!cipher) continue;

        struct encrypted_packet p = {0};
        p.sender_id  = generate_uuid(10);
        p.channel_id = 1;
        p.msg_id     = generate_uuid(10);
        p.timestamp  = (uint32_t)time(NULL);
        p.len        = (uint32_t)enc_len;

        if (enc_len > MAX_ENCRYPTED_PAYLOAD) enc_len = MAX_ENCRYPTED_PAYLOAD;
        for (size_t i = 0; i < enc_len; i++)
            p.encrypted_payload[i] = cipher[i];

        send(server_fd, &p, sizeof(p), 0);
        free(cipher);
    }
}

void *payload_receiver_thread() {
    for (;;) {
        struct encrypted_packet p = {0};
        ssize_t received = recv(server_fd, &p, sizeof(p), 0);
        if (received <= 0) continue;

        char *plaintext = decrypt(p.encrypted_payload, p.len, c_d, c_n);
        if (!plaintext) continue;

        printf("\n[%lu] %s\n> ", p.sender_id, plaintext);
        fflush(stdout);
        free(plaintext);
    }
}

int main() {
    srand(time(NULL));
    generate_rsa_keys(&c_n, &c_e, &c_d);

    char ip[32];
    int port = 8080;

    printf("• Enter server IP:\n> ");
    fgets(ip, sizeof(ip), stdin);
    ip[strcspn(ip, "\n")] = 0;

    printf("\n• Enter port:\n> ");
    scanf("%d", &port);
    flush_buffer();

    if (c_init(ip, port) < 0) {
        printf("\n• Connection failed.\n");
        return 1;
    }

    int choice = 0;
    printf("\n• Choose action:\n[0] Signup\n[1] Login\n> ");
    scanf("%d", &choice);
    flush_buffer();

    char username[32], password[64];
    printf("\n• Enter username:\n> ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0;

    printf("\n• Enter password:\n> ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = 0;

    char cmd_buf[64];
    snprintf(cmd_buf, sizeof(cmd_buf), "/%s", choice == 0 ? "signup" : "login");

    size_t cmd_enc_len = 0;
    long *enc_cmd = encrypt(cmd_buf, s_e, s_n, &cmd_enc_len);

    size_t username_enc_len = 0, password_enc_len = 0;
    long *enc_username = encrypt(username, s_e, s_n, &username_enc_len);
    long *enc_password = encrypt(password, s_e, s_n, &password_enc_len);

    struct encrypted_packet p = {0};
    p.sender_id  = generate_uuid(10);
    p.channel_id = 1;
    p.msg_id     = generate_uuid(10);
    p.timestamp  = (uint32_t)time(NULL);
    p.len        = cmd_enc_len;

    for (size_t i = 0; i < cmd_enc_len && i < MAX_ENCRYPTED_PAYLOAD; i++)
        p.encrypted_payload[i] = enc_cmd[i];

    send(server_fd, &p, sizeof(p), 0);

    send(server_fd, enc_username, username_enc_len * sizeof(long), 0);
    send(server_fd, enc_password, password_enc_len * sizeof(long), 0);

    free(enc_cmd);
    free(enc_username);
    free(enc_password);

    pthread_t t_send, t_recv;
    pthread_create(&t_send, NULL, message_bar_thread, NULL);
    pthread_create(&t_recv, NULL, payload_receiver_thread, NULL);

    pthread_join(t_send, NULL);
    pthread_join(t_recv, NULL);

    return 0;
}
