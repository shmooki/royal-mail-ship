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

    send(fd, &c_n, sizeof(long), 0);
    send(fd, &c_e, sizeof(long), 0);

    printf("\n• RSA Handshake | Public Key (n, e): (%ld, %ld)\n", s_n, s_e);
}

void send_encrypted(int fd, const char *payload, long e, long n) {
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

int c_init(const char *ip, int port) {
    struct sockaddr_in serv = {0};

    serv.sin_family = AF_INET;
    serv.sin_port = htons(port);
    inet_pton(AF_INET, ip, &serv.sin_addr);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    if (connect(fd, (struct sockaddr *)&serv, sizeof(serv)) < 0)
        return -1;

    rsa_handshake(fd);

    server_fd = fd;
    return 0;
}

void *message_bar_thread() {
    char input[512];

    for (;;) {
        printf("> ");
        if (!fgets(input, sizeof(input), stdin))
            continue;

        input[strcspn(input, "\n")] = 0;
        if (strlen(input) == 0)
            continue;

        size_t enc_len = 0;
        long *cipher = encrypt(input, s_e, s_n, &enc_len);

        if (!cipher) continue;

        struct encrypted_packet p = {0};

        p.sender_id  = generate_uuid(10);
        p.channel_id = 1;
        p.msg_id     = generate_uuid(10);
        p.timestamp  = (uint32_t)time(NULL);
        p.len        = (uint32_t)enc_len;

        if (enc_len > MAX_ENCRYPTED_PAYLOAD)
            enc_len = MAX_ENCRYPTED_PAYLOAD;

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
        if (received <= 0)
            continue;

        char *plaintext = decrypt(p.encrypted_payload, p.len, c_d, c_n);
        if (!plaintext)
            continue;

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

    printf("• What is the server IP?\n> ");
    fgets(ip, sizeof(ip), stdin);
    ip[strcspn(ip, "\n")] = 0;

    printf("• What is the server port?\n> ");
    scanf("%d", &port);
    flush_buffer();

    if (c_init(ip, port) < 0) {
        printf("• Connection failed.\n");
        return 1;
    }

    printf("\n• Enter username:\n> ");
    char username[32];
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0;

    printf("• Enter password:\n> ");
    char password[32];
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = 0;

    send_encrypted(server_fd, username, s_e, s_n);
    send_encrypted(server_fd, password, s_e, s_n);

    printf("\n");

    pthread_t t_send, t_recv;
    pthread_create(&t_send, NULL, message_bar_thread, NULL);
    pthread_create(&t_recv, NULL, payload_receiver_thread, NULL);

    pthread_join(t_send, NULL);
    pthread_join(t_recv, NULL);

    return 0;
}