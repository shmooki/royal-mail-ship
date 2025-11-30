#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include "utility.h"
#include "rsa.h"
#include "encrypted_packet.h"

// Critical Information
int server_fd;

// RSA Keys
long s_n, s_e;
long c_n, c_e, c_d;

void rsa_handshake() {
    recv(server_fd, &s_n, sizeof(long), 0);
    recv(server_fd, &s_e, sizeof(long), 0);
    send(server_fd, &c_n, sizeof(long), 0);
    send(server_fd, &c_e, sizeof(long), 0);
}

int c_init(char *ip, int port) {
    struct sockaddr_in serv = {0};

    serv.sin_family = AF_INET;
    serv.sin_port = htons(port);
    inet_pton(AF_INET, ip, &serv.sin_addr);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    if (connect(fd, (struct sockaddr *)&serv, sizeof(serv)) < 0)
        return -1;

    rsa_handshake();

    server_fd = fd;
    return 0;
}

void message_bar_thread() {
    char input[512];
    for (;;) {
        printf("> ");
        if (fgets(input, sizeof(input), stdin) != NULL) {
            input[strcspn(input, "\n")] = 0;

            size_t input_len = strlen(input) + 1;
            long *encrypted_payload = encrypt(input, s_e, s_n, &input_len);

            struct encrypted_packet p;
            p.sender_id = generate_uuid(10);
            p.channel_id = 1;
            p.msg_id = generate_uuid(10);
            p.timestamp = (uint32_t)time(NULL);
            p.payload = *encrypted_payload;

            send(server_fd, &p, sizeof(struct encrypted_packet), 0);

            if (encrypted_payload) {
                free(encrypted_payload);
            }
        }
    }
}

void payload_receiver_thread() {
    for (;;) {
        struct encrypted_packet p;
        recv(server_fd, &p, sizeof(struct encrypted_packet), 0);

        char *decrypted_payload = decrypt(&p.payload, sizeof(p.payload), c_d, c_n);

        printf("\n%ld\n%s\n> ", p.sender_id, decrypted_payload);
        free(decrypted_payload);
    }
}

int main() {
    srand(time(NULL));
    generate_rsa_keys(&c_n, &c_e, &c_d);

    char ip[16] = "";
    int port = 8080;

    printf("• Enter server IP address:\n> ");
    fgets(ip, sizeof(ip), stdin);
    ip[strcspn(ip, "\n")] = 0;

    printf("\n• Enter server port:\n> ");
    scanf("%d", &port);

    flush_buffer();

    system("clear");
    printf("\n> ");

    pthread_t message_bar_thread = 0;
    pthread_t payload_receiver_thread = 0;

    pthread_create(&message_bar_thread, NULL, (void *)message_bar_thread, NULL);
    pthread_create(&payload_receiver_thread, NULL, (void *)payload_receiver_thread, NULL);
}