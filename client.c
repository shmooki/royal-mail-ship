#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#define CONNECTIONS_LIMIT 5

void strip_newline(char* input, char* destination) {
    input[strcspn(input, "\n")] = '\0';
    strncpy(destination, input, sizeof(*destination));
}

void clear_stdin() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

int client_setup(const char *ip, int port) {
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(ip);

    int client = socket(AF_INET, SOCK_STREAM, 0);
    if (client < 0) {
        printf("Failed to create socket.\n");
        return -1;
    }

    if (connect(client, (struct sockaddr *)&server, sizeof(server)) < 0) {
        printf("Failed to connect to server.\n");
        close(client);
        return -1;
    }

    return client;
}

int main() {
    char server_ip[INET_ADDRSTRLEN] = "127.0.0.1";
    int port = 8080;

    printf("[Client]: Server IP to connect to? (press enter to use 127.0.0.1)\n");
    char input_ip[INET_ADDRSTRLEN];
    fgets(input_ip, sizeof(input_ip), stdin);
    if (input_ip[0] != '\n') {
        strip_newline(input_ip, server_ip);
    }

    printf("[Client]: Server Port to connect to? (press enter to use 8080)\n");
    char input_port[16];
    fgets(input_port, sizeof(input_port), stdin);
    if (input_port[0] != '\n')
        port = atoi(input_port);

    int client = client_setup(server_ip, port);
    if (client < 0) {
        return -1;
    }

    printf("[Client]: Connected to %s:%d\n", server_ip, port);

    int selection;
    const char *options = "\n[1]: Send Message\n\nSelect an option:\n";

    printf("[Client]\n");
    while (1) {
        printf("%s", options);
        scanf("%d", &selection);
        clear_stdin();

        if (selection == 1) {
            char msg[100];
            printf("Enter message to send:\n");
            scanf("%s", msg);
            clear_stdin();

            if (send(client, &selection, sizeof(selection), 0) < 0) {
                printf("Failed to send message.\n");
                break;
            }

            if (send(client, msg, strlen(msg) + 1, 0) < 0) {
                printf("Failed to send data.\n");
                break;
            }

            printf("[Client]: Message sent!\n");
        } else {
            printf("[Client]: Unknown option.\n");
        }
    }

    close(client);
    printf("[Client]: Connection closed.\n");
    return 0;
}