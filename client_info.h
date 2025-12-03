#ifndef RMS_CLIENT_H
#define RMS_CLIENT_H

#define USERNAME_SIZE 32
#define PASSWORD_SIZE 32

struct client {
    int socket_fd;
    uint64_t user_id;
    char username[32];
    char password[64];
    int selected_channel;
    long public_key_e;
    long public_key_n;
};

#endif //RMS_CLIENT_H