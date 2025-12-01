#pragma once
#include <inttypes.h>

#ifndef RMS_USER_H
#define RMS_USER_H

#define USERNAME_SIZE 32
#define PASSWORD_SIZE 64
#define MAX_CRED_LEN 64

struct user {
    int socket_fd;
    uint64_t user_id;
    char username[USERNAME_SIZE];
    char password[PASSWORD_SIZE];
    long public_key_e;
    long public_key_n;
};

#endif //RMS_USER_H