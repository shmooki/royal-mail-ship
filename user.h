#pragma once
#include <inttypes.h>

#ifndef RMS_USER_H
#define RMS_USER_H

struct user {
    uint64_t user_id;
    char username[32];
    char password_hash[64];
    long public_key_e;
    long public_key_n;
    long private_key_d;
};

#endif //RMS_USER_H