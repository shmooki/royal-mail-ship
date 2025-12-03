#pragma once
#include "client_info.h"

#ifndef ENCRYPTED_PACKET_H
#define ENCRYPTED_PACKET_H

#define MAX_ENCRYPTED_PAYLOAD 128

struct encrypted_packet {
    uint64_t sender_id;
    uint64_t channel_id;
    uint64_t msg_id;
    uint32_t timestamp;
    uint32_t len;
    char username[USERNAME_SIZE];
    long encrypted_payload[MAX_ENCRYPTED_PAYLOAD];
};

#endif
