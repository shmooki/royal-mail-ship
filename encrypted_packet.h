#pragma once
#include <inttypes.h>

#ifndef RMS_ENCRYPTED_PACKET_H
#define RMS_ENCRYPTED_PACKET_H

struct packet {
    uint64_t sender_id;
    uint64_t channel_id;
    uint64_t msg_id;
    uint32_t timestamp;
    long encrypted_payload;
};

#endif //RMS_ENCRYPTED_PACKET_H