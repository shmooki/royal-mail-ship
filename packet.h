#pragma once
#include "client_info.h"

#ifndef RMS_PACKET_H
#define RMS_PACKET_H

#define PAYLOAD_SIZE 512

/*
 * type:
 *          0 = Text
 *          1 = Command
 *          2 = File
 *          3 = Text + File
 */

struct packet {
    uint64_t msg_id;
    uint64_t sender_id;
    uint64_t channel_id;
    uint32_t timestamp;
    char username[USERNAME_SIZE];
    int type;
    char payload[PAYLOAD_SIZE];
};

#endif //RMS_PACKET_H