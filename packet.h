#pragma once
#include <inttypes.h>

#ifndef RMS_PACKET_H
#define RMS_PACKET_H

/*
 * type:
 *          0 = Text
 *          1 = Command
 *          2 = File
 *          3 = Text + File
 */

struct encrypted_packet {
    uint64_t msg_id;
    uint64_t sender_id;
    uint64_t channel_id;
    uint32_t timestamp;
    int type;
    char payload[512];
};

#endif //RMS_PACKET_H