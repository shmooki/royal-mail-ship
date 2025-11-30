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

struct packet {
    int type;
    uint64_t sender_id;
    uint64_t channel_id;
    uint64_t msg_id;
    uint32_t timestamp;
    char payload[512];
};

#endif //RMS_PACKET_H