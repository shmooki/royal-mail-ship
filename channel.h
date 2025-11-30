#pragma once
#include <inttypes.h>
#include "packet.h"

#ifndef RMS_CHANNEL_H
#define RMS_CHANNEL_H

/*
 * channel file structure:
 * channel_id
 * channel_name
 * participant_ids_1
 * participant_ids_2
 * ...
 * participant_ids_25
 * gated
 * gate_type
 * message_id_1 sender_id_1 timestamp_1 type_1 payload_1
 * message_id_2 sender_id_2 timestamp_2 type_2 payload_2
 * ...
 */

/*
 * gated:
 *          0 = No
 *          1 = Yes
 * gate_type:
 *          0 = DM
 *          1 = Group
 *          2 = Public
 *          3 = Private
 */

#define MSG_BUFFER_LIMIT 128

struct channel {
    uint64_t channel_id;
    char channel_name[64];
    uint64_t participant_ids[25];
    int gated;
    int gate_type;
    struct encrypted_packet message_buffer[MSG_BUFFER_LIMIT];
};

#endif //RMS_CHANNEL_H