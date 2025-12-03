#pragma once

#ifndef RMS_CHANNEL_H
#define RMS_CHANNEL_H

#define CHANNEL_NAME_SIZE 32
#define MAX_PARTICIPANTS 25

/*
 * channel file structure:
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
 */

#define MSG_BUFFER_LIMIT 32

struct msg {
    uint64_t msg_id;
    uint64_t sender_id;
    uint32_t timestamp;
    char content[512];
};

struct channel {
    uint64_t channel_id;
    char channel_name[CHANNEL_NAME_SIZE];
    uint64_t participant_ids[MAX_PARTICIPANTS];
    int gated;
    int gate_type;
    struct msg messages[MSG_BUFFER_LIMIT];
};

#endif //RMS_CHANNEL_H