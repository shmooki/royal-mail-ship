#pragma once
#include <inttypes.h>

#ifndef RMS_CHANNEL_H
#define RMS_CHANNEL_H

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
};

#endif //RMS_CHANNEL_H