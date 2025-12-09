#pragma once
#include <stdint.h>
#include <pthread.h>

#ifndef RMS_CHANNEL_H
#define RMS_CHANNEL_H

#define CHANNEL_NAME_SIZE 32
#define MAX_CHANNELS 100
#define MAX_PARTICIPANTS 25
#define MAX_CHANNEL_MEMBERS 25

#define MSG_BUFFER_LIMIT 100
#define MAX_MEDIA_SIZE (10 * 1024 * 1024) // 10MB max file size

// Message types
#define MSG_TYPE_TEXT 0
#define MSG_TYPE_FILE 1
#define MSG_TYPE_IMAGE 2
#define MSG_TYPE_AUDIO 3
#define MSG_TYPE_VIDEO 4

/*
 * channel file structure:
 * channel_name
 * participant_ids_1
 * participant_ids_2
 * ...
 * participant_ids_25
 * message_id_1 sender_id_1 timestamp_1 type_1 payload_1
 * message_id_2 sender_id_2 timestamp_2 type_2 payload_2
 * ...
 */

 struct media_info {
    char file_name[256];
    uint64_t file_size;
    char file_type[64];
    uint8_t is_encrypted;
};

struct msg {
    uint64_t msg_id;
    uint64_t sender_id;
    uint32_t timestamp;
    int msg_type;
    char content[512];
    struct media_info media;
};

struct channel {
    uint64_t channel_id;
    char channel_name[CHANNEL_NAME_SIZE];
    uint64_t participant_ids[MAX_PARTICIPANTS];
    int participant_count;
    int message_count;
    struct msg messages[MSG_BUFFER_LIMIT];
};

struct channel_subscription {
    uint64_t channel_id;
    uint64_t user_id;
    time_t joined_at;
};

struct channel_manager {
    struct channel channels[MAX_CHANNELS];
    struct channel_subscription subscriptions[MAX_CHANNELS * MAX_CHANNEL_MEMBERS];
    int channel_count;
    int subscription_count;
    pthread_mutex_t lock;
};

void channel_manager_init(struct channel_manager *cm);
int channel_create(struct channel_manager *cm, const char *name, uint64_t creator_id);
int channel_join(struct channel_manager *cm, uint64_t channel_id, uint64_t user_id);
int channel_add_message(struct channel_manager * cm, uint64_t channel_id, uint64_t sender_id, const char * content, int msg_type);
struct channel *channel_find(struct channel_manager *cm, uint64_t channel_id);
struct channel *channel_find_by_name(struct channel_manager *cm, const char *name);
void channel_save_to_file(struct channel_manager *cm, uint64_t channel_id);
void channel_load_from_file(struct channel_manager *cm, uint64_t channel_id);
int channel_is_member(struct channel_manager *cm, uint64_t channel_id, uint64_t user_id);

#endif //RMS_CHANNEL_H