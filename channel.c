#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>

#include "utility.h"
#include "channel.h"

void channel_manager_init(struct channel_manager *cm){
    memset(cm, 0, sizeof(struct channel_manager));
    pthread_mutex_init(&cm->lock, NULL);
}

int channel_create(struct channel_manager *cm, const char *name, 
                       uint64_t creator_id){
    pthread_mutex_lock(&cm->lock);
    
    if (cm->channel_count >= MAX_CHANNELS){
        pthread_mutex_unlock(&cm->lock);
        return 0;
    }
    
    uint64_t channel_id = generate_uuid(8);
    
    struct channel *new_channel = &cm->channels[cm->channel_count];
    new_channel->channel_id = channel_id;
    strncpy(new_channel->channel_name, name, CHANNEL_NAME_SIZE - 1);
    new_channel->participant_ids[0] = creator_id;
    new_channel->participant_count = 1;
    new_channel->message_count = 0;
    
    cm->subscriptions[cm->subscription_count].channel_id = channel_id;
    cm->subscriptions[cm->subscription_count].user_id = creator_id;
    cm->subscriptions[cm->subscription_count].joined_at = time(NULL);
    cm->subscription_count++; 
    cm->channel_count++;
    
    // Save to file
    channel_save_to_file(cm, channel_id);
    pthread_mutex_unlock(&cm->lock);
    return channel_id;
}

struct channel *channel_find(struct channel_manager *cm, uint64_t channel_id){
    for (int i = 0; i < cm->channel_count; i++){
        if (cm->channels[i].channel_id == channel_id){
            return &cm->channels[i];
        }
    }
    return NULL;
}

struct channel *channel_find_by_name(struct channel_manager *cm, const char *name) {
    for (int i = 0; i < cm->channel_count; i++) {
        if (strcmp(cm->channels[i].channel_name, name) == 0) {
            return &cm->channels[i];
        }
    }
    return NULL;
}

int channel_join(struct channel_manager *cm, uint64_t channel_id, uint64_t user_id){
    
    pthread_mutex_lock(&cm->lock);
    struct channel *ch = channel_find(cm, channel_id);

    if (!ch){
        pthread_mutex_unlock(&cm->lock);
        return -1;
    }
    
    // Check if already member
    for (int i = 0; i < ch->participant_count; i++){
        if (ch->participant_ids[i] == user_id) {
            pthread_mutex_unlock(&cm->lock);
            return -3;
        }
    }
    
    // Add to participants
    ch->participant_ids[ch->participant_count] = user_id;
    ch->participant_count++;
    
    // Add subscription
    cm->subscriptions[cm->subscription_count].channel_id = channel_id;
    cm->subscriptions[cm->subscription_count].user_id = user_id;
    cm->subscriptions[cm->subscription_count].joined_at = time(NULL);
    cm->subscription_count++;
    
    channel_save_to_file(cm, channel_id);
    pthread_mutex_unlock(&cm->lock);
    return 0;
}

int channel_is_member(struct channel_manager *cm, uint64_t channel_id, uint64_t user_id){
    
    struct channel *ch = channel_find(cm, channel_id);
    if (!ch)
        return 0;
    
    for (int i = 0; i < ch->participant_count; i++){
        if (ch->participant_ids[i] == user_id)
            return 1;
    }

    return 0;
}

void channel_save_to_file(struct channel_manager *cm, uint64_t channel_id){
    struct channel *ch = channel_find(cm, channel_id);
    if (!ch) return;
    
    char filename[256];
    snprintf(filename, sizeof(filename), "%s%" PRIu64 ".dat", "channel_", channel_id);
    
    FILE *file = fopen(filename, "wb");
    if (!file) return;
    
    fwrite(ch, sizeof(struct channel), 1, file);
    fclose(file);
}

int channel_add_message(struct channel_manager *cm, uint64_t channel_id, 
                       uint64_t sender_id, const char *content, int msg_type){

    pthread_mutex_lock(&cm->lock); 
    struct channel *ch = channel_find(cm, channel_id);
    if (!ch) {
        pthread_mutex_unlock(&cm->lock);
        return -1;
    }
    
    int is_member = 0;
    for (int i = 0; i < ch->participant_count; i++){
        if (ch->participant_ids[i] == sender_id){
            is_member = 1;
            break;
        }
    }
    
    if (!is_member){
        pthread_mutex_unlock(&cm->lock);
        return -2;
    }
    
    int msg_index = ch->message_count % MSG_BUFFER_LIMIT; 
    ch->messages[msg_index].msg_id = generate_uuid(8);
    ch->messages[msg_index].sender_id = sender_id;
    ch->messages[msg_index].timestamp = (uint32_t)time(NULL);
    ch->messages[msg_index].msg_type = msg_type;
    if (content){
        strncpy(ch->messages[msg_index].content, content, 
                sizeof(ch->messages[msg_index].content) - 1);
    }
    
    ch->message_count++;
    channel_save_to_file(cm, channel_id);
    
    pthread_mutex_unlock(&cm->lock);
    return 0;
}

void channel_load_from_file(struct channel_manager *cm, uint64_t channel_id){
    char filename[256];
    snprintf(filename, sizeof(filename), "%s%lu.dat", 
             "channel_", channel_id);
    
    FILE *file = fopen(filename, "rb");
    if (!file) return;
    
    struct channel ch;
    if (fread(&ch, sizeof(struct channel), 1, file) == 1){
        pthread_mutex_lock(&cm->lock);
        
        int exists = 0;
        for (int i = 0; i < cm->channel_count; i++){
            if (cm->channels[i].channel_id == channel_id){
                exists = 1;
                break;
            }
        }
        
        if (!exists && cm->channel_count < MAX_CHANNELS){
            cm->channels[cm->channel_count] = ch;
            cm->channel_count++;
        }
        
        pthread_mutex_unlock(&cm->lock);
    }
    
    fclose(file);
}