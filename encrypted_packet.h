#pragma once
#include "client_info.h"
#include <stdint.h>

#ifndef ENCRYPTED_PACKET_H
#define ENCRYPTED_PACKET_H

#define MAX_ENCRYPTED_PAYLOAD 256
#define USERNAME_SIZE 32
#define PASSWORD_SIZE 32

#define CMD_MESSAGE 0
#define CMD_FILE_TRANSFER 1
#define CMD_CHANNEL_CREATE 2
#define CMD_CHANNEL_JOIN 3
#define CMD_CHANNEL_LEAVE 4
#define CMD_LIST_CHANNELS 5
#define CMD_LIST_MEMBERS 6
#define CMD_CHANNEL_INFO 7
#define CMD_INVITE_USER 8

struct encrypted_packet {
    uint64_t sender_id;          
    uint64_t channel_id;
    uint64_t msg_id;

    uint32_t timestamp;
    uint32_t len;
    uint32_t command_type;

    char username[USERNAME_SIZE];
    int64_t encrypted_payload[MAX_ENCRYPTED_PAYLOAD];

    uint8_t is_file;
    char file_name[256];
    uint64_t file_size;
    uint32_t chunk_index;
    uint32_t total_chunks;

    uint8_t file_data[4096];
};

#endif
