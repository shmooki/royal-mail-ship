#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <time.h>
#include <inttypes.h>
#include <sys/sendfile.h>
#include <sys/stat.h> 

#include "utility.h"
#include "rsa.h"
#include "client_info.h"
#include "encrypted_packet.h"
#include "channel.h"

#define CLIENTS_LIMIT 10
#define CRED_FILE "client_credentials"

// Server File Descriptor
int server_fd;

// RSA Keys
long s_n, s_e, s_d;

// Client Management
pthread_mutex_t u_lock = PTHREAD_MUTEX_INITIALIZER;
struct channel_manager cm;
struct client users[CLIENTS_LIMIT];
int num_users = 0;
FILE *cred_file = NULL;

int insert_user(struct client *new_user) {
    pthread_mutex_lock(&u_lock);
    for (int i = 0; i < CLIENTS_LIMIT; i++) {
        if (users[i].socket_fd == -1 && users[i].username[0] == '\0') {
            users[i] = *new_user;
            users[i].socket_fd = new_user->socket_fd;
            num_users++;
            pthread_mutex_unlock(&u_lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&u_lock);
    return -1;
}

int find_user_index_by_username(const char *username) {
    if (!username) return -1;
    pthread_mutex_lock(&u_lock);
    for (int i = 0; i < CLIENTS_LIMIT; i++) {
        if (users[i].username[0] != '\0' && strcmp(users[i].username, username) == 0) {
            pthread_mutex_unlock(&u_lock);
            return i;
        }
    }
    pthread_mutex_unlock(&u_lock);
    return -1;
}

int find_user_index_by_user_id(uint64_t user_id) {
    pthread_mutex_lock(&u_lock);
    for (int i = 0; i < CLIENTS_LIMIT; i++) {
        if (users[i].username[0] != '\0' && users[i].user_id == user_id) {
            pthread_mutex_unlock(&u_lock);
            return i;
        }
    }
    pthread_mutex_unlock(&u_lock);
    return -1;
}

void broadcast_to_channel(const char *msg, uint64_t sender_id, uint64_t channel_id, int exclude_fd) {
    if (!msg) 
        return;

    struct encrypted_packet p = {0};
    struct channel *ch = channel_find(&cm, channel_id);
    if (!ch){
        printf("[ERROR] Channel %" PRIu64 " not found for broadcast\n", channel_id);
        return;
    } 
       
    int sender_idx = find_user_index_by_user_id(sender_id);
    if (sender_idx != -1) {
        pthread_mutex_lock(&u_lock);
        strncpy(p.username, users[sender_idx].username, USERNAME_SIZE - 1);
        pthread_mutex_unlock(&u_lock);
    }
    
    p.sender_id = sender_id;
    p.channel_id = channel_id;
    p.timestamp = (uint32_t)time(NULL);
    
    if (strncmp(msg, "FILE_METADATA:", 14) == 0){
        
        p.is_file = 1;
        const char *src = msg + 14;
        size_t src_len = strlen(src);
        char *metadata = malloc(src_len + 1);

        if (metadata != NULL) {
            memcpy(metadata, src, src_len + 1); 
            char *filename = strtok(metadata, ":");
            char *filesize_str = strtok(NULL, ":");
            char *channel_id_str = strtok(NULL, ":");

            if (filename && filesize_str && channel_id_str) {
                strncpy(p.file_name, filename, sizeof(p.file_name) - 1);
                p.file_name[sizeof(p.file_name) - 1] = '\0';
                p.file_size = (unsigned long) atol(filesize_str);
                p.channel_id = (uint64_t) atol(channel_id_str);
            }
            free(metadata);
        }
    }
    
    for (int i = 0; i < ch->participant_count; i++){
        uint64_t participant_id = ch->participant_ids[i];
        
        if (exclude_fd != -1 && participant_id == sender_id) 
            continue;
        
        // Find client by user_id
        int user_id = find_user_index_by_user_id(participant_id);
        if (user_id == -1 || users[user_id].socket_fd == -1) 
            continue;
        
        struct client *recipient = &users[user_id];
        
        size_t enc_len;
        long *enc = encrypt(msg, recipient->public_key_e, recipient->public_key_n, &enc_len);
        if (!enc) continue;

        if (enc_len > MAX_ENCRYPTED_PAYLOAD) 
            enc_len = MAX_ENCRYPTED_PAYLOAD;

        p.len = enc_len;

        for (size_t j = 0; j < enc_len; j++){
            p.encrypted_payload[j] = enc[j];
        }

        send(recipient->socket_fd, &p, sizeof(p), 0);
        free(enc);
    }
}

void rsa_handshake(int fd, struct client *u) {
    send(fd, &s_n, sizeof(long), 0);
    send(fd, &s_e, sizeof(long), 0);

    recv(fd, &u->public_key_n, sizeof(long), 0);
    recv(fd, &u->public_key_e, sizeof(long), 0);

    printf("• RSA Handshake with User [%d] | Public Key (n, e): (%ld, %ld)\n",
           fd, u->public_key_n, u->public_key_e);
}

void send_encrypted(int fd, char *payload, long e, long n) {
    size_t enc_len;
    long *cipher = encrypt(payload, e, n, &enc_len);
    if (!cipher)
        return;

    if (enc_len > MAX_ENCRYPTED_PAYLOAD)
        enc_len = MAX_ENCRYPTED_PAYLOAD;

    struct encrypted_packet p = {0};
    for (size_t i = 0; i < enc_len; i++)
        p.encrypted_payload[i] = cipher[i];

    p.len = enc_len;

    send(fd, &p, sizeof(p), 0);
    free(cipher);
}

char *recv_decrypted(int fd, long d, long n) {
    struct encrypted_packet p = {0};
    ssize_t r = recv(fd, &p, sizeof(p), 0);
    if (r <= 0 || p.len == 0 || p.len > MAX_ENCRYPTED_PAYLOAD)
        return NULL;

    char *plaintext = decrypt(p.encrypted_payload, p.len, d, n);
    return plaintext;
}

void combine_file_chunks(const char *dir, const char *filename, uint32_t total_chunks) {
    char full_path[512];
    snprintf(full_path, sizeof(full_path), "%s/%s", dir, filename);
    
    FILE *output = fopen(full_path, "wb");
    if (!output) return;
    
    for (uint32_t i = 0; i < total_chunks; i++) {
        char chunk_path[512];
        snprintf(chunk_path, sizeof(chunk_path), "%s/%s.part%u", dir, filename, i);
        
        FILE *chunk = fopen(chunk_path, "rb");
        if (chunk) {
            uint8_t buffer[4096];
            size_t bytes;
            while ((bytes = fread(buffer, 1, sizeof(buffer), chunk)) > 0) {
                fwrite(buffer, 1, bytes, output);
            }
            fclose(chunk);
            unlink(chunk_path); // Remove chunk file
        }
    }
    
    fclose(output);
}

void handle_message(struct client *u, struct encrypted_packet *p, char *msg){
    uint64_t actual_channel_id = p->channel_id;
    char *message_content = msg;
    
    if (strncmp(msg, "ID:", 3) == 0){
        char *id_str = msg + 3;
        char *colon = strchr(id_str, ':');
        if (colon){
            *colon = '\0';
            actual_channel_id = strtoull(id_str, NULL, 10);
            message_content = colon + 1;
        }
    } else if(strncmp(msg, "NAME:", 5) == 0){
        char *name = msg + 5;
        char *colon = strchr(name, ':');
        if (colon) {
            *colon = '\0';
            struct channel *ch = channel_find_by_name(&cm, name);
            if (ch){
                actual_channel_id = ch->channel_id;
                message_content = colon + 1;
            } else{
                char error[128];
                snprintf(error, sizeof(error), "Channel '%s' not found", name);
                send_encrypted(u->socket_fd, error, u->public_key_e, u->public_key_n);
                printf("[ERROR] Channel '%s' not found\n", name);
                return;
            }
        }
    } else if (actual_channel_id == 0) {
        // No channel specified and no prefix
        char *error = "Please specify channel with /msg <channel> <message>";
        send_encrypted(u->socket_fd, error, u->public_key_e, u->public_key_n);
        printf("[ERROR] No channel specified in message\n");
        return;
    }
    
    printf("• User [%s | %" PRIu64 "] in channel %" PRIu64 ":\n%s\n",
           u->username, u->user_id, actual_channel_id, message_content);
    
    // Check if user is member of channel
    if (!channel_is_member(&cm, actual_channel_id, u->user_id)) {
        char *error = "You are not a member of this channel";
        send_encrypted(u->socket_fd, error, u->public_key_e, u->public_key_n);
        return;
    }

    channel_add_message(&cm, actual_channel_id, u->user_id, message_content, MSG_TYPE_TEXT);
    broadcast_to_channel(message_content, u->user_id, actual_channel_id, u->socket_fd);
}

void handle_file_transfer(struct client *u, struct encrypted_packet *p) {
    if (!channel_is_member(&cm, p->channel_id, u->user_id)) {
        char *error = "You are not a member of this channel";
        send_encrypted(u->socket_fd, error, u->public_key_e, u->public_key_n);
        return;
    }
    
    // Create directory for files if it doesn't exist
    char channel_dir[256];
    snprintf(channel_dir, sizeof(channel_dir), "channel_%lu_files", p->channel_id);
    mkdir(channel_dir, 0755);
    
    // Save file chunk
    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s/%s.part%u", 
             channel_dir, p->file_name, p->chunk_index);
    
    FILE *file = fopen(file_path, "wb");
    if (file){
        fwrite(p->file_data, 1, p->len, file);
        fclose(file);
        
        // If this is the last chunk, combine all parts
        if (p->chunk_index == p->total_chunks - 1){
            combine_file_chunks(channel_dir, p->file_name, p->total_chunks);
 
            char file_message[512];
            snprintf(file_message, sizeof(file_message),
                    "[FILE] %s (%lu bytes)", p->file_name, p->file_size);
            channel_add_message(&cm, p->channel_id, u->user_id, file_message, MSG_TYPE_FILE);

            // Notify channel members about the file
            char notification[512];
            snprintf(notification, sizeof(notification),
                    "[FILE] %s uploaded: %s (%lu bytes)", 
                    u->username, p->file_name, p->file_size);

            // Use channel-specific broadcast
            broadcast_to_channel(notification, u->user_id, p->channel_id, u->socket_fd);
            
            // Also send file metadata
            char file_metadata[512];
            snprintf(file_metadata, sizeof(file_metadata),
                    "FILE_METADATA:%s:%lu:%lu", 
                    p->file_name, p->file_size, p->channel_id);
            
            broadcast_to_channel(file_metadata, u->user_id, p->channel_id, u->socket_fd);
        }
    }
}

void handle_channel_create(struct client *u, const char *channel_info) {
    char channel_name[CHANNEL_NAME_SIZE] = {0};
    
    // Parse the input
    sscanf(channel_info, "%31s", channel_name);
    
    if (strlen(channel_name) == 0) {
        char *error = "Usage: /create <channel_name>";
        send_encrypted(u->socket_fd, error, u->public_key_e, u->public_key_n);
        return;
    }
    
    // Check if channel name already exists
    struct channel *existing = channel_find_by_name(&cm, channel_name);
    if (existing) {
        char error[128];
        snprintf(error, sizeof(error), "Channel '%s' already exists (ID: %" PRIu64 ")\n", 
                channel_name, existing->channel_id);
        send_encrypted(u->socket_fd, error, u->public_key_e, u->public_key_n);
        return;
    }   
    
    // Create the channel
    uint64_t channel_id = channel_create(&cm, channel_name, u->user_id);
    
    if (channel_id == 0){
        char *error = "Failed to create channel (max channels reached?)";
        send_encrypted(u->socket_fd, error, u->public_key_e, u->public_key_n);
        return;
    }
    
    // Success message
    char success_msg[256];
    snprintf(success_msg, sizeof(success_msg),
            "Channel '%s' created successfully! ID: %" PRIu64 "\n"
            "You have been automatically joined to this channel.\n"
            "Use '/join %lu' or '/join %s' to join from other sessions.",
            channel_name, channel_id, channel_id, channel_name);
    
    send_encrypted(u->socket_fd, success_msg, u->public_key_e, u->public_key_n);
    
    // Log system message to channel
    char system_msg[256];
    snprintf(system_msg, sizeof(system_msg),
            "Channel created by %s. Welcome!", u->username);

    channel_add_message(&cm, channel_id, u->user_id, system_msg, MSG_TYPE_TEXT);
}

void handle_channel_join(struct client *u, const char *channel_input){
    uint64_t channel_id = 0;
    char channel_name[CHANNEL_NAME_SIZE] = {0};
    struct channel *ch =  NULL;

    // Try to parse as channel ID (numeric)
    char *endptr;
    channel_id = strtoul(channel_input, &endptr, 10);
    
    if (*endptr != '\0'){
        ch = channel_find_by_name(&cm, channel_input);
        if (ch) {
            channel_id = ch->channel_id;
            strncpy(channel_name, ch->channel_name, sizeof(channel_name) - 1);
            channel_name[sizeof(channel_name) - 1] = '\0';
        } else{
            char error[128];
            snprintf(error, sizeof(error), 
                    "Channel '%s' not found. Use /channels to see available channels.",
                    channel_input);
            send_encrypted(u->socket_fd, error, u->public_key_e, u->public_key_n);
            return;
        }
    } else{
        ch = channel_find(&cm, channel_id);
        if (ch){
            strncpy(channel_name, ch->channel_name, CHANNEL_NAME_SIZE - 1);
        }
    }
    
    // // Check if channel exists
    // struct channel *ch = channel_find(&cm, channel_id);
    if (!ch) {
        char error[128];
        snprintf(error, sizeof(error), "Channel %lu not found", channel_id);
        send_encrypted(u->socket_fd, error, u->public_key_e, u->public_key_n);
        return;
    }  
    
    // Try to join the channel
    int result = channel_join(&cm, channel_id, u->user_id);
    if (result == 0){
        char success_msg[512];
        
        if (strlen(channel_name) > 0){
            snprintf(success_msg, sizeof(success_msg),
                    "Successfully joined channel '%s' (ID: %lu)\n"
                    "Members: %d\n"
                    "Use '/msg %lu <message>' or '/msg %s <message>' to send messages to this channel.",
                    channel_name, channel_id, ch->participant_count, channel_id, channel_name);
        } else{
            snprintf(success_msg, sizeof(success_msg),
                    "Successfully joined channel ID: %lu\n"
                    "Members: %d",
                    channel_id, ch->participant_count);
        }
        
        send_encrypted(u->socket_fd, success_msg, u->public_key_e, u->public_key_n);
        
        // Notify channel members
        char join_msg[256];
        snprintf(join_msg, sizeof(join_msg),
                "%s has joined the channel.", u->username);
        
        broadcast_to_channel(join_msg, u->user_id, channel_id, u->socket_fd);
        channel_add_message(&cm, channel_id, u->user_id, join_msg, MSG_TYPE_TEXT);
    }
}

void *worker(void *arg) {
    struct client *u = arg;
    if (!u) return NULL;

    for (;;){

        struct encrypted_packet p = {0};
        ssize_t rec = recv(u->socket_fd, &p, sizeof(p), 0);
        printf("sizeof(encrypted_packet) = %zu\n", sizeof(struct encrypted_packet));

        if (rec <= 0) {
            printf("• User %s disconnected.\n", u->username);
            close(u->socket_fd);
            pthread_mutex_lock(&u_lock);
            u->socket_fd = -1;
            pthread_mutex_unlock(&u_lock);
            return NULL;
        }

        char *msg = decrypt(p.encrypted_payload, p.len, s_d, s_n);
        if (!msg) {
            continue;
        }

        printf("\n• Received from [%s | %lu] (cmd=%d, channel=%lu): %s\n",
               u->username, u->user_id,
               p.command_type, p.channel_id,
               msg);

        switch (p.command_type) {
            case CMD_MESSAGE:
                handle_message(u, &p, msg);
                break;
            case CMD_FILE_TRANSFER:
                handle_file_transfer(u, &p);
                break;
            case CMD_CHANNEL_CREATE:
                handle_channel_create(u, msg);
                break;
            case CMD_CHANNEL_JOIN:
                handle_channel_join(u, msg);
                break;
            default:
                printf("• Unknown command %d\n", p.command_type);
        }

        free(msg);
    }
}

void create_worker_thread(struct client *u){
    pthread_t t;
    int rc = pthread_create(&t, NULL, worker, u);
    if (rc != 0) {
        printf("[ERROR] pthread_create failed for %s\n", u->username);
        return;
    }
    pthread_detach(t);
}

void load_credentials(){
    printf("\n• Loading credentials from file...\n");

    fseek(cred_file, 0, SEEK_SET);
    char line[256];
    while (fgets(line, sizeof(line), cred_file)){
        char username[USERNAME_SIZE] = {0};
        char password[PASSWORD_SIZE] = {0};
        uint64_t user_id = 0;
        if (sscanf(line, "%31s %31s %" SCNu64, username, password, &user_id) < 3){
            continue;
        }

        struct client u = {0};
        strncpy(u.username, username, sizeof(u.username) - 1);
        u.username[sizeof(u.username) - 1] = '\0';
        strncpy(u.password, password, sizeof(u.password) - 1);
        u.password[sizeof(u.password) - 1] = '\0';
        u.user_id = (uint64_t) user_id;
        u.socket_fd = -1;
        u.public_key_e = 0;
        u.public_key_n = 0;

        if (find_user_index_by_username(username) == -1 && strlen(username) > 0 && strlen(password) > 0) {
            if (insert_user(&u) == 0) {
                printf("• Loaded Credential > Username: %s, Password: %s\n", username, password);
            }
        }
    }

    printf("• Finished loading credentials. Total users: %d...\n\n", num_users);
}

int s_init(int port) {
    struct sockaddr_in serv = {0};
    serv.sin_family = AF_INET;
    serv.sin_port = htons(port);
    serv.sin_addr.s_addr = htonl(INADDR_ANY);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(fd, (struct sockaddr *)&serv, sizeof(serv)) < 0) return -1;
    if (listen(fd, CLIENTS_LIMIT) < 0) return -1;

    for (int i = 0; i < CLIENTS_LIMIT; i++) {
        users[i].socket_fd = -1;
        users[i].username[0] = '\0';
        users[i].password[0] = '\0';
        users[i].public_key_e = 0;
        users[i].public_key_n = 0;
        users[i].user_id = 0;
    }

    cred_file = fopen(CRED_FILE, "a+");
    if (!cred_file) {
        printf("• Failed to open credentials file.\n");
        return -1;
    }

    load_credentials();
    return fd;
}

int main() {
    srand(time(NULL));
    generate_rsa_keys(&s_n, &s_e, &s_d);
    channel_manager_init(&cm);

    printf("• Generated RSA keys:\n");
    printf("• Public Key (n, e): (%ld, %ld)\n", s_n, s_e);
    printf("• Private Key d: %ld\n", s_d);

    int port = 8080;
    printf("\n• What port to listen on?\n> ");
    if (scanf("%d", &port) != 1) {
        fprintf(stderr, "Invalid port input.\n");
        return 1;
    }
    flush_buffer();

    if (port <= 0 || port > 65535) {
        printf("• Invalid port number.\n");
        return 1;
    }

    server_fd = s_init(port);
    if (server_fd < 0) {
        printf("\n• Server failed to start.\n");
        return 1;
    }

    printf("• Server started on port %d.\n", port);

    for (;;) {
        int fd = accept(server_fd, NULL, NULL);
        if (fd < 0) {
            perror("accept");
            continue;
        }

        struct client t = {0};
        t.socket_fd = fd;
        t.public_key_e = 0;
        t.public_key_n = 0;

        rsa_handshake(fd, &t);

        char *username = recv_decrypted(fd, s_d, s_n);
        char *password = recv_decrypted(fd, s_d, s_n);

        printf("• Received credentials from [%d]: Username='%s', Password='%s'\n",
               fd,
               username ? username : "NULL",
               password ? password : "NULL");

        if (!username || !password || strlen(username) >= USERNAME_SIZE || strlen(password) >= PASSWORD_SIZE) {
            printf("• Invalid username/password from [%d], disconnecting.\n", fd);
            close(fd);
            free(username);
            free(password);
            continue;
        }

        int idx = find_user_index_by_username(username);
        struct client *u = NULL;

        if (idx != -1) {
            pthread_mutex_lock(&u_lock);
            if (strcmp(users[idx].password, password) != 0) {
                pthread_mutex_unlock(&u_lock);
                printf("• Incorrect password for '%s' from [%d], disconnecting.\n", username, fd);
                close(fd);
                free(username);
                free(password);
                continue;
            }

            if (users[idx].socket_fd != -1) {
                pthread_mutex_unlock(&u_lock);
                printf("• User '%s' already connected, rejecting new connection from [%d].\n", username, fd);
                close(fd);
                free(username);
                free(password);
                continue;
            }

            users[idx].socket_fd = fd;
            users[idx].public_key_e = t.public_key_e;
            users[idx].public_key_n = t.public_key_n;
            pthread_mutex_unlock(&u_lock);

            u = &users[idx];
            printf("• User '%s' reconnected from [%d].\n", username, fd);
        } else {
            strncpy(t.username, username, USERNAME_SIZE - 1);
            strncpy(t.password, password, PASSWORD_SIZE - 1);
            t.user_id = generate_uuid(8);
            t.socket_fd = fd;

            if (insert_user(&t) < 0) {
                printf("• Max users reached, rejecting [%d]\n", fd);
                close(fd);
                free(username);
                free(password);
                continue;
            }

            idx = find_user_index_by_username(username);
            if (idx == -1) {
                printf("• Unexpected insertion error for '%s'.\n", username);
                close(fd);
                free(username);
                free(password);
                continue;
            }

            u = &users[idx];

            pthread_mutex_lock(&u_lock);
            fprintf(cred_file, "%s %s %" PRIu64 "\n", u->username, u->password, u->user_id);
            fflush(cred_file);
            pthread_mutex_unlock(&u_lock);

            printf("• New user '%s' registered from [%d].\n", username, fd);
        }

        free(username);
        free(password);

        char user_id_str[32];
        snprintf(user_id_str, sizeof(user_id_str), "%lu", (unsigned long)u->user_id);
        send_encrypted(u->socket_fd, user_id_str, u->public_key_e, u->public_key_n);

        create_worker_thread(u);
    }
}