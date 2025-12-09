#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/stat.h>

#include "utility.h"
#include "rsa.h"
#include "encrypted_packet.h"
#include "channel.h"

// Client Information
uint64_t user_id = -1;

// Server File Descriptor
int server_fd = -1;

// Channel Information
uint64_t current_channel_id = 0;

// RSA Keys
long s_n, s_e;
long c_n, c_e, c_d;

void rsa_handshake(int fd) {
    recv(fd, &s_n, sizeof(long), 0);
    recv(fd, &s_e, sizeof(long), 0);

    send(fd, &c_n, sizeof(long), 0);
    send(fd, &c_e, sizeof(long), 0);

    printf("\n• RSA Handshake | Public Key (n, e): (%ld, %ld)\n", s_n, s_e);
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

void send_file(const char *filepath, uint64_t channel_id){
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        printf("Cannot open file: %s\n", filepath);
        return;
    }
    
    // Get file size
    long file_size = ftell(file);
    fseek(file, 0, SEEK_END);
    fseek(file, 0, SEEK_SET);
    
    if (file_size > MAX_MEDIA_SIZE){
        printf("File too large (max: %d bytes)\n", MAX_MEDIA_SIZE);
        fclose(file);
        return;
    }
    
    // Get filename from path
    const char *filename = strrchr(filepath, '/');
    if (!filename) 
        filename = strrchr(filepath, '\\');
    if (!filename) 
        filename = filepath;
    else 
        filename++;
    
    // Calculate chunks
    size_t chunk_size = 4096;
    uint32_t total_chunks = (file_size + chunk_size - 1) / chunk_size; 
    uint8_t buffer[4096];
    uint32_t chunk_index = 0;
    
    while (!feof(file)) {
        size_t bytes_read = fread(buffer, 1, chunk_size, file);
        if (bytes_read == 0) break;
        
        struct encrypted_packet p = {0};
        p.sender_id = user_id;
        p.channel_id = channel_id;
        p.msg_id = generate_uuid(10);
        p.timestamp = (uint32_t)time(NULL);
        p.command_type = CMD_FILE_TRANSFER;
        p.is_file = 1;
        strncpy(p.file_name, filename, sizeof(p.file_name) - 1);
        p.file_name[sizeof(p.file_name) - 1] = '\0';
        p.file_size = file_size;
        p.chunk_index = chunk_index;
        p.total_chunks = total_chunks;
        
        // Encrypt file metadata (not the actual file data for performance)
        char metadata[256];
        snprintf(metadata, sizeof(metadata), "FILE:%s:%lu:%u:%u", 
                filename, file_size, chunk_index, total_chunks);
        
        size_t enc_len;
        long *cipher = encrypt(metadata, s_e, s_n, &enc_len);
        
        if (cipher){
            p.len = (uint32_t)enc_len;

            for (size_t i = 0; i < enc_len && i < MAX_ENCRYPTED_PAYLOAD; i++){
                p.encrypted_payload[i] = cipher[i];
            }

            free(cipher);
        }
        
        // Copy raw file data
        memcpy(p.file_data, buffer, bytes_read);
        p.len = bytes_read; 
        
        send(server_fd, &p, sizeof(p), 0);
        chunk_index++;
        
        printf("Sent chunk %u/%u\r", chunk_index, total_chunks);
        fflush(stdout);
    }
    
    fclose(file);
    printf("\nFile sent: %s\n", filename);
}

void handle_incoming_file(struct encrypted_packet *p){
    if (!p->is_file) return;
    
    printf("\n[%s] sent a file: %s (%lu bytes)\n", 
           p->username, p->file_name, p->file_size);
    
    printf("Do you want to download it? (y/n): ");
    fflush(stdout);
    
    char response[16];
    fgets(response, sizeof(response), stdin);
    
    if (response[0] == 'y' || response[0] == 'Y') {
        printf("Downloading to: downloads/\n");
        
        // Create downloads directory
        mkdir("downloads", 0755);
        
        char filepath[512];
        snprintf(filepath, sizeof(filepath), "downloads/%s", p->file_name);
        
        // In a real implementation, you would request the file chunks from server
        printf("File info received. Use /getfile %s to download.\n", p->file_name);
    }
}

int c_init(const char *ip, int port) {
    struct sockaddr_in serv = {0};

    serv.sin_family = AF_INET;
    serv.sin_port = htons(port);
    inet_pton(AF_INET, ip, &serv.sin_addr);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    if (connect(fd, (struct sockaddr *)&serv, sizeof(serv)) < 0)
        return -1;

    rsa_handshake(fd);

    server_fd = fd;
    return 0;
}

void *message_bar_thread() {
    char input[512];

    printf("Available commands:\n");
    printf("  /create <name> - Create new channel\n");
    printf("  /join <id_or_name>       - Join a channel\n");
    printf("  /msg <id_or_name> <message>      - Send to specific channel\n");
    printf("  /file <path> [channel]   - Send file\n");
    printf("  /help                    - Show this help\n");
    for (;;) {
        printf("> ");
        fflush(stdout);

        if (!fgets(input, sizeof(input), stdin))
            continue;

        input[strcspn(input, "\n")] = 0;

        if (strlen(input) == 0)
            continue;
        
        // Check for commands
        if (strncmp(input, "/file ", 6) == 0){
            char *filepath = input + 6;
            uint64_t channel_id = 1; 
            
            char *space = strchr(filepath, ' ');
            if (space) {
                *space = '\0';
                channel_id = strtoull(space + 1, NULL, 10);
            }
            
            send_file(filepath, channel_id);
            continue;
        } else if(strncmp(input, "/create ", 8) == 0){
            struct encrypted_packet p = {0};
            p.command_type = CMD_CHANNEL_CREATE;
            p.sender_id = user_id;
            p.channel_id = generate_uuid(8);
            
            size_t enc_len;
            long *cipher = encrypt(input + 8, s_e, s_n, &enc_len);
            
            if (cipher){

                p.len = (uint32_t)enc_len;

                for (size_t i = 0; i < enc_len && i < MAX_ENCRYPTED_PAYLOAD; i++) {
                    p.encrypted_payload[i] = cipher[i];
                }

                free(cipher);
            }
            
            send(server_fd, &p, sizeof(p), 0);
            continue;
        } else if (strncmp(input, "/join ", 6) == 0){
            char *arg = input + 6;
            struct encrypted_packet p = {0};

            p.command_type = CMD_CHANNEL_JOIN;
            p.sender_id = user_id;

            char *endptr;
            uint64_t cid = strtoull(arg, &endptr, 10);

            if (*endptr == '\0')
                p.channel_id = cid;   
            else
                p.channel_id = 0;     

            size_t enc_len;
            long *cipher = encrypt(arg, s_e, s_n, &enc_len);

            p.len = enc_len;
            for (size_t i = 0; i < enc_len && i < MAX_ENCRYPTED_PAYLOAD; i++)
                p.encrypted_payload[i] = cipher[i];

            free(cipher);
            send(server_fd, &p, sizeof(p), 0);
            continue;
        } else if(strncmp(input, "/info ", 6) == 0){

            struct encrypted_packet p = {0};
            p.command_type = CMD_CHANNEL_INFO;
            p.sender_id = user_id;
            
            size_t enc_len;
            long *cipher = encrypt(input + 6, s_e, s_n, &enc_len);
            
            if (cipher) {
                p.len = (uint32_t)enc_len;
                for (size_t i = 0; i < enc_len && i < MAX_ENCRYPTED_PAYLOAD; i++) {
                    p.encrypted_payload[i] = cipher[i];
                }
                free(cipher);
            }
            
            send(server_fd, &p, sizeof(p), 0);
            continue;
        } else if (strncmp(input, "/msg ", 5) == 0){
            char *channel_identifier = input + 5;
            
            char *space_pos = strchr(channel_identifier, ' ');
            if (!space_pos) {
                printf("Usage: /msg <id_or_name> <message>\n");
                continue;
            }
            
            // Extract channel identifier
            int channel_len = space_pos - channel_identifier;
            char channel_str[64] = {0};
            strncpy(channel_str, channel_identifier, channel_len);
            channel_str[channel_len] = '\0';
            
            // Message starts after the space
            char *message = space_pos + 1;
            
            // Check if channel_str is numeric
            char *endptr;
            uint64_t channel_id = strtoull(channel_str, &endptr, 10);
            
            // Prepare the full message
            char full_message[1024];
            if (*endptr == '\0'){
                snprintf(full_message, sizeof(full_message), "ID:%" PRIu64 ":%s", channel_id, message);
            } else{
                snprintf(full_message, sizeof(full_message), "NAME:%s:%s", channel_str, message);
            }
            
            // Encrypt and send
            size_t enc_len = 0;
            long *cipher = encrypt(full_message, s_e, s_n, &enc_len);
            
            if (!cipher) {
                printf("[ERROR] Failed to encrypt message\n");
                continue;
            }
            
            struct encrypted_packet p = {0};
            p.sender_id = user_id;
            p.channel_id = 0; 
            p.msg_id = generate_uuid(8);
            p.timestamp = (uint32_t)time(NULL);
            p.command_type = CMD_MESSAGE;
            p.len = (uint32_t)enc_len;
            
            if (enc_len > MAX_ENCRYPTED_PAYLOAD)
                enc_len = MAX_ENCRYPTED_PAYLOAD;
            
            for (size_t i = 0; i < enc_len; i++)
                p.encrypted_payload[i] = cipher[i];
            
            send(server_fd, &p, sizeof(p), 0);
            free(cipher);
            continue;
        } else if (input[0] == '/'){
            // Unknown command
            printf("Unknown command. Available commands:\n");
            printf("  /create <name> - Create new channel\n");
            printf("  /join <id_or_name>       - Join a channel\n");
            printf("  /msg <id_or_name> <message>      - Send to specific channel\n");
            printf("  /file <path> [channel]   - Send file\n");
            printf("  /help                    - Show this help\n");
            continue;
        }

        size_t enc_len = 0;
        long *cipher = encrypt(input, s_e, s_n, &enc_len);

        if (!cipher) continue;

        struct encrypted_packet p = {0};

        p.sender_id  = user_id;
        p.channel_id = current_channel_id;
        p.msg_id     = generate_uuid(10);
        p.timestamp  = (uint32_t)time(NULL);
        p.command_type = CMD_MESSAGE;
        p.len        = (uint32_t)enc_len;

        if (enc_len > MAX_ENCRYPTED_PAYLOAD)
            enc_len = MAX_ENCRYPTED_PAYLOAD;

        for (size_t i = 0; i < enc_len; i++)
            p.encrypted_payload[i] = cipher[i];

        send(server_fd, &p, sizeof(p), 0);

        free(cipher);
    }
}

void *payload_receiver_thread() {
    for (;;) {
        struct encrypted_packet p = {0};

        ssize_t received = recv(server_fd, &p, sizeof(p), 0);
        if (received <= 0)
            continue;
        
        char *plaintext = decrypt(p.encrypted_payload, p.len, c_d, c_n);
        
        uint64_t new_id = 0;
        if (sscanf(plaintext, "Successfully joined channel '%*[^']' (ID: %lu)", &new_id) == 1 ||
            sscanf(plaintext, "Successfully joined channel ID: %lu", &new_id) == 1 ){

            current_channel_id = new_id;
            printf("Active channel set to %" PRIu64 "\n> ", current_channel_id);
        }

        if (p.is_file){
            handle_incoming_file(&p);

            if (plaintext) 
                free(plaintext);

            continue;
        }
        
        if (!plaintext)
            continue;
        
        printf("[%s] %s\n> ", p.username, plaintext);
        fflush(stdout);
        
        free(plaintext);
    }
}

int main() {
    srand(time(NULL));
    generate_rsa_keys(&c_n, &c_e, &c_d);

    char ip[32];
    int port = 8080;

    printf("• What is the server IP?\n> ");
    fgets(ip, sizeof(ip), stdin);
    ip[strcspn(ip, "\n")] = 0;

    printf("• What is the server port?\n> ");
    scanf("%d", &port);
    flush_buffer();

    if (c_init(ip, port) < 0) {
        printf("• Connection failed.\n");
        return 1;
    }

    printf("\n• Enter username:\n> ");
    char username[32];
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0;

    printf("• Enter password:\n> ");
    char password[32];
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = 0;

    send_encrypted(server_fd, username, s_e, s_n);
    send_encrypted(server_fd, password, s_e, s_n);

    char *uid_s = recv_decrypted(server_fd, c_d, c_n);
    if (uid_s){
        user_id = strtoull(uid_s, NULL, 10);
        free(uid_s);
    } else {
        fprintf(stderr, "Failed to receive user id from server\n");
        return 1;
    }

    printf("\n");

    pthread_t t_send, t_recv;
    pthread_create(&t_send, NULL, message_bar_thread, NULL);
    pthread_create(&t_recv, NULL, payload_receiver_thread, NULL);

    pthread_join(t_send, NULL);
    pthread_join(t_recv, NULL);

    return 0;
}