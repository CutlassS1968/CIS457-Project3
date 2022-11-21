#ifndef CIS457_PROJECT3_COMMON_H
#define CIS457_PROJECT3_COMMON_H

#define IV_SIZE 16
#define KEY_SIZE 32         // size of client symmetrical key
#define NAME_SIZE 128       // max username size
#define BUFFER_SIZE 1024    // size of send/receive buffers

ssize_t send_encrypted_message(int fd, unsigned char* key, const char* plaintext);
ssize_t recv_encrypted_message(int fd, unsigned char* key, char* plaintext);

#endif //CIS457_PROJECT3_COMMON_H
