//
// Created by bryan on 11/20/2022.
//

#include <stdio.h>
#include <sys/socket.h>
#include "common.h"
#include "cryptotest.h"


/* encrypted message format
 * 16 bytes IV
 * remaining bytes encrypted data
 * size of e data is recv size - IV size (16)
 */

/* encrypt and send null terminated string */
ssize_t send_encrypted_message(
        int fd,
        unsigned char* key,
        const char* plaintext) {
    if (NULL == key) { return -1; }
    if (NULL == plaintext) { return -1; }

    /* P2 encrypt plaintext */
    int plaintext_len = (int) (strlen(plaintext) + 1);
    char buffer_out[BUFFER_SIZE];
    unsigned char* iv = (unsigned char*) &buffer_out[0];
    unsigned char* ciphertext = (unsigned char*) &buffer_out[IV_SIZE];

    /* send iv and encrypted text */
    RAND_bytes(iv, IV_SIZE);
    int ciphertext_len = encrypt(
            (unsigned char*) plaintext, plaintext_len,
            key, iv,
            ciphertext);
    printf("cypher length %d\n", ciphertext_len);


    /* P2 send our encrypted */
    int len = IV_SIZE + ciphertext_len;
    ssize_t sent = send(fd, buffer_out, len, 0);
    if (sent < 0) {
        perror("send encrypted text");
    }

    return sent;
}

/* receive and decrypt a null terminated string */
ssize_t recv_encrypted_message(
        int fd,
        unsigned char* key,
        char* plaintext) {
    if (NULL == key) { return -1; }
    if (NULL == plaintext) { return -1; }

    char buffer_in[BUFFER_SIZE];
    unsigned char* iv = (unsigned char*) &buffer_in[0];
    unsigned char* ciphertext = (unsigned char*) &buffer_in[IV_SIZE];

    /* P2 recv users encrypted text */
    ssize_t rec = recv(fd, buffer_in, BUFFER_SIZE, 0);
    printf("encrypted text length %zd\n", rec);
    if (rec < 0) {
        perror("recv encrypted text");
        return rec;
    }
    if (rec == 0) {
        return rec;
    }

    /* P2 decrypt text */
    int ciphertext_len = (int) (rec - IV_SIZE);
    int plaintext_len = decrypt(
            ciphertext, ciphertext_len,
            key, iv,
            (unsigned char*) plaintext);
    printf("decrypted text length %d\n", plaintext_len);

    return plaintext_len;
}
