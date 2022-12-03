/****************************************************
 *                  Project 3
 *                 CIS 457  03
 *
 * Bryan Vandyke
 *  email: vandybry@mail.gvsu.edu
 *  email: bryan.vandyke@gmail.com
 *
 * Evan Johns
 *  email: johnsev@mail.gvsu.edu
 *  email: evanlloydjohns@gmail.com
 ****************************************************/

#include <stdio.h>
#include <sys/socket.h>
#include "common.h"
#include "cryptotest.h"


/* encrypted message format
 * 16 bytes IV
 * remaining bytes encrypted data
 * size of encrypted data is recv size - IV size (16)
 */

/* encrypt and send null terminated string */
ssize_t send_encrypted_message(
        int fd,
        unsigned char* key,
        const char* plaintext) {
    if (NULL == key) { return -1; }
    if (NULL == plaintext) { return -1; }

    int plaintext_len = (int) (strlen(plaintext) + 1);
    char buffer_out[BUFFER_SIZE];
    unsigned char* iv = (unsigned char*) &buffer_out[0];
    unsigned char* ciphertext = (unsigned char*) &buffer_out[IV_SIZE];

    /* encrypt plaintext */
    RAND_bytes(iv, IV_SIZE);
    int ciphertext_len = encrypt(
            (unsigned char*) plaintext, plaintext_len,
            key, iv,
            ciphertext);

    /* send our encrypted data blob */
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

    /* receive users encrypted blob */
    ssize_t rec = recv(fd, buffer_in, BUFFER_SIZE, 0);
    if (rec < 0) {
        perror("recv encrypted text");
        return rec;
    }
    if (rec == 0) {
        return rec;
    }

    /* decrypt text */
    int ciphertext_len = (int) (rec - IV_SIZE);
    int plaintext_len = decrypt(
            ciphertext, ciphertext_len,
            key, iv,
            (unsigned char*) plaintext);

    return plaintext_len;
}
