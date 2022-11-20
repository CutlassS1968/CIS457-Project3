#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <termios.h>
#include "common.h"
#include "cryptotest.h"


/* remember kids globals are bad. m'kay? */
int sockfd = -1;
EVP_PKEY* pubkey = NULL;
unsigned char key[KEY_SIZE];


void crypto_init(void) {
    OpenSSL_add_all_algorithms();

    /* session key */
    RAND_bytes(key, KEY_SIZE);
}

void crypt_cleanup(void) {
    if (pubkey) { EVP_PKEY_free(pubkey); } //not sure if we need to do this
    EVP_cleanup();
}

/* Structs */

/* Helper Methods */


/* perform all the necessary connection protocols with server */
bool handshake(
        uint16_t portNum,
        char* ipaddr,
        const char* username) {
    if (NULL == ipaddr || NULL == username) {
        return false;
    }

    ssize_t rec;
    ssize_t sent;
    char buffer_in[BUFFER_SIZE];
    char buffer_out[BUFFER_SIZE];


    /* init */
    struct sockaddr_in serveraddr;
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(portNum);
    serveraddr.sin_addr.s_addr = inet_addr(ipaddr);

    /* open socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return false;
    }

    /* connect to server */
    int c = connect(sockfd, (struct sockaddr*) &serveraddr, sizeof(serveraddr));
    if (c < 0) {
        printf("There was a problem connecting to the server\n");
        close(sockfd);
        return 1;
    }

    /* P2 recv server public key  */
    rec = recv(sockfd, buffer_in, BUFFER_SIZE, 0);
    if (rec < 0) {
        printf("receive error\n");
        return false;
    }
    else if (0 == rec) {
        /* server closed connection */
        return false;
        // do something?
    }

    /* P2 should we send an ack for public received? */

    /* P2 convert back to EVP_PKEY format */
    const unsigned char* p = (const unsigned char*) buffer_in;
    pubkey = d2i_PUBKEY(NULL, &p, rec);
    if (NULL == pubkey) {
        printf("public key conversion fail\n");
        return false;
    }
    printf("public key received.\n");

    /* P2 encrypt our symmetric key with server public key */
    int encryptedkey_len = rsa_encrypt(key, KEY_SIZE, pubkey, (unsigned char*) buffer_out);
    printf("my key encrypted length %d\n", encryptedkey_len);

    /* P2 send server our key */
    sent = send(sockfd, buffer_out, encryptedkey_len, 0);
    if (sent < 0) {
        perror("send key");
        return false;
    }

    /* P2 do we need and ack for key received? */

    /* P2 encrypt username */
    sent = send_encrypted_message(sockfd, key, username);
    if (sent < 0) {
        perror("send encrypted name");
        return false;
    }

    return true;
}


bool process_commandline_args(
        int argc, char* argv[],
        char* address_out,
        uint16_t* port_out,
        char* name_out) {
    if (NULL == address_out || NULL == port_out || NULL == name_out) {
        return false;
    }

    if (argc != 4) {
        printf("usage:\n");
        printf("./client IPADDRESS PORT USERNAME\n");
        return false;
    }

    strcpy(address_out, argv[1]);
    *port_out = atoi(argv[2]);
    strcpy(name_out, argv[3]);

    printf("ip address: %s\n", address_out);
    printf("port number %hu\n", *port_out);
    printf("username %s\n", name_out);

    return true;
}

/* on exit do some cleanup */
void clean_up(void) {
    printf("cleaning up...\n");
    if (-1 != sockfd) {
        printf("closing open socket descriptor...\n");
        close(sockfd);
    }
    crypt_cleanup();
}

/* Main Loop */
int main(int argc, char** argv) {
    struct timeval tv = {0, 0}; /* dont block */
    fd_set fds;
    char buffer_in[BUFFER_SIZE];
    char buffer_out[BUFFER_SIZE];

    char username[NAME_SIZE];
    char ipaddr[20];
    uint16_t portNum;

    /* init */
    atexit(&clean_up);
    crypto_init();

    if (!process_commandline_args(argc, argv, ipaddr, &portNum, username)) {
        return EXIT_FAILURE;
    }

    if (!handshake(portNum, ipaddr, username)) {
        return EXIT_FAILURE;
    }


    fprintf(stdout, "> ");
    fflush(stdout);
    while (1) {
        /* only two fds. just set everytime */
        FD_ZERO(&fds); /* because fd_set hates me */
        FD_SET(sockfd, &fds); /* receive socket */
        FD_SET(fileno(stdin), &fds); /* stdin */
        int s = select(FD_SETSIZE, &fds, NULL, NULL, &tv);
        if (s < 0) {
            printf("select error\n");
            return EXIT_FAILURE;
        }


        /* check for user input */
        if (FD_ISSET(fileno(stdin), &fds)) {
            /* get text input */
            fgets(buffer_out, sizeof(buffer_out), stdin);
            size_t len = strlen(buffer_out);
            if (len > 0) { buffer_out[len - 1] = '\0'; } /* remove \n */
            len = strlen(buffer_out);
            /* skip empty strings */
            if (len > 0) {
                /* !exit. duh. */
                if (strcmp(buffer_out, "!exit") == 0) {
                    return EXIT_SUCCESS;
                }

                /* admin request */
                if (strcmp(buffer_out, "!admin") == 0) {
                    // initial code from
                    // https://stackoverflow.com/questions/59922972/how-to-stop-echo-in-terminal-using-c
                    printf("Enter password: ");

                    struct termios term;
                    tcgetattr(fileno(stdin), &term);

                    term.c_lflag &= ~ECHO;
                    tcsetattr(fileno(stdin), 0, &term);

                    char passwd[32];
                    fgets(passwd, sizeof(passwd), stdin);
                    len = strlen(passwd);
                    if (len > 0) { passwd[len - 1] = '\0'; } /* remove \n */

                    term.c_lflag |= ECHO;
                    tcsetattr(fileno(stdin), 0, &term);

                    printf("\nYour password is: %s\n", passwd);

                    sprintf(buffer_out, "%s %s", buffer_out, passwd);
                    len = strlen(buffer_out);

                    // send "!admin password
                }

                /* P2 send encrypted text */
                ssize_t sent = send_encrypted_message(sockfd, key, buffer_out);
                if (sent < 0) {
                    printf("send error\n");
                    return EXIT_FAILURE;
                }
            }

            fprintf(stdout, "> ");
            fflush(stdout);
        }

        /* check for data from server */
        if (FD_ISSET(sockfd, &fds)) {
            ssize_t rec = recv_encrypted_message(sockfd, key, buffer_in);
            if (rec < 0) {
                printf("receive error\n");
                return EXIT_FAILURE;
            }
            else if (0 == rec) {
                /* server closed connection */
                return EXIT_SUCCESS;
            }
            else {
                // Client has a really simple job:
                //      Print whatever the server sends it
                //      Send the server whatever the user inputs
                // That's basically it.
                /* P2 decrypt text with our key */
                /* P2 print decrypted text */
                printf("%s\n", buffer_in);
            }
        }
    }

}
