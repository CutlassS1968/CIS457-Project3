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

#define prompt() { printf("%s> ", username); fflush(stdout); }


/* remember kids globals are bad. m'kay? */
int sockfd = -1; /* connection to server */
unsigned char key[KEY_SIZE]; /* our symmetrical key */
/* our session key encrypted with sever public key */
int encryptedkey_len;
unsigned char encrypted_key[256];

/****** encryption *******/

void crypto_init(void) {
    printf("initializing cryptography...\n");
    OpenSSL_add_all_algorithms();
    printf("\tloaded encryption algorithms\n");

    /* server public key */
    char* pubfilename = "RSApub.pem";
    FILE* pubf = fopen(pubfilename, "rb");
    EVP_PKEY* pubkey = PEM_read_PUBKEY(pubf, NULL, NULL, NULL);
    if (!pubkey) { printf("error: PEM_read_PUBKEY\n"); }
    fclose(pubf);
    printf("\tloader server public key\n");

    /* session key */
    RAND_bytes(key, KEY_SIZE);
    printf("\tinit session key\n");

    /* encrypt our symmetric key with server public key */
    encryptedkey_len = rsa_encrypt(key, KEY_SIZE, pubkey, encrypted_key);
    printf("\tencrypted session key\n");

    if (pubkey) { EVP_PKEY_free(pubkey); } //not sure if we need to do this
}

void crypt_cleanup(void) {
    printf("shutting down cryptography...\n");
    EVP_cleanup();
}

/****** network *******/

/* perform all the necessary connection protocols with server */
bool handshake(
        uint16_t portNum,
        char* ipaddr,
        char* username) {
    if (NULL == ipaddr || NULL == username) {
        return false;
    }

    ssize_t sent;
    ssize_t rec;
    char buffer_in[BUFFER_SIZE];

    printf("connecting to server %s...\n", ipaddr);

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
    printf("\tsocket open\n");

    /* connect to server */
    int c = connect(sockfd, (struct sockaddr*) &serveraddr, sizeof(serveraddr));
    if (c < 0) {
        printf("There was a problem connecting to the server\n");
        close(sockfd);
        return false;
    }
    printf("\tconnected\n");


    /* send server our key */
    sent = send(sockfd, encrypted_key, encryptedkey_len, 0);
    if (sent < 0) {
        perror("send key");
        return false;
    }
    printf("\tsent session key.\n");

    /*******************************************************************
     from this point on ALL communications are encrypted with our key
     ******************************************************************/

    /* Do we need to ack key received?
     * yes, apparently.
     * OS is occasionally combining the previous and next send into one packet.
     * Which is giving rsa_decrypt kvetches.
     * Not the only solution, but doing an ACK to break up the sends */

    /* receive ACK */
    rec = recv_encrypted_message(sockfd, key, buffer_in);
    if (rec <= 0 || strcmp(buffer_in, ACK) != 0) {
        perror("recv ACK");
        return false;
    }
    printf("\tsession key ACK'd\n");

    /* send requested username */
    sent = send_encrypted_message(sockfd, key, username);
    if (sent < 0) {
        perror("send name");
        return false;
    }
    printf("\nsent name request.\n");

    /* receive our assigned name */
    rec = recv_encrypted_message(sockfd, key, buffer_in);
    if (rec < 0) {
        perror("recv name validation");
        return false;
    }
    if (rec > 5) {
        strcpy(username, &buffer_in[5]);
    }

    return true;
}


/****** general *******/

bool process_commandline_args(
        int argc, char* argv[],
        char* address_out,
        uint16_t* port_out,
        char* name_out) {
    if (NULL == address_out || NULL == port_out || NULL == name_out) {
        return false;
    }
    printf("processing command line...\n");

    if (argc != 4) {
        printf("usage:\n");
        printf("./client IPADDRESS PORT USERNAME\n");
        return false;
    }

    strcpy(address_out, argv[1]);
    *port_out = atoi(argv[2]);
    strcpy(name_out, argv[3]);

    printf("\tip address: %s\n", address_out);
    printf("\tport number %hu\n", *port_out);
    printf("\tusername %s\n", name_out);

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
    fd_set fds; /* for select() */
    char buffer_in[BUFFER_SIZE];
    char buffer_out[BUFFER_SIZE];

    /* command line args */
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

    printf("!help for help\n");
    prompt();
    while (1) {
        /* only two fds. just set everytime */
        FD_ZERO(&fds);                  /* because fd_set hates me */
        FD_SET(sockfd, &fds);           /* server socket */
        FD_SET(fileno(stdin), &fds);    /* stdin */
        /* tv so we don't (lockup) block */
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
                /* exit. duh. */
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

                    sprintf(buffer_out, "%s %s", buffer_out, passwd);

                    // send "!admin password
                    // fallthrough for send
                    printf("\n");
                }

                /* send message blob */
                ssize_t sent = send_encrypted_message(sockfd, key, buffer_out);
                if (sent < 0) {
                    printf("send error\n");
                    return EXIT_FAILURE;
                }
            }
            prompt();
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

            /* print decrypted text */
            printf("%s\n", buffer_in);
            prompt();
        }
    }

}
