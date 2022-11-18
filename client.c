#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>

#define NAME_SIZE 128
#define BUFFER_SIZE 1024

/* remember kids globals are bad. m'kay? */
int sockfd = -1;
void clean_up(void) {
    printf("closing open descriptors\n");

    if (-1 != sockfd) {
        printf("closing open socket descriptor...\n");
        close(sockfd);
    }
}

/* Structs */

/* Helper Methods */

/* Main Loop */
int main(int argc, char** argv) {
    struct timeval tv = {0, 0}; /* dont block */
    fd_set fds;
    char buffer_in[BUFFER_SIZE];
    char buffer_out[BUFFER_SIZE];

    /* init */
    FD_ZERO(&fds);

    /* clean up */
    atexit(&clean_up);


    /* open socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    // TODO: Should probably just use command args
    char username[NAME_SIZE];
    printf("Enter username: ");
    scanf("%s%*c", username);
    printf("user entered:[%s]\n", username);

    char ipaddr[20];
    printf("Enter server IP address: ");
    scanf("%s%*c", ipaddr);

    uint16_t portNum;
    printf("Enter port number: ");
    scanf("%hd%*c", &portNum);

    struct sockaddr_in serveraddr;
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(portNum);
    serveraddr.sin_addr.s_addr = inet_addr(ipaddr);

    int n = connect(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr));
    if(n < 0) {
        printf("There was a problem connecting to the server\n");
        close(sockfd);
        return 1;
    }

    // Send first packet to server for user info
    memcpy(buffer_out, username, sizeof(username));
    send(sockfd, buffer_out, strlen(buffer_out) + 1, 0);

    fprintf(stdout, "> ");
    fflush(stdout);
    while (1) {
        FD_SET(sockfd, &fds);
        FD_SET(fileno(stdin), &fds);
        int s = select(FD_SETSIZE, &fds, NULL, NULL, &tv);
        if (s < 0) {
            printf("select error\n");
            return EXIT_FAILURE;
        }


        /* check for user input */
        if (FD_ISSET(fileno(stdin), &fds)) {
            /* get text input */
            scanf("%s%*c", buffer_out);
            size_t len = strlen(buffer_out);
            if (len > 0) {
                /* exit. duh. */
                if (strcmp(buffer_out, "exit") == 0) {
                    return EXIT_SUCCESS;
                }

                /* send text */
                ssize_t sent = send(sockfd, buffer_out, len + 1, 0);
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
            ssize_t rec = recv(sockfd, buffer_in, BUFFER_SIZE, 0);
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
                printf("%s\n", buffer_in);
            }
        }





    }

    return EXIT_SUCCESS;
}
