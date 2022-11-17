#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

// Client should be relatively simple as we are offloading most if not all of the effort
// to the server.

// I am 100% confident that most of this is a bad idea, but alas, this is what I have come up with.

#define BUFFER_SIZE 1024

/* Structs */

/* Helper Methods */

/* Main Loop */
int main(int argc, char** argv) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    // TODO: Should probably just use command args
    char username[128];
    printf("Enter username: ");
    scanf("%s%*c", username);

    char ipaddr[20];
    printf("Enter server IP address: ");
    scanf("%s%*c", ipaddr);

    uint16_t portNum;
    printf("Enter port number: ");
    scanf("%hd%*c", &portNum);

    struct sockaddr_in serveraddr;
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(portNum);
    serveraddr.sinn_addr.s_addr = inet_addr(ipaddr);

    int n = connect(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr));
    if(n < 0) {
        printf("There was a problem connecting to the server\n");
        close(sockfd);
        return 1;
    }

    // Send first packet to server for user info
    char buffer[BUFFER_SIZE];
    memcpy(buffer, username, sizeof(username));
    send(sockfd, buffer, BUFFER_SIZE, 0);


    while (1) {

        // Client has a really simple job:
        //      Print whatever the server sends it
        //      Send the server whatever the user inputs
        // That's basically it.

        // Get text input
        // TODO: need to allow for interrupt if incoming message, need to research this
        scanf("%s%*c", buffer);
        send(sockfd, buffer, BUFFER_SIZE, 0);
        memset(buffer, 0, BUFFER_SIZE);

        recv(sockfd, &buffer, BUFFER_SIZE, 0);
        printf("%s\n", buffer);

    }
}
