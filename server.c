#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <stdbool.h>
#include <stdlib.h>
#include "common.h"
#include "signal_handler.h"
#include "cryptotest.h"

/* maximum number of new clients allowed in new conection queue */
#define MAX_QUE 10

/* evil globals */
fd_set sockets_to_watch;
int listen_fd;
EVP_PKEY* privkey = NULL;   /* our asymmetrical private key */

/* Structs */



/****** clients *******/

typedef struct client {
    bool active;
    char name[NAME_SIZE];
    bool admin;
    unsigned char key[KEY_SIZE];
} client;
client clients[FD_SETSIZE];

/* search user database for name. return their fd */
int find_client(char* username) {
    for (int fd = 0; fd < FD_SETSIZE; fd++) {
        if (clients[fd].active) {
            if (strcmp(username, clients[fd].name) == 0) {
                return fd;
            }
        }
    }
    return -1;
}

void end_client(int fd) {
    close(fd);
    clients[fd].active = false;
    FD_CLR(fd, &sockets_to_watch);
    printf("client %d %s has left the chat.\n", fd, clients[fd].name);
}


/****** encryption *******/

void crypto_init(void) {
    printf("initializing cryptography...\n");
    OpenSSL_add_all_algorithms();
    printf("\tloaded encryption algorithms\n");

    /* load our private ke from disk */
    char* privfilename = "RSApriv.pem";
    FILE* privf = fopen(privfilename, "rb");
    privkey = PEM_read_PrivateKey(privf, NULL, NULL, NULL);
    if (!privkey) { printf("error: PEM_read_PrivateKey\n"); }
    fclose(privf);
    printf("\tloader private key\n");
}

void crypt_cleanup(void) {
    printf("shutting down cryptography...\n");
    if (privkey) { EVP_PKEY_free(privkey); }    //not sure if we need to do this
    EVP_cleanup();
}


/****** network *******/

/* create a listening / new client socket */
// todo: is there a better name for this function?
bool create_listen(int port) {
    struct sockaddr_in serveraddr;
    memset(&serveraddr, 0, sizeof(struct sockaddr_in));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port = htons(port);

    printf("creating socket for client requests...\n");

    /* socket for listening */
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        printf("socket error\n");
        return false;
    }
    FD_SET(listen_fd, &sockets_to_watch);
    printf("\tsocket created\n");

    int b = bind(listen_fd, (struct sockaddr*) &serveraddr, sizeof(serveraddr));
    // Address already in use ??? setsockopt with? SO_REUSEADDR, SO_REUSEPORT , SO_LINGER,
    if (b < 0) {
        perror("bind");
        return false;
    }
    printf("\tbound\n");

    int l = listen(listen_fd, MAX_QUE);
    if (l < 0) {
        printf("listen error\n");
        return false;
    }
    printf("\tlistening\n");

    return true;
}

/* perform first connection handshake with client */
bool handshake(int fd) {
    ssize_t sent;
    ssize_t rec;
    char buffer_out[BUFFER_SIZE];
    char buffer_in[BUFFER_SIZE];

    printf("connecting with new client...\n");

    /* receive users symmetric key (encrypted with our public key) */
    rec = recv(fd, buffer_in, BUFFER_SIZE, 0);
    if (rec < 0) {
        perror("recv key");
        return false;
    }
    printf("\treceived client's session key\n");

    /* decrypt with our private key */
    int decryptedkey_len = rsa_decrypt(
            (unsigned char*) buffer_in, rec,
            privkey,
            clients[fd].key);
    /* this variable can be removed.
     * But for now this kills compiler warnings */
    (void) decryptedkey_len;
    printf("\tdecrypted session key\n");

    /*******************************************************************
    from this point on ALL communications are encrypted with user's key
    ******************************************************************/

    /* ACK session key */
    sent = send_encrypted_message(fd, clients[fd].key, ACK);
    if (-1 == sent) { printf("error sending session key ACK\n"); }
    printf("\tACK session key\n");

    /* receiver users encrypted username */
    rec = recv_encrypted_message(fd, clients[fd].key, buffer_out);
    printf("\treceived username request: [%s]\n", buffer_out);
    if (rec < 0 || rec > NAME_SIZE) {
        return false;
    }
    strcpy(clients[fd].name, buffer_out); //todo: assignment should be after confirmation

    /* validate user name */
    // todo: probably should be moved to it's own function
    // TODO: rewrite/simplify using find_client(char* username) function
    for (int e = 0; e < FD_SETSIZE; e++) {
        if (e != fd && clients[e].active) {
            // todo: validate against command keyword list also.

            /* duplicate name */
            if (strcmp(clients[fd].name, clients[e].name) == 0) {
                printf("\t%d and %d are duplicates of %s\n", fd, e, clients[fd].name);
                /* use fd to make unique */
                sprintf(&clients[fd].name[strlen(clients[e].name)], "%d", fd);
                printf("\tnew name %s\n", clients[fd].name);
            }
        }
    }
    printf("\tvalidated username\n");

    clients[fd].active = true;
    FD_SET(fd, &sockets_to_watch);
    printf("client %d %s has joined the chat.\n", fd, clients[fd].name);

    /* send user their assigned name */
    sprintf(buffer_out, "name:%s", clients[fd].name);
    sent = send_encrypted_message(fd, clients[fd].key, buffer_out);
    if (-1 == sent) { printf("error sending new name\n"); }

    return true;
}


/****** general *******/

/* this allows us to do cleanup whenever the program exits */
void clean_up(void) {
    printf("cleaning up...\n");

    /* close stray data sockets */
    for (int i = 0; i < FD_SETSIZE; i++) {
        if (clients[i].active) {
            printf("closing %d\n", i);
            close(i);
        }
    }
    //todo: getting occasional bind error "address already in use" if
    // server initiates close while clients are still connected.
    // you have to wait for system to fully timout (about 90 seconds)
    // until can connect again.
    // Is there a 'more' proper way to this to avoid that bind error?

    /* new connection socket */
    close(listen_fd);

    /* just to be safe */
    FD_ZERO(&sockets_to_watch);

    crypt_cleanup();
}

/* Commands Helper Methods */

// rename  command
// send new name to client
// name:<username>

// best guess at how to implement prob s/b differrent
char* all_cmd(int fd, char* data) {
    // take data and build string to send to all clients
    // [<sender_username>]: <data>

    char buffer_out[BUFFER_SIZE];
    memset(buffer_out, 0, sizeof(buffer_out));

    /* tag message with username */
    sprintf(buffer_out, "%s:%s", clients[fd].name, data);

    /* find all users that are not sender and send */
    for (int e = 0; e < FD_SETSIZE; e++) {
        if (clients[e].active && e != fd) {
            ssize_t sent = send_encrypted_message(e, clients[e].key, buffer_out);
            if (-1 == sent) { printf("error sending chat all\n"); }
        }
    }

    return NULL;
}

char* username_cmd(char* data) {
    // take data and build string to send to specific client
    // [<sender_username>]: <data>
    return NULL;
}

char* admin_cmd() {
    // TODO: Does !admin mod yourself or someone else?
    /* P1 verify password */
    /* P1 set admin=true; */
    return NULL;
}

char* kick_cmd(char* username) {
    //end_client(fd);
    return NULL;
}

char* help_cmd() {
    // Build string that shows all commands and their functions
    return NULL;
}

void list_cmd() {
    // Build string with all usernames currently connected
}


/* Main Loop */
int main(int argc, char** argv) {
    int port = 9999;

    /* init */
    install_signal_handler(); /* for safe shutdown */
    atexit(&clean_up); /* clean up no matter how we exit */
    crypto_init(); /* initialize encryption */

    /* Connection socket */
    if (!create_listen(port)) { return EXIT_FAILURE; }

    printf("server started...\n");

    /* Main loop */
    while (!exit_program) {
        /* wait for actionable activity on the line */
        fd_set temp_sockets = sockets_to_watch;
        int s = select(FD_SETSIZE, &temp_sockets, NULL, NULL, NULL);
        if (s < 0) {
            perror("select()");
            return EXIT_FAILURE;
        }
        if (exit_program) { continue; }

        /* check for a new client connection */
        if (FD_ISSET(listen_fd, &temp_sockets)) {
            struct sockaddr_in clientaddr;
            socklen_t len = sizeof(struct sockaddr_in);
            memset(&clientaddr, 0, len);
            int fd = accept(listen_fd, (struct sockaddr*) &clientaddr, &len);
            if (-1 == fd) {
                perror("accept");
                return EXIT_FAILURE;
            }
            else if (fd >= FD_SETSIZE) {
                printf("too many clients\n");
                close(fd);
            }
            else {
                /* new user connection */
                if (!handshake(fd)) {
                    return EXIT_FAILURE;
                }
            }
        }

        /* check for data from a client */
        for (int i = 0; i < FD_SETSIZE; i++) {
            if (FD_ISSET(i, &temp_sockets) && i != listen_fd) {
                char buffer_in[BUFFER_SIZE];
                char buffer_out[BUFFER_SIZE];

                /* avoid receiving ghost data */
                memset(buffer_in, 0, sizeof(buffer_in));
                memset(buffer_out, 0, sizeof(buffer_out));

                /* theoretically receive some data */
                ssize_t rec = recv_encrypted_message(i, clients[i].key, buffer_in);
                if (rec < 0) {
                    perror("recv");
                    break;
                }
                else if (0 == rec) {
                    /* client closed connection */
                    end_client(i);
                    continue;
                }

                /* received data */
                printf("[%d-%s] %s\n", i, clients[i].name, buffer_in);

                /* user commands */
                if (buffer_in[0] == '!') {
                    printf("received a user command...\n");

                    // Taking a string builder approach. Each sub cmd
                    // function will build a string and return it here

                    // Commands:
                    // !all			Send output to all clients
                    // !admin		Send output to sender
                    // !help		Send output to sender
                    // !list		Send output to sender
                    // !kick		Send output to receiver
                    // !<username>	Send output to receiver
                    // Input Not Valid

                    // bryan - possible optional command most from spec docs
                    // !uplift - make another user admin
                    // !nerf - remove another user admin privileges
                    // !mute
                    // !unmute
                    // !rename OLDNAME NEWNAME
                    // @rename NEWNAME (self)
                    // !shuffle - randomly mix everyone's name
                    // !me - what is my username?
                    // !reverse USERNAME - make all the user text they send backwards
                    // !uno USERNAME     - make all the user text they receive backwards
                    // !deathclock USERNAME TIMEINSECONDS - send user countdown until they get kicked




                    // Parse the first word out of the data.
                    /* todo: no idea how to do this. using strtok for now */
                    char* command = strtok(buffer_in, " \n");
                    // All incoming data from clients will be interpreted as a command.
                    if (NULL != command) {
                        char* data = &buffer_in[strlen(command) + 1];
                        size_t len = strlen(data);
                        printf("command: %s\n", command);
                        // make sure buffer_in was zeroed out before recv
                        // or you will have ghost msg data and a bad day.
                        printf("msg: %s\n", data);
                        printf("length: %zu\n", len);

                        // Compare the first string to all of the possible commands
                        // 		If match, pass remaining data to appropriate function

                        if (strcmp("!admin", command) == 0) {
                            admin_cmd();
                        }

                        if (strcmp("!help", command) == 0) {
                            help_cmd();
                        }

                        if (strcmp("!all", command) == 0) {
                            all_cmd(i, data);
                        }

                        if (strcmp("!list", command) == 0) {
                            list_cmd();
                        }

                        if (strcmp("!kick", command) == 0) {
                            kick_cmd(data);
                        }

                        // If it doesn't fit in any of the commands. check usernames table

                        /* search usernames */
                        int fd = find_client(&command[1]);
                        /* don't send back to yourself */
                        if (fd != -1 && i != fd) {
                            /* tag message with username */
                            sprintf(buffer_out, "%s:%s", clients[i].name, data);
                            ssize_t sent = send_encrypted_message(fd, clients[fd].key, buffer_out);
                            if (-1 == sent) { printf("error sending chat user\n"); }
                        }
                    }

                    // If the string doesn't fit a username, set out_str to appropriate err msg.
                    /* send error message? */

                    /* bad command drop? */
                    continue;
                }

                // todo: remove. old echo server.
                /* tag message with username */
                sprintf(buffer_out, "%s:%s", clients[i].name, buffer_in);

                /* just echo to everybody for now */
                for (int e = 0; e < FD_SETSIZE; e++) {
                    if (e != i && clients[e].active) {
                        ssize_t sent = send_encrypted_message(e, clients[e].key, buffer_out);
                        if (-1 == sent) { printf("error sending chat all\n"); }
                    }
                }


            }
        }
    }

    return EXIT_SUCCESS;
}
