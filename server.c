#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <stdbool.h>
#include <stdlib.h>
#include "signal_handler.h"
#include "cryptotest.h"

#define NAME_SIZE 128
#define BUFFER_SIZE 1024

/* Structs */

// May need to keep client's port num incase multiple people on same network?
// Not sure, socket might take care of that for us.
fd_set sockets_to_watch;
int listen_fd;
#define MAX_QUE 10

typedef struct client {
    bool active;
    char name[NAME_SIZE];
    bool admin;
    unsigned char key[32];
} client;
client clients[FD_SETSIZE];

/* search user database for name. return their fd */
int find_user(char* username) {
    for (int e = 0; e < FD_SETSIZE; e++) {
        if (clients[e].active) {
            if (strcmp(username, clients[e].name) == 0) {
                return e;
            }
        }
    }
    return -1;
}


EVP_PKEY* pubkey, * privkey;

void crypto_init(void) {
    OpenSSL_add_all_algorithms();


    char* pubfilename = "RSApub.pem";
    char* privfilename = "RSApriv.pem";

    FILE* pubf = fopen(pubfilename, "rb");
    pubkey = PEM_read_PUBKEY(pubf, NULL, NULL, NULL);
    fclose(pubf);

    FILE* privf = fopen(privfilename, "rb");
    privkey = PEM_read_PrivateKey(privf, NULL, NULL, NULL);
    fclose(privf);


    // PEM_write_bio_PUBKEY
    // PEM_read_bio_PUBKEY

    // i2d_PublicKey()
    // d2i_PublicKey()

    // i2d_PUBKEY()
//    keylen = i2d_PUBKEY(key, NULL);
//    p1 = p = (unsigned char *)OPENSSL_malloc(keylen);
//    keylen = i2d_PUBKEY(key, &p);
//    pubkey = d2i_PUBKEY(NULL, (const unsigned char**)&p, keylen);
//    OPENSSL_free(p1);


}

/* perform first connection handshake with client */
bool handshake(int fd) {
    char buffer_out[BUFFER_SIZE];
    char buffer_in[BUFFER_SIZE];

    ssize_t sent;
    ssize_t rec;

    /* convert key to sendable data */
    int len = i2d_PUBKEY(pubkey, NULL); // size of serialization data
    printf("public keylen %d\n", len);
    unsigned char* data = malloc(len);
    unsigned char* p = data; // use copy only. pointer gets modified
    printf("p %p\n", p);
    len = i2d_PUBKEY(pubkey, (unsigned char**) &p);
    printf("p %p\n", p);
    printf("public keylen %d\n", len);

    /* P2 send user our public key */
    sent = send(fd, data, len, 0);
    if (-1 == sent) { printf("error sending public key\n"); }
    printf("sent key %zd\n", sent);

    /* P2 recv users symmetric key */
    //unsigned char encrypted_key[256];
    rec = recv(fd, buffer_in, BUFFER_SIZE, 0);
    if (rec < 0) {
        perror("recv key");
        return false;
    }
    printf("received %zd encrypted data\n", rec);

    /* P2 decrypt with our private key */
    int decryptedkey_len = rsa_decrypt((unsigned char *)buffer_in, rec, privkey, clients[fd].key);
    printf("key size %d\n", decryptedkey_len);

//    /* get username */
//    rec = recv(fd, clients[fd].name, NAME_SIZE, 0);
//    if (rec < 0) {
//        perror("recv username");
//        return false;
//    }

    /* P2 recv users encrypted username */
    // unsigned char iv[16];
    rec = recv(fd, buffer_in, BUFFER_SIZE, 0);
    if (rec < 0) {
        perror("recv encrypted username");
        return false;
    }

    /* P2 decrypt username */
    int decryptedtext_len = decrypt(
            (unsigned char*)&buffer_in[16], (int)(rec-16),
            clients[fd].key, (unsigned char*)&buffer_in[0],
            (unsigned char*)buffer_out);
    printf("decrypted username length %d\n", decryptedtext_len);
    if (decryptedtext_len <= NAME_SIZE) { // zero check
        printf("decrypted username %s\n", buffer_out);
        strcpy(clients[fd].name, buffer_out);
    }

    /* validate user name */
    for (int e = 0; e < FD_SETSIZE; e++) {
        if (e != fd && clients[e].active) {
            /* duplicate name */
            if (strcmp(clients[fd].name, clients[e].name) == 0) {
                printf("%d and %d are duplicates of %s\n", fd, e, clients[fd].name);
                /* use fd to make unique */
                sprintf(&clients[fd].name[rec - 1], "%d", fd);
                printf("new name %s\n", clients[fd].name);

                sprintf(buffer_out, "name already taken. new name %s", clients[fd].name);
                sent = send(fd, buffer_out, strlen(buffer_out) + 1, 0);
                if (-1 == sent) { printf("error sending new name\n"); }
            }
        }
    }
    clients[fd].active = true;
    FD_SET(fd, &sockets_to_watch);
    printf("client %d %s has joined the chat.\n", fd, clients[fd].name);

    return true;
}

/* create a listening / new client socket */
bool create_listen(int port) {
    struct sockaddr_in serveraddr;
    memset(&serveraddr, 0, sizeof(struct sockaddr_in));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port = htons(port);

    /* socket for listening */
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        printf("socket error\n");
        return false;
    }
    FD_SET(listen_fd, &sockets_to_watch);

    int b = bind(listen_fd, (struct sockaddr*) &serveraddr, sizeof(serveraddr));
    // Address already in use ??? setsockopt with? SO_REUSEADDR, SO_REUSEPORT , SO_LINGER,
    if (b < 0) {
        perror("bind");
        return false;
    }

    int l = listen(listen_fd, MAX_QUE);
    if (l < 0) {
        printf("listen error\n");
        return false;
    }

    return true;
}


void crypt_cleanup(void) {
    //EVP_PKEY_free(pubkey);
    //EVP_PKEY_free(privkey);
    // or does EVP_cleanup do this?


    EVP_cleanup();
}


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
    //todo: getting occasional bind error "address already in use"
    // if server initiates close while clients are still connected.
    //  have to wait for system to fully timout until can connect again.
    //  is there a 'more' proper way to this to avoid that bind error?

    /* new connection socket */
    close(listen_fd);

    /* just to be safe */
    FD_ZERO(&sockets_to_watch);

    crypt_cleanup();
}

/* Helper Methods */

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
            /* P2 encrypt with users key */
            /* P2 send encrypted text */
            ssize_t sent = send(e, buffer_out, strlen(buffer_out) + 1, 0);
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
    //
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
    crypto_init();

    /* P2 initialize encryption protocols stuff */
    /* P2 load our public and private key from disk */

    // Connection socket
    // Open connection fd
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

        /* check for new client connection */
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

        /* check active data sockets */
        for (int i = 0; i < FD_SETSIZE; i++) {
            if (FD_ISSET(i, &temp_sockets) && i != listen_fd) {
                char buffer_in[BUFFER_SIZE];
                char buffer_out[BUFFER_SIZE];
                memset(buffer_in, 0, sizeof(buffer_in));
                memset(buffer_out, 0, sizeof(buffer_out));

                /* theoretically receive some data */
                ssize_t rec = recv(i, buffer_in, BUFFER_SIZE, 0);
                if (rec < 0) {
                    perror("recv");
                    break;
                }
                else if (0 == rec) {
                    /* client closed connection */
                    /* deactivate client () */
                    // todo: make helper function?
                    {
                        close(i);
                        clients[i].active = false;
                        FD_CLR(i, &sockets_to_watch);
                        FD_CLR(i, &temp_sockets); // prob not needed
                        printf("client %d %s has left the chat.\n", i, clients[i].name);
                    }
                }
                else {
                    /* received data */
                    /* P2 decrypt message with users key */
                    printf("[%d] %s\n", i, buffer_in);

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
                            int fd = find_user(&command[1]);
                            /* don't send back to yourself */
                            if (fd != -1 && i != fd) {
                                /* tag message with username */
                                sprintf(buffer_out, "%s:%s", clients[i].name, data);
                                ssize_t sent = send(fd, buffer_out, strlen(buffer_out) + 1, 0);
                                if (-1 == sent) { printf("error sending chat user\n"); }
                            }


                        }

                        // If the string doesn't fit a username, set out_str to appropriate err msg.
                        // send error message?

                        /* bad command drop? */
                        continue;
                    }

                    // todo: old echo server, remove
                    /* tag message with username */
                    sprintf(buffer_out, "%s:%s", clients[i].name, buffer_in);

                    /* just echo to everybody for now */
                    for (int e = 0; e < FD_SETSIZE; e++) {
                        if (e != i && clients[e].active) {
                            /* P2 encrypt message with users key */
                            ssize_t sent = send(e, buffer_out, strlen(buffer_out) + 1, 0);
                            if (-1 == sent) { printf("error sending chat all\n"); }
                        }
                    }


                }
            }
        }
    }

    return EXIT_SUCCESS;
}
