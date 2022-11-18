#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>

/* Structs */

// May need to keep client's port num incase multiple people on same network?
// Not sure, socket might take care of that for us.
struct client {
    // client's name
    // client's fd_connection
    // admin boolean
    // encription key
};

/* Helper Methods */
char* all_cmd(char* data) {
    // take data and build string to send to all clients
    // [<sender_username>]: <data>
    return NULL;
}

char* username_cmd(char* data) {
    // take data and build string to send to specific client
    // [<sender_username>]: <data>
    return NULL;
}

char* admin_cmd() {
    // TODO: Does !admin mod yourself or someone else?
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
    // Connection socket

    // Open connection fd

    // Main loop
    while (1) {
        // loop data connection

        // recv data

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

        // Parse the first word out of the data.
        // Compare the first string to all of the possible commands
        // 		If match, pass remaining data to appropriate function
        // If it doesn't fit in any of the commands. check usernames table
        // If the string doesn't fit a username, set out_str to appropriate err msg.

        // All incomming data from clients will be interpreted as a command.
        //

    }
}
