//
// Created by bryan on 9/21/2022.
//
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <stdbool.h>

#include "signal_handler.h"

/* CONTROL FLOW */
bool exit_program = false;

void sigint_handler(int signum) {
    (void) signum;
    exit_program = true; // update parent's exit variable
}

int install_signal_handler(void) {
    /* sig variables */
    struct sigaction sig;
    sig.sa_flags = 0;
    sigemptyset(&sig.sa_mask); /* clear masks */

    /* install sig int */
    sig.sa_handler = sigint_handler;
    if (-1 == sigaction(SIGINT, &sig, NULL)) {
        perror("parent sigint sigaction failed");
        return -1;
    }
    return 0;
}