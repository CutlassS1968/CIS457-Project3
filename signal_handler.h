//
// Created by bryan on 9/21/2022.
//

#ifndef CIS457_L5_SIGNAL_H
#define CIS457_L5_SIGNAL_H


#include <stdbool.h>

/* handle ctrl-c for clean shut down */
extern bool exit_program;

#include <signal.h>

int install_signal_handler(void);


#endif //CIS457_L5_SIGNAL_H
