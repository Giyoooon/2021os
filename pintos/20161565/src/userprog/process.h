#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
void filename_parser(char* src, char* dest);
void stack_esp(char* file_name, void **esp);
#endif /* userprog/process.h */
