#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "../lib/user/syscall.h"
void syscall_init (void);

/*--------------------------------------------------------
-------------------------project1-------------------------
--------------------------------------------------------*/
void custom_halt(void);
void custom_exit(int status);
pid_t custom_exec(const char* command_line);
int custom_wait(pid_t pid);
int custom_write(int fd, const void *buf, unsigned size);
int custom_read(int fd, void *buf, unsigned size);
int custom_fibonacci(int n);
int custom_max_of_four_int(int a, int b, int c, int d);

/*--------------------------------------------------------
-------------------------project1-------------------------
--------------------------------------------------------*/
bool custom_create(const char *file, unsigned initial_size);
bool custom_remove(const char *file);
int custom_open(const char *file);
int custom_filesize(int fd);
void custom_seek(int fd, unsigned position);
unsigned custom_tell(int fd);
void custom_close(int fd);
/*
#ifdef VM
bool custom_munmap(int );
#endif
*/
#endif /* userprog/syscall.h */
