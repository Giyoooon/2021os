#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "userprog/process.h"

void syscall_init (void);

void custom_halt(void);
void custom_exit(int status);
pid_t custom_exec(const char *cmd_line);
int custom_wait(pid_t pid);

bool custom_create(const char *file_name, unsigned initial_size);
bool custom_remove(const char *file_name);

int custom_open(const char *file);
int custom_filesize(int fd);
int custom_read(int fd,void *buffer, unsigned size);
int custom_write(int fd, const void *buffer,unsigned size);
void custom_seek(int fd, unsigned position);
unsigned custom_tell(int fd);
void custom_close(int fd);

#ifdef VM
bool custom_munmap(mmapid_t);
#endif


#endif /* userprog/syscall.h */