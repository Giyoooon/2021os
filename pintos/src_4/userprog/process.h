#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H
#include <stdio.h>
#include "threads/thread.h"
#include "threads/synch.h"

/* Process identifier type.
   You can redefine this to whatever type you like. */
typedef int pid_t;
#define PID_ERROR ((pid_t) -1)          /* Error value for tid_t. */
#define PID_INIT ((pid_t) -2)

struct process_control_block {
    pid_t pid;

    const char *cmdline;

    struct list_elem elem;
    struct thread *parent_thread;

    bool waiting;   //parent process is waiting.
    bool exited;    //process is done.
    bool orphan;    //parent process has terminated before.
    int32_t exitcode;   //passed from exit(), when exited = true

    //for sync
    struct semaphore sema_init;
    struct semaphore sema_wait; 
};

//fd
struct file_desc {
    int id;
    struct list_elem elem;
    struct file* file;
};

#ifdef VM
typedef int mmapid_t;

struct mmap_descriptor {
  mmapid_t id;
  struct list_elem elem;
  struct file* file;

  void *addr;   // store user virtual address
  size_t size;  // file size
};
#endif

pid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
/*-----Project 1-----*/
void parse_cmd(char *file_name, char **argv, int *argc);
void construct_stack (const char *[], int cnt, void **esp);

struct process_control_block *process_find_child(pid_t pid);
#endif /* userprog/process.h */
