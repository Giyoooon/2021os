#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <hash.h>

#include "threads/synch.h"
#include "threads/palloc.h"
#include "lib/kernel/hash.h"

/*
kernel_page
user_page
 */
/* Frame Table Entry */
struct vm_frame_table_entry
{
    void *kernel_page;               /* Kernel page, mapped to physical address */
    void *user_page;               /* User (Virtual Memory) Address, pointer to page */
    struct thread *t;          /* The associated thread. */
    bool is_pinned;               
		/* Used to prevent a frame from being evicted, while it is acquiring some resources.
                                  If it is true, it is never evicted. */
    struct hash_elem h_elem;    /* frame_map */
    struct list_elem l_elem;    /* frame_list */
};

void vm_frame_init(void);

void* vm_frame_alloc(enum palloc_flags pa_flag, void* user_page);
void vm_frame_free(void* kernel_page);
void vm_frame_just_free(void *kernel_page, bool is_free_page);
void vm_frame_entry_remove(void* kernel_page);

void vm_frame_pinned(void* kernel_page);
void vm_frame_unpinned(void* kernel_page);
#endif
