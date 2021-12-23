#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <hash.h>
#include "lib/kernel/hash.h"
#include "threads/synch.h"
#include "threads/palloc.h"

/* Frame Table Entry */
struct frame_table_entry
{
    void *kpage;  
    void *upage;               
    struct thread *t;          

    bool pinned;            
    struct hash_elem helem;    /* frame_map */
    struct list_elem lelem;    /* frame_list */
};

/* Initialize */
void vm_frame_init(void);
void* vm_frame_alloc(enum palloc_flags flag, void *upage);

/* Free the page frame */ 
void vm_frame_free(void* kpage);
void vm_frame_entry_remove(void *kpage);
void vm_frame_just_free (void *kpage, bool free_page);

/*For pinning*/
void vm_frame_pinned(void*kpage);
void vm_frame_unpinned(void *kpage);



#endif
