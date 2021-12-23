#ifndef VM_SWAP_H
#define VM_SWAP_H
#include <stdio.h>
typedef uint32_t swap_idx;


void vm_swap_init(void);

/* swap out : write the content of page into the swap disk
and return the index of swap region. */
swap_idx vm_swap_out(void *page);

/* swap in : read the content through the index from the mapped block
and store into page. */
void vm_swap_in(swap_idx swap_index, void *page);

/* Free the swap region. */
void vm_swap_free(swap_idx swap_index);
#endif
