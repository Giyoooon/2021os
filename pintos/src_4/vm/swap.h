#ifndef VM_SWAP_H
#define VM_SWAP_H
typedef uint32_t swap_idx_t;

/*swap table init */
void vm_swap_init(void);

swap_idx_t vm_swap_out(void *page);
void vm_swap_in(swap_idx_t swap_index, void *page);
void vm_swap_free(swap_idx_t swap_index);
#endif

