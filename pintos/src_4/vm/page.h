#ifndef VM_PAGE_H
#define VM_PAGE_H
#include <hash.h>
#include "vm/swap.h"
#include "filesys/off_t.h"

enum page_status {
    ALL_ZERO,   /* zero로 차있을 때. */
    ON_FRAME,   /* frame에 존재. */
    ON_SWAP,     /* swap space에 존재. */
    FROM_FILESYS /* filesystem 에 존재 */
};

struct vm_page_table {
    struct hash page_map;
};

struct vm_page_table_entry {
    void *upage;     /* user Virtual page. */
    void *kpage;     /* Kernel page */
    enum page_status status;
    bool dirty;
    uint32_t read_bytes, zero_bytes;
    bool writable;

    swap_idx_t swap_index; // status == ON_SWAP

    // status == FROM_FILESYS    
    struct file *file;
    off_t file_offset;

    struct hash_elem elem;
};

/* page table function */
struct vm_page_table *vm_create_init(void);
void vm_page_destroy(struct vm_page_table *vm);

bool vm_install_frame(struct vm_page_table *vm, void *upage, void *kpage);
bool is_stack_growth(struct vm_page_table *vm, void *);
bool vm_install_filesys(struct vm_page_table *vm, void *page,
    struct file *file, off_t offset, uint32_t read_bytes, uint32_t zero_bytes,bool writable);

bool vm_set_swap(struct vm_page_table *vm, void *, swap_idx_t);
struct vm_page_table_entry *vm_page_lookup (struct vm_page_table *vm, void *);
bool vme_has_entry(struct vm_page_table *vm, void *page);
bool vm_set_isdirty(struct vm_page_table *vm, void *, bool);

bool handle_mm_fault(struct vm_page_table *vm, uint32_t *pagedir, void *upage);
bool vm_mm_unmap(struct vm_page_table *vm, uint32_t *pagedir, 
    void *page, struct file *file, off_t offset, size_t bytes); 

void vm_preload_pin_pages(const void *, size_t);
void vm_unpin_preloaded_pages(const void *, size_t);
void vm_page_pin(struct vm_page_table *vm, void *page);
void vm_page_unpin(struct vm_page_table *vm, void *page);
#endif


