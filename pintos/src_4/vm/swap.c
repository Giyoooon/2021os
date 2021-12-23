#include <bitmap.h>

#include "vm/swap.h"
#include "threads/vaddr.h"
#include "devices/block.h"

static struct block *swap_block;
static struct bitmap *swap_available;

/* size is 4096 / 512*/
static const size_t SECTORS_PER_PAGE = PGSIZE / BLOCK_SECTOR_SIZE; 
static size_t swap_size;

void vm_swap_init(void){
    ASSERT(SECTORS_PER_PAGE > 0);
    swap_block = block_get_role(BLOCK_SWAP);
    if(swap_block == NULL){
        PANIC("initialization fail");
        NOT_REACHED();
    }
    swap_size = block_size(swap_block) / (PGSIZE / BLOCK_SECTOR_SIZE);
    swap_available = bitmap_create(swap_size);
    bitmap_set_all(swap_available, true);
}

/* swap out */
swap_idx_t vm_swap_out(void *page){
    
    ASSERT(page >= PHYS_BASE);
    size_t i;
    size_t swap_index = bitmap_scan(swap_available, 0 , 1, true);

    
    for(i = 0;i < SECTORS_PER_PAGE;i++){
        block_write(swap_block, swap_index * (PGSIZE / BLOCK_SECTOR_SIZE) + i, page+(BLOCK_SECTOR_SIZE * i));
    }
    bitmap_set(swap_available, swap_index, false);
    return swap_index;
}

/* swap in */
void vm_swap_in(swap_idx_t swap_index, void *page){
    ASSERT(page>= PHYS_BASE);
    size_t i;
    ASSERT(swap_index < swap_size);
    if(bitmap_test(swap_available, swap_index) == true){
        PANIC("Invalid access to unassinged swap block");
    }
    for(i = 0;i < SECTORS_PER_PAGE;i++){
        block_read(swap_block,swap_index * SECTORS_PER_PAGE + i, page + (BLOCK_SECTOR_SIZE * i));
    }
    bitmap_set(swap_available, swap_index, true);
}

void vm_swap_free(swap_idx_t swap_index){
    ASSERT(swap_index < swap_size);
    if(swap_index < swap_size && bitmap_test(swap_available, swap_index) == true){
        PANIC("Invalid access to unassinged swap block");
    }
    bitmap_set(swap_available, swap_index, true);
}

