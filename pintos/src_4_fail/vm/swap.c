#include "vm/swap.h"
#include <bitmap.h>
#include "threads/vaddr.h"
#include "devices/block.h"

static struct bitmap *swap_available;
static struct block* swap_block;

static size_t swap_size_t;
static const size_t SECTORS_PER_PAGE = PGSIZE / BLOCK_SECTOR_SIZE ;

void vm_swap_init(void){
	ASSERT(SECTORS_PER_PAGE > 0);
	
	swap_block = block_get_role(BLOCK_SWAP);
	if(swap_block == NULL){
		PANIC("Error! can't initialize swap block");
		NOT_REACHED();
	}
	
	swap_size_t = block_size(swap_block)/SECTORS_PER_PAGE;
	swap_available = bitmap_create(swap_size_t);
	bitmap_set_all(swap_available, true);
}


swap_idx vm_swap_out(void *page){
	ASSERT(page >= PHYS_BASE);

	size_t swap_index = bitmap_scan(swap_available, 0, 1, true);
	
	size_t i = 0;
	while(i < SECTORS_PER_PAGE){
		block_write(swap_block, swap_index * SECTORS_PER_PAGE + i, page + (BLOCK_SECTOR_SIZE*i));
		i++;
	}
	bitmap_set(swap_available, swap_index, false);
	return swap_index;
}

/* swap in : read the content through the index from the mapped block
and store into page. */
void vm_swap_in(swap_idx swap_index, void *page){
	ASSERT(page >= PHYS_BASE);
	ASSERT(swap_index < swap_size_t);
	if(bitmap_test(swap_available, swap_index) == true){
		PANIC("Error! invalid access to read unassigned swap block");
	}
	bitmap_set(swap_available, swap_index, true);
};

/* Free the swap region. */
void vm_swap_free(swap_idx swap_index){
	ASSERT(swap_index < swap_size_t);
	if(bitmap_test(swap_available, swap_index) == true){
		PANIC("Errror! invalid access to read unassigned swap block");
	}
	bitmap_set(swap_available, swap_index, true);
}
