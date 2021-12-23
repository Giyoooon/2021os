#include <hash.h>
#include <list.h>
#include <stdio.h>
#include "lib/kernel/hash.h"
#include "lib/kernel/list.h"

#include "vm/frame.h"
#include "vm/swap.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"

static struct hash frame_hash_map;
static struct lock frame_lock;

static struct list frame_list;
static struct list_elem *victim;

static unsigned frame_hash_function(const struct hash_elem *helem, void* aux );
static bool frame_less_function(const struct hash_elem *, const struct hash_elem *, void *aux);

/*second chance*/
static struct vm_frame_table_entry* second_chance(uint32_t* pagedir);
//struct vm_frame_table_entry* next_frame(void);

static unsigned frame_hash_function(const struct hash_elem *helem, void *aux UNUSED){
	struct vm_frame_table_entry *f_entry = hash_entry(helem, struct vm_frame_table_entry, h_elem);
	return hash_bytes(&f_entry->kernel_page, sizeof f_entry->kernel_page);
} 

static bool frame_less_function(const struct hash_elem * left, const struct hash_elem *right , void *aux UNUSED){
	struct vm_frame_table_entry *left_entry, *right_entry;
	left_entry = hash_entry(left, struct vm_frame_table_entry, h_elem);
	right_entry = hash_entry(right, struct vm_frame_table_entry, h_elem);
	
	return left_entry->kernel_page < left_entry->kernel_page;
}

void 
vm_frame_init(){
	victim = NULL;
	hash_init(&frame_hash_map, frame_hash_function, frame_less_function, NULL);
	list_init(&frame_list);
	lock_init(&frame_lock);
}

void* 
vm_frame_alloc(enum palloc_flags pa_flag, void* user_page){
	lock_acquire(&frame_lock);
	//bool result = true;
	void *get_frame_page = palloc_get_page(PAL_USER | pa_flag);
	if(get_frame_page == NULL){//page alloc fail
		struct vm_frame_table_entry *evicted = second_chance(thread_current()->pagedir);
		
		ASSERT(evicted != NULL && evicted->t != NULL);
		ASSERT(evicted->t->pagedir != (void*)0xCCCCCCCC);
		
		bool is_dirty = false, kernel_user_page_dirty;
		kernel_user_page_dirty = pagedir_is_dirty(evicted->t->pagedir, evicted->user_page) || pagedir_is_dirty(evicted->t->pagedir, evicted->kernel_page);
		is_dirty = is_dirty || kernel_user_page_dirty;

		swap_idx swap_index = vm_swap_out(evicted->kernel_page);
		vm_set_swap(evicted->t->vm, evicted->user_page, swap_index);
		vm_set_is_dirty(evicted->t->vm, evicted->user_page, is_dirty);
		vm_frame_just_free(evicted->kernel_page, true);

	}
	struct vm_frame_table_entry *frame = malloc(sizeof(struct vm_frame_table_entry));
	if(frame == NULL){
		get_frame_page = NULL;
	}
	else{ // frame != NULL
		frame->kernel_page = get_frame_page;
		frame->user_page = user_page;
		frame->t = thread_current();
		frame->is_pinned = true;
		hash_insert(&frame_hash_map, &frame->h_elem);
		list_push_back(&frame_list, &frame->l_elem);
	}
	lock_release(&frame_lock);
	return get_frame_page;
}

struct vm_frame_table_entry* second_chance(uint32_t *pagedir){
	size_t frame_table_len = hash_size(&frame_hash_map);
	//struct vm_frame_table_entry *result = NULL;
	if(frame_table_len == 0){
		PANIC("Error! frame table is empty");	
	}

	size_t iter = 0;
	while(iter <= frame_table_len + frame_table_len){
		struct vm_frame_table_entry *e;
		if(list_empty(&frame_list)){
			PANIC("Error! frame table is empty");
		}
		if(victim == NULL || victim == list_end(&frame_list)){
			victim = list_begin(&frame_list);
		}
		else{
			victim = list_next(victim);
		}
		e = list_entry(victim, struct vm_frame_table_entry, l_elem);

		if(e->is_pinned){ 
			++iter;
			continue;
		}
		else if(pagedir_is_accessed(pagedir, e->user_page)){
			pagedir_set_accessed(pagedir, e->user_page, false);
			++iter;
			continue;
		}
		return e;
	}
		PANIC("Error! cannot evict frame");
}
void 
vm_frame_just_free(void *kernel_page, bool is_free_page){
	ASSERT(lock_held_by_current_thread(&frame_lock) == true);
	ASSERT(is_kernel_vaddr(kernel_page));
	ASSERT(pg_ofs(kernel_page) == 0);

	struct vm_frame_table_entry tmp_frame, *f;
	struct hash_elem *h;

	tmp_frame.kernel_page = kernel_page;
	h = hash_find(&frame_hash_map, &(tmp_frame.h_elem));
	if(h == NULL){
		PANIC("Error! freed page is not stored in table");
	}
	f = hash_entry(h, struct vm_frame_table_entry, h_elem);

	hash_delete(&frame_hash_map, &f->h_elem);
	list_remove(&f->l_elem);
	if(is_free_page){
		palloc_free_page(kernel_page);
	}
	free(f);
}
void vm_frame_free(void* kernel_page){
	lock_acquire(&frame_lock);
	vm_frame_just_free(kernel_page, true);
	lock_release(&frame_lock);
}

void vm_frame_entry_remove(void* kernel_page){
	lock_acquire(&frame_lock);
	vm_frame_just_free(kernel_page, false);
	lock_release(&frame_lock);
}

void 
vm_frame_pinned(void* kernel_page){
	lock_acquire(&frame_lock);
	struct vm_frame_table_entry tmp_frame, *f;
	struct hash_elem *h;
	tmp_frame.kernel_page = kernel_page;
	h = hash_find(&frame_hash_map, &(tmp_frame.h_elem));
	if(h == NULL){
		PANIC("Error! frame not exist");
	}
	f = hash_entry(h, struct vm_frame_table_entry, h_elem);
	f->is_pinned = true;
	lock_release(&frame_lock);
}
void 
vm_frame_unpinned(void* kernel_page){
	lock_acquire(&frame_lock);
	struct vm_frame_table_entry tmp_frame, *f;
	struct hash_elem *h;
	tmp_frame.kernel_page = kernel_page;
	h = hash_find(&frame_hash_map, &(tmp_frame.h_elem));
	if(h == NULL){
		PANIC("Error! frame not exist");
	}
	f = hash_entry(h, struct vm_frame_table_entry, h_elem);
	f->is_pinned = false;
	lock_release(&frame_lock);
}

