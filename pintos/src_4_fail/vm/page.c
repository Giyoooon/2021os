#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <threads/malloc.h>
#include <threads/palloc.h>
#include "lib/kernel/list.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "filesys/file.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "vm/page.h"
#include "vm/frame.h"

static void vm_destroy_func(struct hash_elem *e, void *aux UNUSED);
static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
static unsigned vm_hash_func(const struct hash_elem *e, void *aux UNUSED);


static unsigned
vm_hash_func (const struct hash_elem *elem, void *aux UNUSED)
{
  ASSERT (elem != NULL);
	struct vm_page_table_entry *vme = hash_entry(elem, struct vm_page_table_entry, elem);
  return hash_int ((int)vme->user_page);
}

static bool
vm_less_func (const struct hash_elem *a,const struct hash_elem *b, void *aux UNUSED)
{
  ASSERT (a != NULL);
  ASSERT (b != NULL);
  return hash_entry (a, struct vm_page_table_entry, elem)->user_page < hash_entry (b, struct vm_page_table_entry, elem)->user_page;
}

static void
vm_destroy_func (struct hash_elem *e, void *aux UNUSED)
{
  ASSERT (e != NULL);
  struct vm_page_table_entry *vme = hash_entry (e, struct vm_page_table_entry, elem);
  if(vme->kernel_page != NULL){
		ASSERT(vme->status == ON_FRAME);
		vm_frame_entry_remove(vme->kernel_page);
	}
	else if(vme->status == ON_SWAP){
		vm_swap_free(vme->swap_slot);
	}
	//free_page_vaddr (vme->vaddr);
  //swap_clear (vme->swap_slot);
  free (vme);
}

struct vm_page_table *vm_page_init_create(){
	struct vm_page_table *vm;
	vm = (struct vm_page_table *)malloc(sizeof(struct vm_page_table));

	hash_init(&vm->page_hash_map, vm_hash_func, vm_less_func, NULL);
	return vm;
}

void 
vm_page_destroy(struct vm_page_table* vm){
	ASSERT(vm != NULL);
	hash_destroy(&vm->page_hash_map, vm_destroy_func);
}

bool vm_install_frame(struct vm_page_table* vm, void *user_page, void* kernel_page){
	struct vm_page_table_entry *vme;
	struct hash_elem *prev;
	bool success = true;
	vme = (struct vm_page_table_entry *)malloc(sizeof(struct vm_page_table_entry));
	
	vme->status = ON_FRAME;
	vme->kernel_page = kernel_page;
	vme->user_page = user_page;
	vme->is_dirty = false;
	vme->swap_slot = -1;
	
	prev = hash_insert(&vm->page_hash_map, &vme->elem);
	if(prev != NULL){
		free(vme);
		success = false;
	}
	return success;
}

bool vm_install_filesys(struct vm_page_table* vm, void* user_page, struct file *file, off_t offset, size_t read_bytes, size_t zero_bytes, bool writable){
	struct vm_page_table_entry *vme;
	struct hash_elem *prev;
	bool install_success = true;
	vme = (struct vm_page_table_entry *)malloc(sizeof(struct vm_page_table_entry));
	vme->status = FROM_FILESYS;
	vme->kernel_page = NULL;
	vme->user_page = user_page;
	vme->is_dirty = false;
	vme->file = file;
	vme->file_offset = offset;
	vme->read_bytes = read_bytes;
	vme->zero_bytes = zero_bytes;
	vme->writable = writable;

	prev = hash_insert(&vm->page_hash_map, &vme->elem);
	if(prev != NULL){
		PANIC("Error! there's already entry");
		install_success = false;
	}
	return install_success;
}

bool stack_growth(struct vm_page_table* vm, void *user_page){
	struct vm_page_table_entry *vme;
	struct hash_elem *prev;
	bool is_stack_growth = true;
	vme = (struct vm_page_table_entry *)malloc(sizeof(struct vm_page_table_entry));
	
	vme->status = ALL_ZERO;
	vme->kernel_page = NULL;
	vme->user_page = user_page;
	vme->is_dirty = false;

	prev = hash_insert(&vm->page_hash_map, &vme->elem);
	if(prev != NULL){
		PANIC("Error! duplicated vm page table entry for zero page");
		is_stack_growth = false;
	}
	return is_stack_growth;
}

struct vm_page_table_entry* vm_page_look_up(struct vm_page_table *vm, void* page){
	struct vm_page_table_entry tmp_vme;
	struct hash_elem *elem;
	
	tmp_vme.user_page = page;
	elem = hash_find(&vm->page_hash_map, &tmp_vme.elem);
	if(elem == NULL){
		return NULL;
	}
	else{
		return hash_entry(elem, struct vm_page_table_entry, elem);
	}
}

bool vm_set_swap(struct vm_page_table *vm, void* page, swap_idx swap_index){
	struct vm_page_table_entry *vme;
	bool set_success = false;
	vme = vm_page_look_up(vm, page);
	if(vme != NULL){
		vme->status = ON_SWAP;
		vme->kernel_page = NULL;
		vme->swap_slot = swap_index;
		set_success = true;
	}
	return set_success;
}

bool vme_has_entry(struct vm_page_table *vm, void* page){
	struct vm_page_table_entry* vme = vm_page_look_up(vm, page);
	bool entry_empty = true;
	if(vme != NULL){
		entry_empty = false;
	}
	return entry_empty;
}

bool vm_set_is_dirty(struct vm_page_table *vm, void* page, bool val){
	struct vm_page_table_entry *vme;
	vme = vm_page_look_up(vm, page);
	if(vme == NULL){
		PANIC("Error! entry not exist");
	}
	else{
		vme->is_dirty = vme->is_dirty || val;
		return true;
	}
}

bool handle_mm_fault(struct vm_page_table *vm, uint32_t *pagedir, void *user_page){
	struct vm_page_table_entry *vme;
	void *frame_page;
	enum palloc_flags page_status;
	vme = vm_page_look_up(vm, user_page);
	
	if(vme == NULL) return false;
	if(vme->status == ON_FRAME) return true;
	
	page_status = PAL_USER;
	frame_page = vm_frame_alloc(page_status, user_page);

	bool writable = true;
	switch(vme->status){

		case ALL_ZERO:
			memset(frame_page, 0, PGSIZE);
			break;
		case ON_FRAME:
			break;
		case ON_SWAP:
			vm_swap_in(vme->swap_slot, frame_page);
			break;
		case FROM_FILESYS:
			file_seek(vme->file, vme->file_offset);
			int read = file_read(vme->file, frame_page, vme->read_bytes);
			if(read != (int)vme->read_bytes){
					//false
				vm_frame_free(frame_page);
				return false;
			}
			ASSERT(vme->read_bytes + vme->zero_bytes == PGSIZE);
			memset(frame_page + read, 0, vme->zero_bytes);

			writable = vme->writable;
			break;
		default:
			PANIC("Error! exception");
	}

	if(!pagedir_set_page(pagedir, user_page, frame_page, writable)){
		vm_frame_free(frame_page);
		return false;
	}
	vme->status = ON_FRAME;
	vme->kernel_page = frame_page;
	
	pagedir_set_dirty(pagedir, frame_page, false);

	vm_frame_unpinned(frame_page);
	return true;
}

bool vm_mm_unmap(struct vm_page_table *vm, uint32_t* pagedir, void *page, struct file* file, off_t offset, size_t bytes){
	struct vm_page_table_entry *vme = vm_page_look_up(vm, page);

	if(vme == NULL){
		PANIC("Error! some pages missing");
	}
	if(vme->status == ON_FRAME){
		ASSERT(vme->kernel_page != NULL);
		vm_frame_pinned(vme->kernel_page);
	}
	bool is_dirty = vme->is_dirty; bool kernel_user_page_is_dirty;
	switch(vme->status){
		case ON_FRAME:
			ASSERT(vme->kernel_page != NULL);
			kernel_user_page_is_dirty = pagedir_is_dirty(pagedir, vme->kernel_page) || pagedir_is_dirty(pagedir, vme->user_page);

			is_dirty = is_dirty || kernel_user_page_is_dirty;

			if(is_dirty){
				file_write_at(file, vme->user_page, bytes, offset);
			}
			vm_frame_free(vme->kernel_page);
			pagedir_clear_page(pagedir, vme->user_page);
			break;
		case ON_SWAP:
			is_dirty = is_dirty || pagedir_is_dirty(pagedir, vme->user_page);
			if(is_dirty){
				void* temp_page;
				temp_page = palloc_get_page(0);
				vm_swap_in(vme->swap_slot, temp_page);
				file_write_at(file, temp_page, PGSIZE, offset);
				palloc_free_page(temp_page);
			}
			else{
				vm_swap_free(vme->swap_slot);
			}
			break;
		case FROM_FILESYS:
			break;
		default :
			PANIC("Error! no way");
	}
	hash_delete(&vm->page_hash_map, &vme->elem);
	return true;
}

void vm_page_pin(struct vm_page_table *vm, void* page){
	struct vm_page_table_entry *vme;
	vme = vm_page_look_up(vm, page);

	if(vme == NULL) return;

	ASSERT(vme->status == ON_FRAME);
	vm_frame_pinned(vme->kernel_page);
}
void vm_page_unpin(struct vm_page_table *vm, void* page){
	struct vm_page_table_entry *vme = vm_page_look_up(vm, page);
	if(vme == NULL) {
		PANIC("Error! request page not exist");
	}
	if(vme->status == ON_FRAME){
		vm_frame_unpinned(vme->kernel_page);
	}
}

void preload_pin_page(const void* buffer,size_t size){
	struct vm_page_table *vm = thread_current()->vm;
	uint32_t *pagedir = thread_current()->pagedir;
	void *user_page;
	
	for(user_page = pg_round_down(buffer); user_page < buffer + size; user_page += PGSIZE){
		handle_mm_fault(vm, pagedir, user_page);
		vm_page_pin(vm, user_page);
	}
}

void unpin_preloaded_page(const void *buffer, size_t size){
	struct vm_page_table *vm = thread_current()->vm;
	void *user_page;
	
	for(user_page = pg_round_down(buffer); user_page < buffer+size; user_page += PGSIZE){
		vm_page_unpin(vm, user_page);
	}
}
