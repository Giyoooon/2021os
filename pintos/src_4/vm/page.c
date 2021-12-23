#include <hash.h>
#include <string.h>

#include "lib/kernel/hash.h"
#include "page.h"
#include "frame.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

static bool vme_less_func(const struct hash_elem *, const struct hash_elem *, void *aux);
static void vme_destroy_func(struct hash_elem *elem, void *aux);
static unsigned vme_hash_func(const struct hash_elem *elem, void *aux);
static bool vm_load_page(struct vm_page_table_entry *, void *);

static unsigned vme_hash_func(const struct hash_elem *elem, void *aux UNUSED){
    struct vm_page_table_entry *entry = hash_entry(elem, struct vm_page_table_entry, elem);
    return hash_int((int)entry->upage);
}
static bool vme_less_func(const struct hash_elem *l, const struct hash_elem *r, void *aux UNUSED){
    struct vm_page_table_entry *entry_l= hash_entry(l, struct vm_page_table_entry, elem);
    struct vm_page_table_entry *entry_r = hash_entry(r, struct vm_page_table_entry, elem);
    return entry_l -> upage < entry_r -> upage;
}
static void vme_destroy_func(struct hash_elem *elem, void *aux UNUSED){
    struct vm_page_table_entry *entry = hash_entry(elem, struct vm_page_table_entry, elem);
    if(entry->kpage != NULL){
        ASSERT(entry -> status == ON_FRAME);
        vm_frame_entry_remove(entry->kpage);
    }
    else if(entry -> status == ON_SWAP){
        vm_swap_free(entry->swap_index);
    }
    free(entry);
}
static bool vm_load_page(struct vm_page_table_entry *vme, void *kpage){
    bool load_success = false;
    file_seek(vme->file, vme->file_offset);
  
    int read = file_read(vme->file, kpage, vme->read_bytes);
    if(read == (int) vme->read_bytes)
    {    
        ASSERT(vme->read_bytes + vme-> zero_bytes == PGSIZE);
        memset(kpage + read, 0, vme->zero_bytes);
        load_success = true;
    }
    return load_success;
}

void vm_preload_pin_pages(const void *buffer, size_t size)
{
  struct thread* curr = thread_current();
  struct vm_page_table *vm = curr->vm;
  uint32_t *pagedir = curr->pagedir;

  void *upage;
  for(upage = pg_round_down(buffer); upage < buffer + size; upage += PGSIZE)
  {
    handle_mm_fault(vm, pagedir, upage);
    vm_page_pin (vm, upage);
  }
}

void vm_unpin_preloaded_pages(const void *buffer, size_t size)
{
  struct thread* curr = thread_current();
  struct vm_page_table *vm = curr->vm;

  void *upage;
  for(upage = pg_round_down(buffer); upage < buffer + size; upage += PGSIZE)
  {
    vm_page_unpin (vm, upage);
  }
}

struct vm_page_table *vm_create_init(void){
    struct vm_page_table *vm = 
    (struct vm_page_table *) malloc(sizeof(struct vm_page_table));

    hash_init(&vm->page_map, vme_hash_func, vme_less_func, NULL);
    return vm;
}

void vm_page_destroy(struct vm_page_table *vm){
    ASSERT(vm != NULL);
    hash_destroy(&vm->page_map, vme_destroy_func);
    free(vm);
}

bool vm_install_frame(struct vm_page_table *vm, void *upage, void *kpage){
    struct vm_page_table_entry *vme;
    bool success = true;
    vme = (struct vm_page_table_entry *) malloc(sizeof(struct vm_page_table_entry));

    vme -> upage = upage;
    vme -> kpage = kpage;
    vme -> status = ON_FRAME;
    vme -> dirty = false;
    vme -> swap_index = -1;

    struct hash_elem *prev = hash_insert(&vm->page_map, &vme->elem);
    if(prev != NULL){
        /* not Success */
        success = false;
        free(vme);
    }
    return success;
}

bool is_stack_growth (struct vm_page_table *vm, void *upage){
    struct vm_page_table_entry *vme = 
        (struct vm_page_table_entry *)malloc(sizeof(struct vm_page_table_entry));
    bool is_growth = true;
    vme -> upage = upage;
    vme -> kpage = NULL;
    vme -> status = ALL_ZERO;
    vme -> dirty = false;

    struct hash_elem *prev = hash_insert(&vm->page_map, &vme->elem);
    if(prev != NULL) {
        PANIC ("Duplicated Supplementary Page Table Entry for zero page");
        is_growth = false;
    }
    return is_growth;
}
bool vm_install_filesys(struct vm_page_table *vm, void *upage,
    struct file *file, off_t offset, uint32_t read_bytes, uint32_t zero_bytes,bool writable){
        struct vm_page_table_entry *vme;
        vme = (struct vm_page_table_entry *)malloc(sizeof(struct vm_page_table_entry));
        bool is_install = true;
        vme -> file = file;
        vme -> file_offset = offset;
        vme -> read_bytes = read_bytes;
        vme -> zero_bytes = zero_bytes;
        vme -> writable = writable;
        vme -> upage = upage;
        vme -> kpage = NULL;
        vme -> status = FROM_FILESYS;
        vme -> dirty = false;

        struct hash_elem *prev = hash_insert(&vm->page_map, &vme->elem);
        if(prev != NULL) {
            PANIC("There's already entry.");
            is_install = false;
        }
        return is_install;
    }

bool vm_set_swap(struct vm_page_table *vm, void *page, swap_idx_t swap_index){
    struct vm_page_table_entry *vme;
    bool is_swap_set = false;
    vme = vm_page_lookup(vm,page);

    if(vme != NULL){
        vme -> status = ON_SWAP;
        vme -> kpage = NULL;
        vme -> swap_index = swap_index;
        is_swap_set = true;
    }
    return is_swap_set;
}
struct vm_page_table_entry *vm_page_lookup (struct vm_page_table *vm, void *page){
    struct vm_page_table_entry tmp_vme;
    void* vm_page;
    struct vm_page_table_entry* vme_entry = NULL;
    vm_page = page;
    tmp_vme.upage = vm_page;
    struct hash_elem *elem = hash_find(&vm->page_map, &tmp_vme.elem);
    if(elem != NULL)
        vme_entry = hash_entry(elem, struct vm_page_table_entry, elem);
    
    return vme_entry;
}

bool vme_has_entry(struct vm_page_table *vm, void *page){
    struct vm_page_table_entry *vme = vm_page_lookup(vm, page);
    bool has_entry = true;
    if(vme == NULL)
        has_entry = false;
    
    return has_entry;
}
bool vm_set_isdirty(struct vm_page_table *vm, void *page, bool value){
    struct vm_page_table_entry *vme = vm_page_lookup(vm,page);
    if(vme == NULL)
        PANIC("No exist.");
    else {
        bool vme_dirty;
        vme_dirty = vme->dirty;
        vme_dirty = vme_dirty || value;
        vme -> dirty = vme_dirty;
        return true;
    }
}

/*user page를 요청시 호출*/
bool handle_mm_fault(struct vm_page_table *vm, uint32_t *pagedir, void *upage){
    struct vm_page_table_entry *vme;
    vme = vm_page_lookup(vm, upage);
    if(vme == NULL) // 가져온 page table entry가 없음
        return false;
    
    if(vme->status == ON_FRAME)//이미 frame에 있으면 true
        return true;
    
    void *frame_page = vm_frame_alloc(PAL_USER, upage);
    if(frame_page == NULL){
        return false;
    }

    bool writable = true;
    switch(vme->status){
        case ALL_ZERO:
            memset(frame_page, 0 , PGSIZE);
            break;
        case ON_FRAME:
            break;
        case ON_SWAP:
            //swap이 set 되었음 => swap_in
            vm_swap_in(vme->swap_index, frame_page);
            break;
        case FROM_FILESYS:
            if(vm_load_page(vme, frame_page) == false){
                vm_frame_free(frame_page);
                return false;
            }
            writable = vme->writable;
            break;
        default:
            PANIC("Error! Status Exception");
    }
    bool is_pagedir_set  = pagedir_set_page(pagedir, upage, frame_page, writable);
    if(!is_pagedir_set){
        vm_frame_free(frame_page);
        return false;
    }
    vme->kpage = frame_page;
    vme->status = ON_FRAME;

    pagedir_set_dirty(pagedir, frame_page, false);

    vm_frame_unpinned(frame_page);
    return true;
}

bool vm_mm_unmap(struct vm_page_table *vm, uint32_t *pagedir, void *page, 
      struct file *file, off_t offset, size_t bytes){
    struct vm_page_table_entry *vme = vm_page_lookup(vm, page);
    if(vme == NULL)
        PANIC("some pages missing");
    if(vme->status == ON_FRAME){
        ASSERT(vme -> kpage != NULL);
        vm_frame_pinned(vme->kpage);
    }
    bool is_dirty;
    bool kpage_dirty, upage_dirty, vme_dirty;
    switch(vme->status){
        case ON_FRAME:
            ASSERT (vme->kpage != NULL);
            //dirty 가 set 됬으면 file에 씀
            vme_dirty = vme->dirty;
            kpage_dirty = pagedir_is_dirty(pagedir, vme->kpage);
            upage_dirty = pagedir_is_dirty(pagedir, vme->upage);
            is_dirty = vme_dirty || upage_dirty|| kpage_dirty;

            if(is_dirty){
                file_write_at(file, vme->upage, bytes, offset);
            }

            //page mapping free 
            vm_frame_free(vme->kpage);
            pagedir_clear_page(pagedir, vme->upage);
            break;

        case ON_SWAP:
            vme_dirty = vme->dirty;
            upage_dirty = pagedir_is_dirty(pagedir,vme->upage);
            is_dirty = vme_dirty || upage_dirty;
            
            if(is_dirty){
                void *tmp_page = palloc_get_page(0);
                vm_swap_in(vme->swap_index, tmp_page);
                file_write_at(file,tmp_page,PGSIZE,offset);
                palloc_free_page(tmp_page);
            }
            else {
                vm_swap_free(vme->swap_index);
            }
            break;
        case FROM_FILESYS:
            break;

        default : 
            PANIC("EXECPTE STATUS.");
    }

    hash_delete(&vm->page_map, &vme->elem);
    return true;
}    

void vm_page_pin(struct vm_page_table *vm, void *page){
    struct vm_page_table_entry *vme = vm_page_lookup(vm, page);
    if(vme != NULL){
         ASSERT(vme->status == ON_FRAME);
        vm_frame_pinned(vme->kpage);
    }
}
void vm_page_unpin(struct vm_page_table *vm, void *page){
    struct vm_page_table_entry *vme = vm_page_lookup(vm, page);
    if(vme == NULL)
        PANIC("Page not exist");
    if(vme->status == ON_FRAME)
        vm_frame_unpinned(vme->kpage);
}
