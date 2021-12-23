#include <hash.h>
#include <list.h>
#include <stdio.h>
#include "lib/kernel/hash.h"
#include "lib/kernel/list.h"

#include "vm/frame.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"


static struct lock frame_lock;

static struct hash frame_hash_map;

static struct list frame_list;      /* frame list */
static struct list_elem *victim_ptr; 

static unsigned frame_hash_func(const struct hash_elem *elem, void *aux);
static bool frame_less_func(const struct hash_elem *, const struct hash_elem *, void *aux);
static struct frame_table_entry* second_chance(uint32_t* pagedir);

static unsigned frame_hash_func(const struct hash_elem *elem, void *aux UNUSED)
{
  struct frame_table_entry *entry = hash_entry(elem, struct frame_table_entry, helem);
  return hash_bytes( &entry->kpage, sizeof entry->kpage );
}

static bool frame_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  struct frame_table_entry *a_entry = hash_entry(a, struct frame_table_entry, helem);
  struct frame_table_entry *b_entry = hash_entry(b, struct frame_table_entry, helem);
  void * ae_kpage, *be_kpage;

  ae_kpage = a_entry->kpage;
  be_kpage = b_entry->kpage;
  return ae_kpage < be_kpage;
}

void
vm_frame_init ()
{
  lock_init (&frame_lock);
  hash_init (&frame_hash_map, frame_hash_func, frame_less_func, NULL);
  list_init (&frame_list);
  victim_ptr = NULL;
}

/* Allocate a new frame */
void*
vm_frame_alloc (enum palloc_flags flags, void *upage)
{
  lock_acquire (&frame_lock);
  void *frame_page = palloc_get_page (PAL_USER | flags);
  
  if (frame_page == NULL) {
    struct frame_table_entry *evicted;
    bool is_dirty = false;
    bool dirty,upage_dirty, kpage_dirty;
    evicted = second_chance( thread_current()->pagedir );
    ASSERT (evicted != NULL && evicted->t != NULL);
    ASSERT (evicted->t->pagedir != (void*)0xcccccccc);

    pagedir_clear_page(evicted->t->pagedir, evicted->upage);

    upage_dirty = pagedir_is_dirty(evicted->t->pagedir, evicted->upage);
    kpage_dirty = pagedir_is_dirty(evicted->t->pagedir, evicted->kpage);
    dirty = false;
    is_dirty = dirty || upage_dirty || kpage_dirty;

    swap_idx_t swap_idx = vm_swap_out( evicted->kpage );
    vm_set_swap(evicted->t->vm, evicted->upage, swap_idx);
    vm_set_isdirty(evicted->t->vm, evicted->upage, is_dirty);
    vm_frame_just_free(evicted->kpage, true); 

    frame_page = palloc_get_page (PAL_USER | flags);
    ASSERT (frame_page != NULL); 
  }

  struct frame_table_entry *frame = malloc(sizeof(struct frame_table_entry));
  if(frame == NULL) {
    lock_release (&frame_lock);
    return NULL;
  }

  frame->t = thread_current ();
  frame->upage = upage;
  frame->kpage = frame_page;
  frame->pinned = true;  

  hash_insert (&frame_hash_map, &frame->helem);
  list_push_back (&frame_list, &frame->lelem);

  lock_release (&frame_lock);
  return frame_page;
}


void
vm_frame_free (void *kpage)
{
  lock_acquire (&frame_lock);
  ASSERT (lock_held_by_current_thread(&frame_lock) == true);
  ASSERT (is_kernel_vaddr(kpage));
  ASSERT (pg_ofs (kpage) == 0); // should be aligned

  struct frame_table_entry tmp_frame;
  struct hash_elem *h;
  struct frame_table_entry *f;
  
  tmp_frame.kpage = kpage;

  h = hash_find (&frame_hash_map, &(tmp_frame.helem));
  if (h == NULL) {
    PANIC ("The page to be freed is not stored in the table");
  }

  f = hash_entry(h, struct frame_table_entry, helem);

  hash_delete (&frame_hash_map, &f->helem);
  list_remove (&f->lelem);

 
  palloc_free_page(kpage);
  free(f);
  lock_release (&frame_lock);
}

/* Just removes*/
void vm_frame_entry_remove (void *kpage)
{
  lock_acquire (&frame_lock);
  ASSERT (lock_held_by_current_thread(&frame_lock) == true);
  ASSERT (is_kernel_vaddr(kpage));
  ASSERT (pg_ofs (kpage) == 0); // should be aligned

  struct frame_table_entry tmp_frame;
  struct hash_elem *h;
  struct frame_table_entry *f;
  
  tmp_frame.kpage = kpage;

  h = hash_find (&frame_hash_map, &(tmp_frame.helem));
  if (h == NULL) {
    PANIC ("The page to be freed is not stored in the table");
  }

  f = hash_entry(h, struct frame_table_entry, helem);

  hash_delete (&frame_hash_map, &f->helem);
  list_remove (&f->lelem);

  free(f);
  lock_release (&frame_lock);
}

void
vm_frame_just_free (void *kpage, bool free_page)
{
  ASSERT (lock_held_by_current_thread(&frame_lock) == true);
  ASSERT (is_kernel_vaddr(kpage));
  ASSERT (pg_ofs (kpage) == 0); 

  struct frame_table_entry tmp_frame;
  struct hash_elem *h;
  struct frame_table_entry *f;
  
  tmp_frame.kpage = kpage;

  h = hash_find (&frame_hash_map, &(tmp_frame.helem));
  if (h == NULL) {
    PANIC ("The page to be freed is not stored in the table");
  }

  f = hash_entry(h, struct frame_table_entry, helem);

  hash_delete (&frame_hash_map, &f->helem);
  list_remove (&f->lelem);

  if(free_page) palloc_free_page(kpage);
  free(f);
}

/* Second Chance Algorithm */
struct frame_table_entry* second_chance( uint32_t *pagedir ) {
  //struct frame_table_entry* res = NULL;
  size_t frame_hash_map_size = hash_size(&frame_hash_map);
  size_t iter;
  if(frame_hash_map_size == 0) 
    PANIC("Frame table is empty.");
  else{
    frame_hash_map_size *= 2;
  }

  for(iter = 0; iter <= frame_hash_map_size; iter++) 
  {
    if(iter > frame_hash_map_size) break;

    if (list_empty(&frame_list))
      PANIC("Frame table is empty, can't happen - there is a leak somewhere");
    if (victim_ptr == NULL || victim_ptr == list_end(&frame_list))
      victim_ptr = list_begin (&frame_list);
    else
      victim_ptr = list_next (victim_ptr);
    struct frame_table_entry *e = list_entry(victim_ptr, struct frame_table_entry, lelem);
    if(e->pinned) continue;
    else if( pagedir_is_accessed(pagedir, e->upage)) {
      pagedir_set_accessed(pagedir, e->upage, false);
      continue;
    }

    // victim_ptr 
    return e;
  }

  PANIC ("Can't evict any frame. \n");

}

void
vm_frame_pinned (void* kpage) {
  lock_acquire (&frame_lock);
  struct frame_table_entry tmp_frame;
  struct hash_elem *h;
  struct frame_table_entry *f;
  bool pin;
  tmp_frame.kpage = kpage;
  h = hash_find (&frame_hash_map, &(tmp_frame.helem));
  if (h == NULL) {
    PANIC ("The frame to be pinned/unpinned does not exist");
  }
  pin = true;
  f = hash_entry(h, struct frame_table_entry, helem);
  f->pinned = pin;

  lock_release (&frame_lock);
}

void
vm_frame_unpinned (void* kpage) {
  //vm_frame_set_pinned (kpage, false);
  lock_acquire (&frame_lock);
  struct frame_table_entry tmp_frame;
  struct frame_table_entry *f;
  bool unpin;
  // hash lookup : a temporary entry
  
  tmp_frame.kpage = kpage;
  struct hash_elem *h = hash_find (&frame_hash_map, &(tmp_frame.helem));
  if (h == NULL) {
    PANIC ("The frame to be pinned/unpinned does not exist");
  }
  unpin = false;
  f = hash_entry(h, struct frame_table_entry, helem);
  f->pinned = unpin;
  lock_release (&frame_lock);
}

