#ifndef VM_PAGE_H
#define VM_PAGE_h

#include <debug.h>
#include <inttypes.h>
#include <stdio.h>
#include <round.h>
#include <stdlib.h>
#include <string.h>
#include <hash.h>

#include "vm/frame.h"
#include "vm/swap.h"
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "filesys/directory.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "filesys/off_t.h"

#define VM_BIN 0
#define VM_FILE 1
#define VM_ANON 2
#define CLOSE_ALL 9999
enum vm_page_status {
	ALL_ZERO,
	ON_FRAME,
	ON_SWAP,
	FROM_FILESYS
};

struct vm_page_table_entry{
	//uint8_t type;	/*VM_BIN : 0 VM_FILE : 1 VM_ANON : 2*/
	enum vm_page_status status;
	void* user_page;
	void* kernel_page;
	//void *vaddr;	/* vm_entry가 관리하는 가상 페이지 번호*/
	bool writable;	/* True : writable false : non-writable*/
	
	bool is_dirty; /* True : is in PA false : no in PA */
	struct file* file; /* 가상주소와 mapping된 파일 */
	
	/*Memory Mapped file*/
//	struct list_elem mmap_elem; /* mmap list element */

	off_t file_offset; /*file offest*/
	size_t read_bytes;	/*가상 페이지에 쓰여져있는 데이터 크기*/
	size_t zero_bytes;	/* 0으로 채울 남은 페이지 바이트*/

	/*swapping*/
	size_t swap_slot; /* swap slot */

	/*vm_entry 자료구조*/
	struct hash_elem elem;  /*hash_table element*/
};

struct vm_page_table{
	struct hash page_hash_map;
};

struct vm_page_table *vm_page_init_create(void);
void vm_page_destroy(struct vm_page_table *vm);

bool vm_install_frame(struct vm_page_table* vm, void *user_page, void *kernel_page);
bool vm_install_filesys(struct vm_page_table* vm, void* user_page, struct file *file, off_t offset, size_t read_bytes, size_t zero_bytes, bool writable);
bool stack_growth(struct vm_page_table* vm, void*);

struct vm_page_table_entry *vm_page_look_up (struct vm_page_table *vm, void *);
bool vm_set_swap(struct vm_page_table *vm, void *, swap_idx );
bool vme_has_entry(struct vm_page_table *vm, void* page);
bool vm_set_is_dirty(struct vm_page_table *vm, void* , bool );
bool handle_mm_fault(struct vm_page_table *vm, uint32_t *pagedir, void *user_page);
bool vm_mm_unmap(struct vm_page_table *vm, uint32_t *pagedir, void *page, struct file * file, off_t offset, size_t bytes);

void vm_page_pin(struct vm_page_table *vm, void *page);
void vm_page_unpin(struct vm_page_table *vm, void *page);

void preload_pin_page(const void *, size_t);
void unpin_preloaded_page(const void *, size_t);
#endif /* vm/page.h */
