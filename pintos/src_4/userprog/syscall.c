#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"

struct lock filesys_lock;


static void syscall_handler (struct intr_frame *);
static struct file_desc* find_file_desc(struct thread *t,int fd);
static void is_invalid(void);
void check_user(const uint8_t *addr);
static int get_user(const uint8_t *addr);
static int read_user(void *src, void *dst, size_t bytes);


#ifdef VM
static struct mmap_descriptor* find_mmdescriptor(struct thread *, mmapid_t fd);
mmapid_t custom_mmap(int fd, void *);
bool custom_munmap(mmapid_t);
#endif

void
syscall_init (void) 
{
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  int syscall_number;
  read_user(f->esp,&syscall_number,sizeof(syscall_number));
  ASSERT(sizeof(syscall_number == 4));
  
  //page_fault handler에서 필요
  thread_current()->prev_esp = f->esp;
  
  switch(syscall_number){
    case SYS_HALT: //0
    {
      custom_halt();
      break;
    }

    case SYS_EXIT: //1
    {
      int exit_code;
      read_user(f->esp + 4,&exit_code,sizeof(exit_code));
      custom_exit(exit_code);
      break;
    }

    case SYS_EXEC: //2
    {
      void *cmd_line;
      read_user(f->esp+4,&cmd_line,sizeof(cmd_line));
      
      f->eax = (uint32_t) custom_exec((const char*)cmd_line);
      break;
    }

    case SYS_WAIT: //3
    {
      pid_t pid;
      read_user(f->esp + 4,&pid,sizeof(pid));
      int ret = custom_wait(pid);
      f->eax = (uint32_t)ret;
      break;
    }
  
    case SYS_CREATE: //4
    {
      const char *file_name;
      unsigned initial_size;
      read_user(f->esp + 4,&file_name,sizeof(file_name));
      read_user(f->esp + 8,&initial_size,sizeof(initial_size));
      bool return_code = custom_create(file_name,initial_size);
      f->eax = return_code;
      break;
    }

    case SYS_REMOVE: //5
    {
      const char *file_name;
      bool return_code; 
      read_user(f->esp + 4,&file_name,sizeof(file_name));
      return_code = custom_remove(file_name);
      f->eax = return_code;
      break;
    }

    case SYS_OPEN: //6
    {
      const char *file_name;
      int return_code;
      read_user(f->esp + 4,&file_name,sizeof(file_name));
      return_code = custom_open(file_name);
      f->eax = return_code;
      break;
    }

    case SYS_FILESIZE: //7
    {
      int fd;
      read_user(f->esp+4,&fd,sizeof(fd));
      int return_code = custom_filesize(fd);
      f->eax = return_code;
      break;
    }

    case SYS_READ: //8
    {
      int fd;
      void *buffer;
      unsigned size;

      read_user(f->esp + 4, &fd, sizeof(fd));
      read_user(f->esp + 8, &buffer, sizeof(buffer));
      read_user(f->esp + 12, &size, sizeof(size));

      int return_code = custom_read(fd,buffer,size);
      f->eax = (uint32_t) return_code;
      break;
    }

    case SYS_WRITE: //9
    {
      int fd;
      void *buffer;
      unsigned size;

      read_user(f->esp + 4, &fd, sizeof(fd));
      read_user(f->esp + 8, &buffer, sizeof(buffer));
      read_user(f->esp + 12, &size, sizeof(size));

      int return_code = custom_write(fd,buffer,size);
      f->eax = (uint32_t) return_code;
      break;
    }

    case SYS_SEEK: //10
    {
      int fd;
      unsigned position;

      read_user(f->esp+4, &fd, sizeof(fd));
      read_user(f->esp+8, &position, sizeof(position));

      custom_seek(fd,position);
      break;
    }

    case SYS_TELL://11
    {
      int fd;
      unsigned return_code;

      read_user(f->esp+4,&fd,sizeof(fd));
      return_code = custom_tell(fd);
      f->eax = (uint32_t) return_code;
      break;
    }

    case SYS_CLOSE://12
    {
      int fd;
      read_user(f->esp+4, &fd, sizeof(fd));
      custom_close(fd);
      break;
    }
#ifdef VM
    case SYS_MMAP:// 13
    {
      int fd;
      void *addr;
      read_user(f->esp + 4, &fd, sizeof(fd));
      read_user(f->esp + 8, &addr, sizeof(addr));

      mmapid_t return_code = custom_mmap (fd, addr);
      f->eax = return_code;
      break;
    }

  case SYS_MUNMAP:// 14
    {
      mmapid_t mid;
      read_user(f->esp + 4, &mid, sizeof(mid));
      custom_munmap(mid);
      break;
    }
#endif
  }
}

void custom_halt(void){
  shutdown_power_off();
}

void custom_exit(int status){
  printf("%s: exit(%d)\n",thread_current()->name,status);

  struct process_control_block *pcb = thread_current() -> pcb;
  if(pcb != NULL)
    pcb -> exitcode = status;
  thread_exit();
}

pid_t custom_exec(const char *cmd_line){
  
  // Check validity
  check_user((const uint8_t *)cmd_line);
  //2. Create new process
  lock_acquire(&filesys_lock);
  pid_t pid = process_execute(cmd_line);
  lock_release(&filesys_lock);

  return  pid;
}

int custom_wait(pid_t pid){
  return process_wait(pid);
}


bool custom_create(const char *file_name, unsigned initial_size){
  if(file_name == NULL)
    custom_exit(-1);
  check_user((const uint8_t*)file_name);

  lock_acquire(&filesys_lock);
  bool success = filesys_create(file_name,initial_size);
  lock_release(&filesys_lock);

  return success;
}

bool custom_remove(const char *file_name){
  if(file_name == NULL)
    custom_exit(-1);
  check_user((const uint8_t*)file_name);

  lock_acquire(&filesys_lock);
  bool success = filesys_remove(file_name);
  lock_release(&filesys_lock);

  return success;
}

int custom_open(const char *file_name){
  struct file_desc* fd;
  struct file *file;
    
  check_user((const uint8_t*)file_name);
  fd = palloc_get_page(0);
  if(!fd) 
    return -1;

  lock_acquire(&filesys_lock);
  file = filesys_open(file_name);
  if(file == NULL){
    palloc_free_page(fd);
    lock_release(&filesys_lock);
    return -1;
  }
  if(strcmp(thread_name(),file_name) == 0){
    file_deny_write(file);
  }


  fd->file = file;
 
  struct list* fd_list = &thread_current()->file_descriptors;
  if(list_empty(fd_list)){
    fd->id = 3;
  }
  else{
    fd->id = (list_entry(list_back(fd_list),struct file_desc,elem)->id) + 1;
  }
  list_push_back(fd_list,&(fd->elem));
  lock_release(&filesys_lock);
  return fd->id;
}

int custom_filesize(int fd){
  struct file_desc* desc;
  lock_acquire(&filesys_lock);
  desc = find_file_desc(thread_current(),fd);

  if(desc == NULL){
    lock_release(&filesys_lock);
    return -1;
  }
  int return_code = file_length(desc->file);
  lock_release(&filesys_lock);
  return return_code;
}

int custom_read(int fd, void *buffer, unsigned size){
  check_user((const uint8_t *)buffer);
  check_user((const uint8_t *)buffer + size -1);

  lock_acquire(&filesys_lock);
  int return_code;

  if(fd == 0){// STDIN
    unsigned i;
    for(i = 0;i<size;i++){
      if(!input_getc()){
        custom_exit(-1);
      }
    }
    return_code = size;
  }

  else{ //file
    struct file_desc* desc = find_file_desc(thread_current(), fd);
    if(fd && desc->file){
#ifdef VM
      vm_preload_pin_pages(buffer, size);
#endif
      return_code = file_read(desc->file,buffer,size);
#ifdef VM
      vm_unpin_preloaded_pages(buffer, size);
#endif
    }
    else{
      return_code = -1;
    }
  }
  lock_release(&filesys_lock);
  return return_code;
}

int custom_write(int fd, const void *buffer,unsigned size){

  int return_code;
  check_user((const uint8_t*)buffer);
  check_user((const uint8_t*)buffer + size -1);

  lock_acquire(&filesys_lock);
  if(fd == 1){
    putbuf(buffer,size);
    return_code = size;
  }
  else {
    struct file_desc *desc = find_file_desc(thread_current(),fd);
    if(desc && desc->file){
#ifdef VM
      vm_preload_pin_pages(buffer, size);
#endif
      return_code = file_write(desc->file,buffer,size);
#ifdef VM
      vm_unpin_preloaded_pages(buffer, size);
#endif
    }
    else{
      return_code = -1;
    }
  }
  lock_release(&filesys_lock);
  return return_code;
}

void custom_seek(int fd, unsigned position){
  lock_acquire(&filesys_lock);
  struct file_desc* desc = find_file_desc(thread_current(),fd);
  if(desc && desc->file){
    file_seek(desc->file,position);
  }
  else
    return;
  lock_release(&filesys_lock);
}

unsigned custom_tell(int fd){
  lock_acquire(&filesys_lock);
  struct file_desc* desc = find_file_desc(thread_current(),fd);
  unsigned ret;
  if(desc && desc->file){
    ret = file_tell(desc->file);
  }
  else
    ret = -1;
  lock_release(&filesys_lock);
  return ret;
}

void custom_close(int fd){
  lock_acquire(&filesys_lock);
  struct file_desc *desc = find_file_desc(thread_current(),fd);
  if(desc && desc->file){
    file_close(desc->file);
    list_remove(&(desc->elem));
    palloc_free_page(desc);
  }
  lock_release(&filesys_lock);
}

#ifdef VM
mmapid_t custom_mmap(int fd, void *upage) {
  struct file *f = NULL;
  if (upage == NULL || pg_ofs(upage) != 0) 
    return -1;
  if (fd <= 1) 
    return -1; 
  struct thread *cur = thread_current();

  lock_acquire (&filesys_lock);

  /* file open */
  struct file_desc* desc = find_file_desc(thread_current(), fd);
  if(desc && desc->file) {
    f = file_reopen (desc->file);
  }
  if(f == NULL) 
    goto MMAP_FAIL;

  size_t file_size = file_length(f);
  if(file_size == 0) 
    goto MMAP_FAIL;

  /* mapping memory pages */
  size_t offset;
  for (offset = 0; offset < file_size; offset += PGSIZE) {
    void *addr = upage + offset;
    if (vme_has_entry(cur->vm, addr)) goto MMAP_FAIL;
  }

  /* map each page to filesystem */
  for (offset = 0; offset < file_size; offset += PGSIZE) {
    void *addr = upage + offset;

    size_t read_bytes = (offset + PGSIZE < file_size ? PGSIZE : file_size - offset);
    size_t zero_bytes = PGSIZE - read_bytes;

    vm_install_filesys(cur->vm, addr,
        f, offset, read_bytes, zero_bytes, true);
  }

  /* Assign mmapid */
  mmapid_t mid;
  if (! list_empty(&cur->mmap_list)) {
    mid = list_entry(list_back(&cur->mmap_list), struct mmap_descriptor, elem)->id + 1;
  }
  else mid = 1;

  struct mmap_descriptor *mmap_d = (struct mmap_descriptor*) malloc(sizeof(struct mmap_descriptor));
  mmap_d->id = mid;
  mmap_d->file = f;
  mmap_d->addr = upage;
  mmap_d->size = file_size;

  list_push_back (&cur->mmap_list, &mmap_d->elem);

  lock_release (&filesys_lock);
  return mid;

MMAP_FAIL:
  lock_release (&filesys_lock);
  return -1;
}

bool custom_munmap(mmapid_t mid)
{
  struct thread *curr = thread_current();
  struct mmap_descriptor *mmap_d = find_mmdescriptor(curr, mid);

  if(mmap_d == NULL) { 
    return false; 
  }

  lock_acquire (&filesys_lock);
  {
    
    size_t offset, file_size = mmap_d->size;
    for(offset = 0; offset < file_size; offset += PGSIZE) {
      void *addr = mmap_d->addr + offset;
      size_t bytes = (offset + PGSIZE < file_size ? PGSIZE : file_size - offset);
      vm_mm_unmap (curr->vm, curr->pagedir, addr, mmap_d->file, offset, bytes);
    }

    list_remove(& mmap_d->elem);
    file_close(mmap_d->file);
    free(mmap_d);
  }
  lock_release (&filesys_lock);

  return true;
}
#endif


void check_user(const uint8_t *addr){
  if(get_user(addr) == -1){
    is_invalid();
  }
}

static int get_user(const uint8_t *addr){
  int result;
  if(!is_user_vaddr((void*)addr)){
    return -1;
  }
  asm("movl $1f, %0; movzbl %1, %0; 1:"
      : "=&a"(result): "m"(*addr));
  return result;
}

static int read_user(void *src, void *dst, size_t bytes){
  int32_t value;
  size_t i;
  for(i = 0; i < bytes;i++){
    value = get_user(src + i);
    if(value == -1)
      is_invalid();
    
    *(char*)(dst + i) = value & 0xff;
  }
  return (int)bytes;
}

static struct file_desc* find_file_desc(struct thread *t,int fd){
  ASSERT(t != NULL);
  struct list_elem *e;
  if(fd < 3){
    return NULL;
  }
  
  if(!list_empty(&t->file_descriptors)){
    for(e = list_begin(&t->file_descriptors);e !=list_end(&t->file_descriptors);e = list_next(e)){
      struct file_desc *desc = list_entry(e, struct file_desc, elem);
      if(desc -> id == fd){
        return desc;
      }
    }
  }
  return NULL;
}

static void is_invalid(void){
  if(lock_held_by_current_thread(&filesys_lock))
    lock_release(&filesys_lock);
  custom_exit(-1);
}

#ifdef VM
static struct mmap_descriptor* find_mmdescriptor(struct thread *t, mmapid_t mid)
{
  ASSERT (t != NULL);

  struct list_elem *e;

  if (t != NULL && ! list_empty(&t->mmap_list)) {
    for(e = list_begin(&t->mmap_list);
        e != list_end(&t->mmap_list); e = list_next(e))
    {
      struct mmap_descriptor *desc = list_entry(e, struct mmap_descriptor, elem);
      if(desc->id == mid) {
        return desc;
      }
    }
  }

  return NULL; 
}
#endif