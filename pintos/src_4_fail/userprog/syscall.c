#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"

/*---------------------------------*/

#include "filesys/file.h"
#include "filesys/off_t.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "threads/synch.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"
struct file 
  {
    struct inode *inode;        /* File's inode. */
    off_t pos;                  /* Current position. */
    bool deny_write;            /* Has file_deny_write() been called? */
  };

struct lock filesys_lock;
static void syscall_handler (struct intr_frame *);
/*
#ifdef VM
int custom_mmap(int fd, void *);
bool custom_munmap(int );
static struct mmap_descriptor* find_mmap_desc(struct thread *, ind fd);
#endif
*/
void
syscall_init (void) 
{
	/*-------project2-------*/
	lock_init(&filesys_lock);
	/*---------------------*/
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}



static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf ("system call! : %d \n",*(uint32_t *)(f->esp));
	//hex_dump(f->esp, f->esp, 100, 1);
	uint32_t sys_num = *(uint32_t *)(f->esp);
	thread_current()->prev_esp = f->esp;
	if(!is_user_vaddr(sys_num)){
		custom_exit(-1);
	}
	switch(sys_num){
		case SYS_HALT:
			custom_halt();
			break;

		case SYS_EXIT:
			if(!is_user_vaddr(f->esp+4)){
				custom_exit(-1);
			}
			custom_exit(*(uint32_t *)(f->esp + 4));
			break;

		case SYS_EXEC:
			if(!is_user_vaddr(f->esp+4)){
				custom_exit(-1);
			}
			f->eax = custom_exec((const char *)*(uint32_t *)(f->esp+4));
			break;

		case SYS_WAIT:
			if(!is_user_vaddr(f->esp+4)){
				custom_exit(-1);
			}
			f->eax =custom_wait((pid_t)*(uint32_t *)(f->esp+4));
			break;

		case SYS_CREATE:
			if(!is_user_vaddr(f->esp+4) || !is_user_vaddr(f->esp+8)){
				custom_exit(-1);
			}
			f->eax = custom_create((const char *)*(uint32_t *)(f->esp+4), (unsigned)*(uint32_t *)(f->esp+8));
			break;

		case SYS_REMOVE:
			if(!is_user_vaddr(f->esp+4)){
				custom_exit(-1);
			}
			f->eax = custom_remove((const char *)*(uint32_t *)(f->esp + 4));
			break;

		case SYS_OPEN:
			if(!is_user_vaddr(f->esp+4)){
				custom_exit(-1);
			}
			f->eax = custom_open((const char *)*(uint32_t *)(f->esp +4));
			break;
		case SYS_FILESIZE:
			if(!is_user_vaddr(f->esp+4)){
				custom_exit(-1);
			}
			f->eax = custom_filesize((int)*(uint32_t *)(f->esp+4));
			break;
		case SYS_READ:
			if(!is_user_vaddr(f->esp+4)||!is_user_vaddr(f->esp+8)||!is_user_vaddr(f->esp+12)){
				custom_exit(-1);
			}
			f->eax = custom_read((int)*(uint32_t *)(f->esp + 4),(void *)*(uint32_t *)(f->esp + 8),(unsigned)*((uint32_t *)(f->esp + 12)));

			break;

		case SYS_WRITE:
			if(!is_user_vaddr(f->esp+4)||!is_user_vaddr(f->esp+8)||!is_user_vaddr(f->esp+12)){
				custom_exit(-1);
			}
			f->eax = custom_write((int)*(uint32_t *)(f->esp + 4),(void *)*(uint32_t *)(f->esp + 8),(unsigned)*((uint32_t *)(f->esp + 12)));
			break;

		case SYS_SEEK:
			if(!is_user_vaddr(f->esp+4) || !is_user_vaddr(f->esp+8)){
				custom_exit(-1);
			}
			custom_seek((int)*(uint32_t *)(f->esp+4), (unsigned)*(uint32_t *)(f->esp+8));
			break;

		case SYS_TELL:
			if(!is_user_vaddr(f->esp+4)){
				custom_exit(-1);
			}
			f->eax = custom_tell((int)*(uint32_t *)(f->esp+4));
			break;

		case SYS_CLOSE:
			if(!is_user_vaddr(f->esp+4)){
				custom_exit(-1);
			}
			custom_close((int)*(uint32_t *)(f->esp+4));
			break;
#ifdef VM
		case SYS_MMAP:
			/*
			if(!is_user_vaddr(f->esp+4) || !is_user_vaddr(f->esp+8)){
				custom_exit(-1);
			}
			f->eax = custom_mmap((int *)(f->esp+4), (void *)(f->esp+8));
			*/
			break;

		case SYS_MUNMAP:
			/*
			int munid;
			if(!is_user_vaddr(f->esp+4)){
				custom_exit(-1);
			}
			custom_munmap((int *)(f->esp+4));
			*/
			break;
#endif
		case SYS_CHDIR:
			break;

		case SYS_MKDIR:
			break;

		case SYS_READDIR:
			break;

		case SYS_ISDIR:
			break;

		case SYS_INUMBER:
			break;

		case SYS_FIBONACCI:
			f->eax = custom_fibonacci((int)*(uint32_t *)(f->esp + 4));
			break;
		
		case SYS_MAX_OF_FOUR_INT:
			//hex_dump(f->esp, f->esp, 100, 1);
			f->eax = custom_max_of_four_int((int)*(uint32_t *)(f->esp + 4), (int)*(uint32_t *)(f->esp + 8), (int)*(uint32_t *)(f->esp + 12), (int)*(uint32_t *)(f->esp + 16));
			break;
	}
 // thread_exit ();
}

void custom_halt(void){
	shutdown_power_off();
}

void custom_exit(int status){
	printf("%s: exit(%d)\n", thread_name(), status);
	thread_current()->exit_status = status;
	/*---project2---*/
	int i;
	for(i =3; i < 128; i++){
		if(thread_current()->fd[i] !=NULL){
			custom_close(i);
		}
	}
	thread_exit();
}

pid_t custom_exec(const char* command_line){
	return process_execute(command_line);
}

int custom_wait(pid_t pid){
	return process_wait(pid);
}

int custom_write(int fd, const void *buf, unsigned size){
	//use putbuf	
	int result;
	if(!is_user_vaddr(buf)){
		custom_exit(-1);
	}
	lock_acquire(&filesys_lock);
	result = -1;
	if(fd == 1){
		putbuf(buf, size);
		result = size;
	}
	else if(fd>2){ //preject 2
		//struct file* fp = thread_current()->fd[fd];
		if(thread_current()->fd[fd] == NULL){
			lock_release(&filesys_lock);
			custom_exit(-1);
		}
		if(thread_current()->fd[fd]->deny_write){//deny_write
			file_deny_write(thread_current()->fd[fd]);
		}
#ifdef VM
		preload_pin_page(buf,size);
#endif
		result = file_write(thread_current()->fd[fd], buf, size);
#ifdef VM
		unpin_preloaded_page(buf, size);
#endif
	}
	lock_release(&filesys_lock);
	//incorrect file descriptor
	return result;
}

int custom_read(int fd, void *buf, unsigned size){
	//use input_getc()
	int read_buffer= -1;
	//read_buffer = -1;
	//void* tmp_buf = buf;
	if(!is_user_vaddr(buf)){
		custom_exit(-1);
	}

	lock_acquire(&filesys_lock);
	if(fd == 0){
		//void* tmp_buf = buf;
		//*(uint32_t *)tmp_buf = input_getc();
		read_buffer = input_getc();
	}
	else if(fd > 2){ //project2
		if(thread_current()->fd[fd] == NULL){
			lock_release(&filesys_lock);
			custom_exit(-1);
		}
#ifdef VM
		preload_pin_page(buf, size);
#endif

		read_buffer =  file_read(thread_current()->fd[fd], buf, size);

#ifdef VM
		unpin_preloaded_page(buf, size);
#endif
	}
	lock_release(&filesys_lock);
	return read_buffer;
}

int custom_fibonacci (int n){
	int tmp1, tmp2, result;
	int i;
	tmp1 = 0;
	result = 1;
	//printf("\n\nfibo a = %d\n\n",n);
	if(n <= 2) return 1;
	
	for(i = 0; i < n; i++){
		tmp2 = result;
		result += tmp1;
		tmp1 = tmp2;
	}
	return tmp1;
}

int custom_max_of_four_int (int a, int b, int c, int d){
	int MAX_ = a;
	//printf("\n\na=%d,\nb=%d,\nc=%d,\nd=%d\n\n",a, b, c, d);	
	if(MAX_ < b){
		MAX_ = b;
	}
	if(MAX_ < c){
		MAX_ = c;
	}
	if(MAX_ < d){
		MAX_ = d;
	}
	 
	return MAX_;
}
//-----------------------------------------------
//-------------------project2--------------------
//-----------------------------------------------

bool custom_create(const char *file, unsigned initial_size){
	if(file == NULL){
		custom_exit(-1);
	}
	if(!is_user_vaddr(file)){
		custom_exit(-1);
	}
	return filesys_create(file, initial_size);
}

bool custom_remove(const char *file){
	if(file == NULL){
		custom_exit(-1);
	}
	if(!is_user_vaddr(file)){
		custom_exit(-1);
	}

	return filesys_remove(file);
}
int custom_open(const char *file){
	int result;
	if(file == NULL){
		custom_exit(-1);
	}
	if(!is_user_vaddr(file)){
		custom_exit(-1);
	}

	lock_acquire(&filesys_lock);
	
	struct file *fp = filesys_open(file);
	
	if(fp == NULL){
		result = -1;
	}
	else{
		int i;
		for(i = 3; i <128; i++){
			if(thread_current()->fd[i] == NULL){
				char* cur_file_name = thread_current()->name;
				if(strcmp(cur_file_name, file) == 0){
					file_deny_write(fp);
				}
				thread_current()->fd[i] = fp;
				result = i;
				break;
			}
		}
	}
	lock_release(&filesys_lock);
	return result;
}

int custom_filesize(int fd){
	if(thread_current()->fd[fd] == NULL){
		custom_exit(-1);
	}
	return file_length(thread_current()->fd[fd]);
}

void custom_seek(int fd, unsigned position){
	if(thread_current()->fd[fd] == NULL){
		custom_exit(-1);
	}
	return file_seek(thread_current()->fd[fd], position);
}

unsigned custom_tell (int fd){
	if(thread_current()->fd[fd] == NULL){
		custom_exit(-1);
	}
	return file_tell(thread_current()->fd[fd]);
}

void custom_close(int fd){
	struct file* fp;
	if(thread_current()->fd[fd] == NULL){
		custom_exit(-1);
	}
	fp = thread_current()->fd[fd]; 
	thread_current()->fd[fd] = NULL;
	return file_close(fp);
}

#ifdef VM
int custom_mmap(int fd, void* user_page){
	/*
	struct file *f = NULL;

	if(user_page == NULL || pg_ofs(user_page) != 0 || fd < 2){
		return -1;
	}

	struct thread *cur = thread_current();

	lock_acquire(&filesys_lock);
	struct file_descriptor* file_desc;
	file_desc = find_in_file_desc(thread_current(), fd);

	lock_release(&filesys_lock);
	*/
	return fd;
}
bool custom_munmap(int mid){
	return true;
}
static struct mmap_descriptor* find_mmap_desc(struct thread* t, int mid){
	
	ASSERT(t != NULL);
	struct list_elem *e;
	struct mmap_descriptor *result, *desc;
	result = NULL;
	if(!list_empty(&t->mmap_list)){
		e = list_begin(&t->mmap_list);
		while(e != list_end(&t->mmap_list)){
			desc = list_entry(e, struct mmap_descriptor, elem);
			if(desc->id == mid){
				result = desc;
				break;
			}
			e = list_next(e);
		}
	}
	
	return result;
	
}
#endif
