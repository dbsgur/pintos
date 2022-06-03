#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "include/lib/user/syscall.h"
#include "include/threads/init.h"
#include "userprog/process.h"
#include "include/threads/synch.h"
#include "include/threads/thread.h"
#include "include/filesys/file.h"
#include "include/filesys/filesys.h"
#include "threads/palloc.h"
#include "lib/string.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
void check_address(void *addr);
void get_argument(void *esp, int *arg, int count);
int exec(const char *cmd_line);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
void seek(int fd, unsigned position);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
unsigned tell(int fd);
void close(int fd);
int wait(pid_t pid);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081					/* Segment selector msr */
#define MSR_LSTAR 0xc0000082				/* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

static struct lock filesys_lock;

void syscall_init(void)
{
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
													((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
						FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	lock_init(&filesys_lock);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{
	/*
	인자 들어오는 순서:
	1번째 인자: %rdi
	2번째 인자: %rsi
	3번째 인자: %rdx
	4번째 인자: %r10
	5번째 인자: %r8
	6번째 인자: %r9
	*/
	// TODO: Your implementation goes here.
	uintptr_t stack_pointer = f->rsp;
	check_address(stack_pointer);
	uint64_t system_call_number = f->R.rax;
	int res;
	switch (system_call_number)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_FORK:
		/* code */
		break;
	case SYS_EXEC:
		f->R.rax = exec(f->R.rdi);
		break;
	case SYS_WAIT:
		f->R.rax = wait(f->R.rdi);
		break;
	case SYS_CREATE:
		f->R.rax = create(f->R.rdi, f->R.rsi);
		break;
	case SYS_REMOVE:
		f->R.rax = remove(f->R.rdi);
		break;
	case SYS_OPEN:
		f->R.rax = open(f->R.rdi);
		break;
	case SYS_FILESIZE:
		f->R.rax = filesize(f->R.rdi);
		break;
	case SYS_READ:
		/* gitbook : System calls that return a value can do so by modifying the rax member of struct intr_frame.*/
		f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_WRITE:
		res = write(f->R.rdi, f->R.rsi, f->R.rdx);
		f->R.rax = res;
		// if(res ==-1) {
		// 	exit(-1);
		// } else {
		// 	f->R.rax = res;
		// }
		break;
	case SYS_SEEK:
		seek(f->R.rdi, f->R.rsi);
		break;
	case SYS_TELL:
		f->R.rax = tell(f->R.rdi);
		break;
	case SYS_CLOSE:
		close(f->R.rdi);
		break;

	default:
		exit(-1);
		break;
	}
	if (thread_current()->exit_status == -1)
	{
		exit(-1);
	}
}

void check_address(void *addr)
{
	// pml4_get_page addr에 페이지 할당 여부 가능한지
	//
	if ((pml4_get_page(thread_current()->pml4, addr) == NULL) || (is_kernel_vaddr(addr)) || (addr == NULL))
	{
		thread_current()->exit_status = -1;
		exit(-1);
	}
	/* 포인터가 가리키는 주소가 유저영역의 주소인지 확인 */
	// if (addr == NULL || !is_user_vaddr(addr))
	// { /* 잘못된 접근일 경우 프로세스 종료 */
	// 	thread_current()->exit_status = -1;
	// 	exit(-1);
	// }
}

void halt(void)
{
	power_off();
}

void exit(int status)
{
	struct thread *curr = thread_current();
	curr->exit_status = status;
	printf("%s: exit(%d)\n", curr->name, status);
	thread_exit();
	// sema_up(&curr->wait_sema);
}

pid_t fork(const char *thread_name)
{
	// rbx, rsp, rbp, r12-r15까지 복사
	/*return pid of child process
		in child : return value == 0
		parent : return value > 0
	*/
	/* 자식은 duplicated 리소스 가지고 있어야 한다.
		- 파일 디스크립터
		- 가상 메모리공간 포함
	*/
}

int exec(const char *cmd_line)
{
	check_address(cmd_line);
	char *cmd_line_copy;
	cmd_line_copy = palloc_get_page(0);
	if (cmd_line_copy == NULL)
		return TID_ERROR;
	memcpy(cmd_line_copy, cmd_line, strlen(cmd_line) + 1);
	if (process_exec(cmd_line_copy) == -1)
	{
		return -1;
	};
}

/* unsigned는 unsigned int의 축약형, unisigned는 4바이트, off_t는 음수2바이트, 양수 2바이트)*/
bool create(const char *file, unsigned initial_size)
{
	check_address(file);
	return filesys_create(file, initial_size);
}

bool remove(const char *file)
{
	check_address(file);
	return filesys_remove(file);
}

int open(const char *file)
{
	check_address(file);
	struct file *f = filesys_open(file);
	if (f == NULL)
	{
		return -1; /* 수정 : 비정상 종료 처리를 open 만 해주지 않음 ?*/
	}
	return process_add_file(f);
}

int filesize(int fd)
{
	struct file *f = process_get_file(fd);
	if (f == NULL)
	{
		thread_current()->exit_status = -1;
		return -1;
	}
	return file_length(f);
}

int read(int fd, void *buffer, unsigned size)
{
	check_address(buffer);
	if (fd == 0)
	{
		int size = 0;
		uint8_t key;
		while (key != '\0')
		{
			key = input_getc();
			size++;
		}
		return size;
	}

	struct file *f = process_get_file(fd);
	if (f == NULL)
	{
		thread_current()->exit_status = -1;
		return -1;
	}
	lock_acquire(&filesys_lock);
	int read_bytes = file_read(f, buffer, size);
	lock_release(&filesys_lock);

	if (read_bytes < size)
	{
		thread_current()->exit_status = -1;
		return -1;
	}
	return read_bytes;
}

int write(int fd, const void *buffer, unsigned size)
{
	check_address(buffer);
	if (fd == 0)
	{
		thread_current()->exit_status = -1;
		return -1;
	}

	if (fd == 1)
	{
		putbuf(buffer, size);
		return sizeof(buffer);
	}

	struct file *f = process_get_file(fd);
	if (f == NULL)
	{
		thread_current()->exit_status = -1;
		return -1;
	}
	lock_acquire(&filesys_lock);
	int byte = file_write(process_get_file(fd), buffer, size);
	lock_release(&filesys_lock);
	return byte;
}

void seek(int fd, unsigned position)
{
	struct file *f = process_get_file(fd);
	file_seek(f, position);
}

unsigned tell(int fd)
{
	struct file *f = process_get_file(fd);
	if (f == NULL)
	{
		thread_current()->exit_status = -1;
		return -1;
	}
	return file_tell(f);
}

void close(int fd)
{
	process_close_file(fd);
}

int wait(pid_t pid)
{
	// pid process's children's exit status를 확인하면 되는데
	process_wait(pid);
}
