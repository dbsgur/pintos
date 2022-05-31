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
	// lock_init (&filesys_lock);
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
	check_address(stack_pointer); /*추가*/
	uint64_t system_call_number = f->R.rax;
	// printf("system call!\n");
	// printf("system call number : %lld\n", system_call_number);
	switch (system_call_number)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		/* code */
		break;
	case SYS_FORK:
		/* code */
		break;
	case SYS_EXEC:
		// exec(fd);
		/* code */
		break;
	case SYS_WAIT:
		/* code */
		break;
	case SYS_CREATE:
		/* code */
		break;
	case SYS_REMOVE:
		/* code */
		break;
	case SYS_OPEN:
		/* code */
		break;
	case SYS_FILESIZE:
		/* code */
		break;
	case SYS_READ:
		/* gitbook : System calls that return a value can do so by modifying the rax member of struct intr_frame.*/
		f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_WRITE:
		f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_SEEK:
		/* code */
		break;
	case SYS_TELL:
		/* code */
		break;
	case SYS_CLOSE:
		/* code */
		break;

	default:
		thread_exit();
		break;
	}
}

void check_address(void *addr)
{
	/* 포인터가 가리키는 주소가 유저영역의 주소인지 확인 */
	if (!is_user_vaddr(addr))
	{ /* 잘못된 접근일 경우 프로세스 종료 */
		exit(-1);
	}
}

void halt(void)
{
	power_off();
}

void exit(int status)
{
	struct thread *curr = thread_current();
	printf("%s: exit(%d)\n", curr->name, status);
	thread_exit();
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
	char *token, *save_ptr;

	token = strtok_r(cmd_line, " ", &save_ptr);
	if (token != NULL)
	{
		int status = process_exec(token);
		if (status == -1)
		{
			exit(-1);
		}
	}
	else
	{
		exit(-1);
	}
}

/* unsigned는 unsigned int의 축약형, unisigned는 4바이트, off_t는 음수2바이트, 양수 2바이트)*/
bool create(const char *file, unsigned initial_size)
{
	return filesys_create(file, initial_size);
}

bool remove(const char *file)
{
	return filesys_remove(file);
}

/* fd 반환 */
/* 소설 */
/* file open 하면 파일에 대한 포인터가 반환되고 FAQ에 이를 굳이 file descriptor로 캐스팅 할 필요 없다 했으므로... */
int open(const char *file)
{
	int fd = filesys_open(file);
	if (fd == NULL)
	{
		return -1;
	}
	return fd;
}

int filesize(int fd)
{
	return file_length(fd); /* 소설 : 이 함수 쓰는게 맞나 */
}

int read(int fd, void *buffer, unsigned size)
{	

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

	// lock_acuqire(filesys_lock);
	int read_bytes = file_read(fd, buffer, size);
	if (read_bytes < size)
	{
		return -1;
	}
	return read_bytes;
}

int write(int fd, const void *buffer, unsigned size)
{
	if (fd == 0)
	{
		return -1;
	}

	if (fd == 1)
	{
		putbuf(buffer, size);
		return sizeof(buffer);
	}
	// fd 받는법
	return file_write(fd, buffer, size);
}

void seek(int fd, unsigned position)
{
	file_seek(fd, position);
}

unsigned tell(int fd)
{
	return file_tell(fd);
}

void close(int fd)
{
	file_close(fd);
}

int wait(pid_t pid)
{
	process_wait(pid);
}
