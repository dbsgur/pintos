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
pid_t fork(const char *thread_name);

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
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{
	// TODO: Your implementation goes here.
	uintptr_t stack_pointer = f->rsp;
	uint64_t system_call_number = f->R.rax;
	printf("system call!\n");
	switch (system_call_number)
	{
	case SYS_HALT:
		/* code */
		break;
	case SYS_EXIT:
		/* code */
		break;
	case SYS_FORK:
		/* code */
		break;
	case SYS_EXEC:
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
		/* code */
		break;
	case SYS_WRITE:
		/* code */
		printf("SYS_WRITE\n");
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
	// printf("stack_call : %lld\n", system_call);
}

void check_address(void *addr)
{
	/* 포인터가 가리키는 주소가 유저영역의 주소인지 확인 */
	if (&addr < 0x8048000 || &addr > 0xc0000000)
	{ /* 잘못된 접근일 경우 프로세스 종료 */
		exit(-1);
	}
}

void get_argument(void *esp, int *arg, int count)
{
	/* 유저 스택에 저장된 인자값들을 커널로 저장 */

	/* 인자가 저장된 위치가 유저영역인지 확인 */
}

void halt(void)
{
	power_off();
}

void exit(int status)
{
	process_exit();
}

pid_t fork(const char *thread_name) {}