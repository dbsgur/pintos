#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#include "userprog/syscall.h"
#include "threads/synch.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup(void);
static bool load(const char *file_name, struct intr_frame *if_);
static void initd(void *f_name);
static void __do_fork(void *);

static struct lock open_lock;

/* General process initializer for initd and other process. */
static void
process_init(void)
{
	struct thread *current = thread_current();
	lock_init(&open_lock);
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t process_create_initd(const char *file_name)
{
	char *fn_copy;
	tid_t tid;
	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page(0);
	if (fn_copy == NULL)
		return TID_ERROR;
	memcpy(fn_copy, file_name, PGSIZE);

	char *fn_copy2;
	fn_copy2 = palloc_get_page(0);
	if (fn_copy2 == NULL)
		return TID_ERROR;
	memcpy(fn_copy2, fn_copy, PGSIZE);

	char *save_ptr;
	char *title;
	title = strtok_r(fn_copy2, " ", &save_ptr); // 첫번째 인자

	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create(title, PRI_DEFAULT, initd, fn_copy); //특정 기능을 가진 스레드 생성
	palloc_free_page(fn_copy2);
	if (tid == TID_ERROR)
		palloc_free_page(fn_copy);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd(void *f_name)
{
#ifdef VM
	supplemental_page_table_init(&thread_current()->spt);
#endif
	process_init();
	if (process_exec(f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t process_fork(const char *name, struct intr_frame *if_ UNUSED)
{
	thread_current()->temp_tf = *if_;
	return thread_create(name,
											 PRI_DEFAULT, __do_fork, thread_current());
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte(uint64_t *pte, void *va, void *aux)
// pte : page table entry || va : 물리주소 (페이지)
{
	struct thread *current = thread_current();
	struct thread *parent = (struct thread *)aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	if (is_kernel_vaddr(va)) // va : user 영역 가상 주소
	{
		return true;
	}
	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page(parent->pml4, va); // pte가 가리키는 page  주소
	if (parent_page == NULL)
	{
		return false;
	}
	// pte -> parent page table entry
	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
	newpage = palloc_get_page(PAL_USER);
	if (newpage == NULL)
	{
		return false;
	}

	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	memcpy(newpage, parent_page, PGSIZE);

	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	writable = is_writable(pte);

	if (!pml4_set_page(current->pml4, va, newpage, writable))
	{
		/* 6. TODO: if fail to insert page, do error handling. */
		return false;
		// exit(-1);
		// goto error;
	}
	return true;
	// error:
	// 	thread_exit();
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork(void *aux)
{
	struct intr_frame if_;
	struct thread *parent = (struct thread *)aux;
	struct thread *current = thread_current();
	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *parent_if = &parent->temp_tf;
	bool succ = true;
	memcpy(&if_, parent_if, sizeof(struct intr_frame));
	/* 자식 프로세스이므로 return 값을 0이로 설정 pid = 0 */
	if_.R.rax = 0;

	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	process_activate(current);
#ifdef VM
	supplemental_page_table_init(&current->spt);
	if (!supplemental_page_table_copy(&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each(parent->pml4, duplicate_pte, parent))
		goto error;
#endif

	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/
	int fdn;
	current->next_fd = parent->next_fd;
	for (fdn = 2; fdn < parent->next_fd; fdn++)
	{
		if (parent->fdt[fdn] == NULL)
		{
			continue;
		}
		current->fdt[fdn] = file_duplicate(parent->fdt[fdn]);
	}
	process_init();
	sema_up(&current->load_sema);
	/* Finally, switch to the newly created process. */
	if (succ)
		do_iret(&if_);
error:
	sema_up(&current->load_sema);
	exit(-1);
	// thread_exit();
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail.
 run_task에서 호출 시작 프로세스
 인터럽트 프레임과 사용자 스택을 초기화 한다.
 사용자 스택에서 arguments 설정
 인터럽트 종료를 통해 유저프로그램으로 점프
 */
int process_exec(void *f_name)
{
	char *file_name_copy;
	bool success;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	file_name_copy = palloc_get_page(0);
	if (file_name_copy == NULL)
		return TID_ERROR;
	memcpy(file_name_copy, f_name, strlen(f_name) + 1);

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
	process_cleanup();

	/* 파싱하기 */
	int token_count = 0;
	char *token, *last;
	char *arg_list[65];
	char *tmp_save = token;

	token = strtok_r(file_name_copy, " ", &last);
	arg_list[token_count] = token;

	while (token != NULL)
	{
		token = strtok_r(NULL, " ", &last);
		token_count++;
		arg_list[token_count] = token;
	}

	/* And then load the binary */
	if (token_count == 0)
	{
		success = load(f_name, &_if); /* 해당 바이너리 파일을 메모리에 로드하기 */
		argument_stack(token_count, f_name, &_if);
	}
	else
	{
		success = load(arg_list[0], &_if); /* 해당 바이너리 파일을 메모리에 로드하기 */
		argument_stack(token_count, arg_list, &_if);
	}

	/* If load failed, quit. */
	palloc_free_page(file_name_copy);
	/* file name과 file_name copy도 해지 */
	if (!success)
	{
		palloc_free_page(f_name);
		return -1;
	}

	// void **rspp = &_if.rsp;
	// hex_dump(_if.rsp, _if.rsp, USER_STACK - (uint64_t)*rspp, true);

	/* Start switched process. 생성된 프로*/
	palloc_free_page(f_name);
	do_iret(&_if); // 유저 프로그램 실행
	NOT_REACHED();
}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int process_wait(tid_t child_tid UNUSED)
{
	struct thread *t = thread_current();

	/* 자식 프로세스의 프로세스 디스크립터 검색 */
	struct thread *children;
	struct list *children_list = &t->children;
	children = get_child_process(child_tid);
	/* 예외 처리 발생시 -1 리턴 */
	if (children == NULL)
	{
		return -1;
	}

	/* 자식프로세스가 종료될 때까지 부모 프로세스 대기(세마포어 이용) */
	// sema_down(&t->exit_sema);
	sema_down(&children->wait_sema);
	/* 자식 프로세스 디스크립터 삭제 */
	list_remove(&children->child_elem);
	// sema_up(&children->exit_sema);
	/* 자식 프로세스의 exit status 리턴 */
	return children->exit_status;
}

/* Exit the process. This function is called by thread_exit (). */
void process_exit(void)
{
	struct thread *curr = thread_current();
	uint32_t *pd;

	while (--(curr->next_fd) >= 2)
	{
		process_close_file(curr->next_fd);
	}
	palloc_free_page(curr->fdt); /* free 는 나중에 */
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */
	sema_up(&curr->wait_sema);
	// sema_down(&curr->exit_sema);

	process_cleanup();
}

/* Free the current process's resources. */
static void
process_cleanup(void)
{
	struct thread *curr = thread_current();

#ifdef VM
	supplemental_page_table_kill(&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL)
	{
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate(NULL);
		pml4_destroy(pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void process_activate(struct thread *next)
{
	/* Activate thread's page tables. */
	pml4_activate(next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update(next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL 0						/* Ignore. */
#define PT_LOAD 1						/* Loadable segment. */
#define PT_DYNAMIC 2				/* Dynamic linking info. */
#define PT_INTERP 3					/* Name of dynamic loader. */
#define PT_NOTE 4						/* Auxiliary info. */
#define PT_SHLIB 5					/* Reserved. */
#define PT_PHDR 6						/* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr
{
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR
{
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack(struct intr_frame *if_);
static bool validate_segment(const struct Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
												 uint32_t read_bytes, uint32_t zero_bytes,
												 bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load(const char *file_name, struct intr_frame *if_)
{ // 사용자 스택 유형, 함수의 시작진입 점등을 포함한다.
	struct thread *t = thread_current();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create(); //유저 프로세스의 페이지 테이블 생성
	if (t->pml4 == NULL)
		goto done;
	process_activate(thread_current()); //레지서터 값을 실행중인 스레드의 페이지 테이블 주소로 변경

	lock_acquire(&open_lock);

	file = filesys_open(file_name); //프로그램 파일 오픈

	if (file == NULL)
	{
		lock_release(&open_lock);
		printf("load: %s: open failed\n", file_name);
		goto done;
	}

	/* thread 구조체의 run_file을 현재 실행할 파일로 초기화 */
	/* file_deny_write()를 이용하여 파일에 대한 write를 거부 */
	t->run_file = file;
	file_deny_write(file);
	lock_release(&open_lock);

	/* Read and verify executable header.
		 ELF파일의 헤더 정보를 읽어와 저장
	*/
	if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr || memcmp(ehdr.e_ident, "\177ELF\2\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Phdr) || ehdr.e_phnum > 1024)
	{
		printf("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers.
		 배치 정보를 읽어와 저장.
	*/
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++)
	{
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length(file))
			goto done;
		file_seek(file, file_ofs);

		if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type)
		{
		case PT_NULL:
		case PT_NOTE:
		case PT_PHDR:
		case PT_STACK:
		default:
			/* Ignore this segment. */
			break;
		case PT_DYNAMIC:
		case PT_INTERP:
		case PT_SHLIB:
			goto done;
		case PT_LOAD:
			if (validate_segment(&phdr, file))
			{
				bool writable = (phdr.p_flags & PF_W) != 0;
				uint64_t file_page = phdr.p_offset & ~PGMASK;
				uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
				uint64_t page_offset = phdr.p_vaddr & PGMASK;
				uint32_t read_bytes, zero_bytes;
				if (phdr.p_filesz > 0)
				{
					/* Normal segment.
					 * Read initial part from disk and zero the rest. */
					read_bytes = page_offset + phdr.p_filesz;
					zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
				}
				else
				{
					/* Entirely zero.
					 * Don't read anything from disk. */
					read_bytes = 0;
					zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
				}
				/* 배치 정보를 통해 파일을 메모리에 탑재 */
				if (!load_segment(file, file_page, (void *)mem_page,
													read_bytes, zero_bytes, writable))
					goto done;
			}
			else
				goto done;
			break;
		}
	}

	/* Set up stack. */
	if (!setup_stack(if_)) //진입점을 초기화하기 위한 코드(스택 진입점)
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry; //

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */

	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	file_close(file);
	return success;
}

/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment(const struct Phdr *phdr, struct file *file)
{
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t)file_length(file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
		 user address space range. */
	if (!is_user_vaddr((void *)phdr->p_vaddr))
		return false;
	if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
		 address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
		 Not only is it a bad idea to map page 0, but if we allowed
		 it then user code that passed a null pointer to system calls
		 could quite likely panic the kernel by way of null pointer
		 assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page(void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment(struct file *file, off_t ofs, uint8_t *upage,
						 uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
	ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT(pg_ofs(upage) == 0);
	ASSERT(ofs % PGSIZE == 0);

	file_seek(file, ofs);
	while (read_bytes > 0 || zero_bytes > 0)
	{
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page(PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes)
		{
			palloc_free_page(kpage);
			return false;
		}
		memset(kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page(upage, kpage, writable))
		{
			printf("fail\n");
			palloc_free_page(kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack(struct intr_frame *if_)
{
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page(PAL_USER | PAL_ZERO);
	if (kpage != NULL)
	{
		success = install_page(((uint8_t *)USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page(kpage);
	}
	return success;
}

int process_add_file(struct file *f)
{
	struct thread *t = thread_current();
	t->fdt[t->next_fd] = f;
	return t->next_fd++;
}

struct file *process_get_file(int fd)
{
	struct thread *t = thread_current();
	if (fd >= t->next_fd || fd < 2)
	{
		return NULL;
	}
	return t->fdt[fd];
}

void process_close_file(int fd)
{
	struct thread *t = thread_current();
	struct file *f = process_get_file(fd);
	if (f != NULL)
	{
		t->fdt[fd] = NULL;
	}
	file_close(f);
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page(void *upage, void *kpage, bool writable)
{
	struct thread *t = thread_current();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page(t->pml4, upage) == NULL && pml4_set_page(t->pml4, upage, kpage, writable));
}

struct thread *get_child_process(int pid)
{
	/* 자식 리스트에 접근하여 프로세스 디스크립터 검색 */
	struct thread *t = thread_current();
	struct list *children_list = &t->children;
	struct list_elem *e;
	int i;
	/* 해당 pid가 존재하면 프로세스 디스크립터 반환 */
	for (i = 0, e = list_begin(children_list);
			 i < list_size(children_list) && e != list_end(children_list);
			 i++, e = list_next(e))
	{
		struct thread *child_t = list_entry(e, struct thread, child_elem);
		if (child_t->tid == pid)
		{
			return child_t;
		}
	}
	/* 리스트에 존재하지 않으면 NULL 리턴 */
	return NULL;
}

void remove_child_process(struct thread *cp)
{
	struct thread *t = thread_current();
	struct list *children_list = &t->children;
	struct list_elem *e;
	int i;

	/* 자식 리스트에서 제거*/
	if (!list_empty(&children_list))
	{
		struct list_elem *curr = list_begin(&children_list);
		struct thread *curr_thread;
		while (list_end(&children_list) != curr)
		{
			curr_thread = list_entry(curr, struct thread, elem);
			if (curr_thread->tid == cp->tid)
			{
				curr = list_remove(curr);
				/* 프로세스 디스크립터 메모리 해제 */
				palloc_free_page(cp);
			}
			else
			{
				curr = list_next(curr);
			}
		}
	}
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment(struct page *page, void *aux)
{
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment(struct file *file, off_t ofs, uint8_t *upage,
						 uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
	ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT(pg_ofs(upage) == 0);
	ASSERT(ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0)
	{
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer(VM_ANON, upage,
																				writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack(struct intr_frame *if_)
{
	bool success = false;
	void *stack_bottom = (void *)(((uint8_t *)USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	return success;
}
#endif /* VM */

void argument_stack(int argc, char **argv, struct intr_frame *if_)
{
	/*
	argv : 프로그램 이름과 인자가 저장되어 있는 메모리 공간
	argc : 인자의 개수
	if_ : 스택 포인터를 가리키는 주소 값을 저장할 intr_frame
	*/

	char *arg_address[128]; //총 128개 저장가능

	/* 프로그램 이름 및 인자(문자열) push */
	for (int k = argc - 1; k > -1; k--) //뒤에서 부터 넣어주기
	{
		int argv_len = strlen(argv[k]);
		if_->rsp -= (argv_len + 1);
		memcpy(if_->rsp, argv[k], argv_len + 1); //메모리 카피해 주기
		arg_address[k] = if_->rsp;							 //해당 메모리 저장
	}

	/* Insert padding for word-align */
	while (if_->rsp % 8 != 0)
	{
		if_->rsp--;
		*(uint8_t *)(if_->rsp) = 0;
	}

	if_->rsp = if_->rsp - 8;
	*(int8_t *)if_->rsp = 0;

	/* 프로그램 이름 및 인자 주소들 push */
	for (int i = argc - 1; i >= 0; i--)
	{
		if_->rsp = if_->rsp - 8;
		memcpy(if_->rsp, &arg_address[i], sizeof(char **));
	}
	// strlcpy(thread_current()->name, *(&arg_address[0]), sizeof(char[16]));
	/* fake addr 0 넣어주기 */
	if_->rsp = if_->rsp - 8;
	*(int8_t *)if_->rsp = 0;

	if_->R.rdi = argc;				 /* 문자열의 개수 저장 */
	if_->R.rsi = if_->rsp + 8; /*  문자열을 가리키는 주소들의 배열을 가리킴 */
}
