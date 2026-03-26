#include "syscall.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"

uint64 sys_write(int fd, uint64 va, uint len)
{
	debugf("sys_write fd = %d va = %x, len = %d", fd, va, len);
	if (fd != STDOUT)
		return -1;
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	int size = copyinstr(p->pagetable, str, va, MIN(len, MAX_STR_LEN));
	debugf("size = %d", size);
	for (int i = 0; i < size; ++i) {
		console_putchar(str[i]);
	}
	return size;
}

__attribute__((noreturn)) void sys_exit(int code)
{
	exit(code);
	__builtin_unreachable();
}

uint64 sys_sched_yield()
{
	yield();
	return 0;
}

uint64 sys_gettimeofday(TimeVal *val, int _tz)
{
	struct proc *p = curr_proc();
	TimeVal now;
	uint64 cycle = get_cycle();

	// The result is prepared in kernel memory, then copied to the
	// user virtual address through the current process page table.
	now.sec = cycle / CPU_FREQ;
	now.usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;
	if (copyout(p->pagetable, (uint64)val, (char *)&now, sizeof(now)) < 0)
		return -1;
	return 0;
}

uint64 sys_task_info(TaskInfo *ti)
{
	if (ti == 0)
		return -1;

	struct proc *p = curr_proc();
	TaskInfo info;
	uint64 now = get_cycle();
	uint64 elapsed_cycles = (p->start_time == 0) ? 0 : (now - p->start_time);

	// Like gettimeofday, ti is a user VA, so we must return it with copyout.
	info.status = Running;
	memmove(info.syscall_times, p->syscall_times, sizeof(info.syscall_times));
	info.time = (int)(elapsed_cycles * 1000 / CPU_FREQ);
	if (copyout(p->pagetable, (uint64)ti, (char *)&info, sizeof(info)) < 0)
		return -1;
	return 0;
}

static int vm_port_to_perm(int port)
{
	int perm = PTE_U;

	// User port bits map to page-table R/W/X bits; PTE_U is always required.
	if (port & 0x1)
		perm |= PTE_R;
	if (port & 0x2)
		perm |= PTE_W;
	if (port & 0x4)
		perm |= PTE_X;
	return perm;
}

static int range_has_mapped_page(pagetable_t pagetable, uint64 start, uint64 len)
{
	for (uint64 va = start; va < start + len; va += PGSIZE) {
		pte_t *pte = walk(pagetable, va, 0);

		if (pte != 0 && (*pte & PTE_V) != 0)
			return 1;
	}
	return 0;
}

static int range_has_unmapped_page(pagetable_t pagetable, uint64 start, uint64 len)
{
	for (uint64 va = start; va < start + len; va += PGSIZE) {
		pte_t *pte = walk(pagetable, va, 0);

		if (pte == 0 || (*pte & PTE_V) == 0 || (*pte & PTE_U) == 0)
			return 1;
		if ((*pte & (PTE_R | PTE_W | PTE_X)) == 0)
			return 1;
	}
	return 0;
}

uint64 sys_mmap(void *start, uint64 len, int port, int flag, int fd)
{
	(void)flag;
	(void)fd;

	struct proc *p = curr_proc();
	uint64 va = (uint64)start;
	uint64 map_len;
	uint64 end_page;
	int perm;

	if (len == 0)
		return 0;
	if (!PGALIGNED(va) || len > (1ULL << 30))
		return -1;
	if ((port & ~0x7) != 0 || (port & 0x7) == 0)
		return -1;

	map_len = PGROUNDUP(len);
	if (va >= TRAPFRAME || map_len > TRAPFRAME - va)
		return -1;
	if (range_has_mapped_page(p->pagetable, va, map_len))
		return -1;

	perm = vm_port_to_perm(port);
	// Anonymous mmap does not require contiguous physical memory, so we
	// allocate and map one page at a time.
	for (uint64 a = va; a < va + map_len; a += PGSIZE) {
		void *pa = kalloc();

		if (pa == 0)
			return -1;
		if (mappages(p->pagetable, a, PGSIZE, (uint64)pa, perm) != 0)
			return -1;
	}

	end_page = (va + map_len) / PGSIZE;
	if (end_page > p->max_page)
		p->max_page = end_page;
	return 0;
}

uint64 sys_munmap(void *start, uint64 len)
{
	struct proc *p = curr_proc();
	uint64 va = (uint64)start;
	uint64 unmap_len;

	if (len == 0)
		return 0;
	if (!PGALIGNED(va) || len > (1ULL << 30))
		return -1;

	unmap_len = PGROUNDUP(len);
	if (va >= TRAPFRAME || unmap_len > TRAPFRAME - va)
		return -1;
	if (range_has_unmapped_page(p->pagetable, va, unmap_len))
		return -1;

	// The range is already validated, so we can remove it page by page.
	uvmunmap(p->pagetable, va, unmap_len / PGSIZE, 1);
	return 0;
}

extern char trap_page[];

void syscall()
{
	struct trapframe *trapframe = curr_proc()->trapframe;
	int id = trapframe->a7, ret;
	uint64 args[6] = { trapframe->a0, trapframe->a1, trapframe->a2,
			   trapframe->a3, trapframe->a4, trapframe->a5 };
	tracef("syscall %d args = [%x, %x, %x, %x, %x, %x]", id, args[0],
	       args[1], args[2], args[3], args[4], args[5]);
	/*
	* LAB1: you may need to update syscall counter for task info here
	*/
	struct proc *p = curr_proc();
	if (id >= 0 && id < MAX_SYSCALL_NUM)
		p->syscall_times[id]++;
	// a7 selects the syscall, a0-a5 carry arguments, and the return value
	// is written back to a0 before returning to user mode.
	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
	case SYS_sched_yield:
		ret = sys_sched_yield();
		break;
	case SYS_gettimeofday:
		ret = sys_gettimeofday((TimeVal *)args[0], args[1]);
		break;
	case SYS_task_info:
		ret = sys_task_info((TaskInfo *)args[0]);
		break;
	case SYS_mmap:
		ret = sys_mmap((void *)args[0], args[1], args[2], args[3], args[4]);
		break;
	case SYS_munmap:
		ret = sys_munmap((void *)args[0], args[1]);
		break;
	default:
		ret = -1;
		errorf("unknown syscall %d", id);
	}
	trapframe->a0 = ret;
	tracef("syscall ret %d", ret);
}
