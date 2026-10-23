#include <asm/mmu_context.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mutex.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/threei.h>

#ifndef THREEI_ARENA_SIZE
#define THREEI_ARENA_SIZE (64 * PAGE_SIZE)
#endif

static DEFINE_MUTEX(threei_arena_mutex);

/* vm_mmap operates on current->mm. borrow target cage's mm_struct prior */
static unsigned long threei_arena_map_into(struct task_struct *cage)
{
	struct mm_struct *mm, *old;
	unsigned long base;

	mm = get_task_mm(cage);
	if (!mm) {
		return 0;
	}

	old = current->mm;
	task_lock(current);
	current->mm = mm;
	current->active_mm = mm;
	switch_mm(old, mm, current);
	task_unlock(current);

	base = vm_mmap(NULL, 0, THREEI_ARENA_SIZE, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, 0);

	task_lock(current);
	current->mm = old;
	current->active_mm = old;
	switch_mm(mm, old, current);
	task_unlock(current);
	mmput(mm);

	return IS_ERR_VALUE(base) ? 0 : base;
}

/* return the cage's arena base, creating (reserving) it on first use.
 * current may be the grate. Caller holds a reference on `cage`. */
unsigned long threei_arena_get(struct task_struct *cage)
{
	struct threei_arena *arena;
	unsigned long base;

	arena = READ_ONCE(cage->threei_arena);
	if (arena && arena->base) {
		return arena->base;
	}

	mutex_lock(&threei_arena_mutex);

	arena = cage->threei_arena;
	if (arena && arena->base) {
		mutex_unlock(&threei_arena_mutex);
		return arena->base;
	}

	if (!arena) {
		arena = kzalloc(sizeof(*arena), GFP_KERNEL);
		if (!arena) {
			mutex_unlock(&threei_arena_mutex);
			return 0;
		}
		arena->size = THREEI_ARENA_SIZE;
		WRITE_ONCE(cage->threei_arena, arena);
	}

	base = threei_arena_map_into(cage);
	if (base) {
		WRITE_ONCE(arena->base, base);
	}
	mutex_unlock(&threei_arena_mutex);
	return base;
}

void threei_arena_free(struct task_struct *task)
{
	struct threei_arena *arena = task->threei_arena;

	if (!arena) {
		return;
	}
	task->threei_arena = NULL;

	/* no vm_munmap here: torn down by exit_mm on the exit path */
	/* just free the tracker */
	kfree(arena);
}

SYSCALL_DEFINE1(threei_arena_setup, pid_t, cageid)
{
	struct task_struct *cage;
	unsigned long base;

	cage = find_get_task_by_vpid(cageid);
	if (!cage) {
		return -ESRCH;
	}
	if (cage->flags & PF_EXITING) {
		put_task_struct(cage);
		return -ESRCH;
	}

	base = threei_arena_get(cage);
	put_task_struct(cage);

	return base ? (long)base : -ENOMEM;
}
