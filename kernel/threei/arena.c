#include <asm/mmu_context.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mutex.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/threei.h>

static DEFINE_MUTEX(threei_arena_mutex);

/* vm_mmap operates on current->mm. borrow target cage's mm_struct prior */
static unsigned long threei_arena_map_into(struct task_struct *cage, size_t size)
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

	base = vm_mmap(NULL, 0, size, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, 0);

	task_lock(current);
	current->mm = old;
	current->active_mm = old;
	switch_mm(mm, old, current);
	task_unlock(current);
	mmput(mm);

	return IS_ERR_VALUE(base) ? 0 : base;
}

static void threei_arena_unmap_from(struct task_struct *cage, unsigned long base, size_t size) {
	struct mm_struct *mm, *old;

	if (!base || !size) {
		return;
	}

	mm = get_task_mm(cage);
	if (!mm) {
		return;
	}

	old = current->mm;
	task_lock(current);
	current->mm = mm;
	current->active_mm = mm;
	switch_mm(old, mm, current);
	task_unlock(current);

	vm_munmap(base, size);

	task_lock(current);
	current->mm = old;
	current->active_mm = old;
	switch_mm(mm, old, current);
	task_unlock(current);
	mmput(mm);
}

/* return the cage's arena base, creating (reserving) it on first use.
 * current may be the grate. Caller holds a reference on `cage`. */
unsigned long threei_arena_get(struct task_struct *cage, size_t need)
{
	struct threei_arena *arena;
	unsigned long base;
	size_t want = ALIGN(max_t(size_t, need, PAGE_SIZE), PAGE_SIZE);

	arena = READ_ONCE(cage->threei_arena);
	if (arena && arena->base && arena->size >= want) {
		return arena->base;
	}

	mutex_lock(&threei_arena_mutex);

	arena = cage->threei_arena;
	if (arena && arena->base && arena->size >= want) {
		base = arena->base;
		goto unlock;
	}
	if (!arena) {
		arena = kzalloc(sizeof(*arena), GFP_KERNEL);
		if (!arena) {
			goto unlock;
		}
		WRITE_ONCE(cage->threei_arena, arena);
	}
	if (arena->base) {
		threei_arena_unmap_from(cage, arena->base, arena->size);
		arena->base = 0; arena->size = 0;
	}

	base = threei_arena_map_into(cage, want);
	if (base) {
		arena->base = base;
		arena->size = want;
	}
unlock:
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
