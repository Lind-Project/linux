#include <asm/mmu_context.h>
#include <asm/pgtable.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mutex.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/threei.h>
#include <linux/highmem.h>

#ifndef THREEI_ARENA_SIZE
#define THREEI_ARENA_SIZE (64 * PAGE_SIZE)
#endif

#define THREEI_ARENA_PGPROT                                                \
	__pgprot(_PAGE_PRESENT | _PAGE_RW | _PAGE_ACCESSED | _PAGE_DIRTY | \
		 _PAGE_NX)

#define THREEI_ARENA_VMFLAGS \
	(VM_MIXEDMAP | VM_DONTEXPAND | VM_DONTDUMP | VM_DONTCOPY | VM_IO)

static DEFINE_MUTEX(threei_arena_mutex);

/* install one kernel page at a cage VA as a supervisor-only by clearing U/S bit */
static unsigned long threei_arena_install(struct mm_struct *mm,
					  unsigned long addr, struct page *pg)
{
	spinlock_t *ptl;
	pte_t *pte;

	/* perform page walk to pmd to fetch pte and acquires a ptl lock
	 * in struct ptdesc */
	pte = get_locked_pte(mm, addr, &ptl);
	if (!pte) {
		return -ENOMEM;
	}
	if (!pte_none(ptep_get(pte))) {
		pte_unmap_unlock(pte, ptl);
		return -EBUSY;
	}
	/* maps consecutive pages starting from the arena base to a
	 * contiguous range of addresses in cage's mm */
	set_pte_at(
		mm, addr, pte,
		pte_mkspecial(pfn_pte(page_to_pfn(pg), THREEI_ARENA_PGPROT)));
	pte_unmap_unlock(pte, ptl);
	return 0;
}

static unsigned long threei_arena_map_into(struct task_struct *cage,
					   size_t size,
					   struct page ***pages_out,
					   unsigned long *npages_out)
{
	struct mm_struct *mm, *old;
	struct vm_area_struct *vma;
	struct page **pages;
	unsigned long base, npages, i;

	npages = size >> PAGE_SHIFT;
	pages = kcalloc(npages, sizeof(*pages), GFP_KERNEL);
	if (!pages) {
		return 0;
	}
	for (i = 0; i < npages; i++) {
		pages[i] = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!pages[i]) {
			goto free_pages;
		}
	}

	mm = get_task_mm(cage);
	if (!mm) {
		goto free_pages;
	}

	old = current->mm;
	task_lock(current);
	current->mm = mm;
	current->active_mm = mm;
	switch_mm(old, mm, current);
	task_unlock(current);

	/* PROT_NONE: user access to the window is a clean SIGSEGV */
	base = vm_mmap(NULL, 0, size, PROT_NONE,
		       MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, 0);
	if (IS_ERR_VALUE(base)) {
		goto restore;
	}

	mmap_write_lock(mm);
	vma = find_vma(mm, base);
	if (!vma || vma->vm_start > base) {
		mmap_write_unlock(mm);
		vm_munmap(base, size);
		base = 0;
		goto restore;
	}

	vm_flags_set(vma, THREEI_ARENA_VMFLAGS);
	for (i = 0; i < npages; i++) {
		if (threei_arena_install(mm, base + (i << PAGE_SHIFT),
					 pages[i])) {
			mmap_write_unlock(mm);
			vm_munmap(base, size);
			base = 0;
			goto restore;
		}
	}
	mmap_write_unlock(mm);

restore:
	task_lock(current);
	current->mm = old;
	current->active_mm = old;
	switch_mm(mm, old, current);
	task_unlock(current);
	mmput(mm);

	if (!base) {
		goto free_pages;
	}

	*pages_out = pages;
	*npages_out = npages;
	return base;

free_pages:
	for (i = 0; i < npages; i++) {
		if (pages[i]) {
			__free_page(pages[i]);
		}
	}
	kfree(pages);
	return 0;
}

static void threei_arena_drop(struct task_struct *cage,
			      struct threei_arena *arena)
{
	struct mm_struct *mm, *old;
	unsigned long i;

	if (arena->base && (mm = get_task_mm(cage))) {
		old = current->mm;
		task_lock(current);
		current->mm = mm;
		current->active_mm = mm;
		switch_mm(old, mm, current);
		task_unlock(current);

		vm_munmap(arena->base, arena->size);

		task_lock(current);
		current->mm = old;
		current->active_mm = old;
		switch_mm(mm, old, current);
		task_unlock(current);
		mmput(mm);
	}

	for (i = 0; i < arena->npages; i++) {
		if (arena->pages[i]) {
			__free_page(arena->pages[i]);
		}
	}
	kfree(arena->pages);
	arena->pages = NULL;
	arena->npages = 0;
	arena->base = 0;
	arena->size = 0;
}

/* return the cage's arena base, creating (reserving) it on first use.
 * current may be the grate. caller holds a reference on `cage`. */
unsigned long threei_arena_get(struct task_struct *cage, size_t need)
{
	struct threei_arena *arena;
	struct page **pages = NULL;
	unsigned long base, npages = 0;
	size_t want = ALIGN(max_t(size_t, need, THREEI_ARENA_SIZE), PAGE_SIZE);

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
			base = 0;
			goto unlock;
		}
		WRITE_ONCE(cage->threei_arena, arena);
	}
	if (arena->base) {
		threei_arena_drop(cage, arena);
	}

	base = threei_arena_map_into(cage, want, &pages, &npages);
	if (base) {
		arena->base = base;
		arena->size = want;
		arena->pages = pages;
		arena->npages = npages;
	}
unlock:
	mutex_unlock(&threei_arena_mutex);
	return base;
}

long threei_arena_write(struct threei_arena *arena, unsigned long at,
			const void *src, size_t len)
{
	const char *src_buf = src;
	unsigned long offset;

	if (!arena || at < arena->base) {
		return -EFAULT;
	}
	offset = at - arena->base;
	if (offset + len > arena->size) {
		return -EFAULT;
	}

	while (len) {
		unsigned long pi = offset >> PAGE_SHIFT;
		unsigned long po = offset & (PAGE_SIZE - 1);
		size_t chunk = min(len, (size_t)(PAGE_SIZE - po));
		/* temporarily map arena->page to VA for copying resolved arg from
		 * kbuf to arena->page */
		void *kmap = kmap_local_page(arena->pages[pi]);

		memcpy(kmap + po, src_buf, chunk);
		kunmap_local(kmap);

		src_buf += chunk;
		offset += chunk;
		len -= chunk;
	}
	return 0;
}

void threei_arena_free(struct task_struct *task)
{
	struct threei_arena *arena = task->threei_arena;

	if (!arena) {
		return;
	}
	task->threei_arena = NULL;

	/* the VA window lives in task's own mm, torn down by exit_mm on the exit
	 * path (which zaps the special PIEs without freeing pages). free the
	 * kernel owned backing pages and the tracker here */
	if (arena->pages) {
		unsigned long i;

		for (i = 0; i < arena->npages; i++) {
			if (arena->pages[i]) {
				__free_page(arena->pages[i]);
			}
		}
		kfree(arena->pages);
	}
	kfree(arena);
}
