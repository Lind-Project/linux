#include <asm/mmu_context.h>
#include <asm/syscall.h>
#include <linux/fdtable.h>
#include <linux/fs_struct.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mutex.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/threei.h>

struct threei_ctx_borrow {
	const struct cred *cage_cred;
	struct mm_struct *cage_mm;
	struct files_struct *cage_files;
	struct fs_struct *cage_fs;
	struct nsproxy *cage_nsproxy;

	const struct cred *old_cred;
	struct mm_struct *old_mm;
	struct files_struct *old_files;
	struct fs_struct *old_fs;
	struct nsproxy *old_nsproxy;
};

static bool ctx_borrow_cred(struct threei_ctx_borrow *borrow,
			    struct task_struct *cage)
{
	const struct cred *cred = get_task_cred(cage);

	if (!cred) {
		return false;
	}

	borrow->old_cred = current_cred();
	rcu_assign_pointer(current->cred, cred);
	borrow->cage_cred = cred;
	return true;
}

static void ctx_restore_cred(struct threei_ctx_borrow *borrow)
{
	if (!borrow->cage_cred) {
		return;
	}

	rcu_assign_pointer(current->cred, borrow->old_cred);
	put_cred(borrow->cage_cred);
	borrow->cage_cred = NULL;
}

/* mm: get_task_mm pins; switch_mm installs. Mirrors threei_run_mm_op. */
static bool ctx_borrow_mm(struct threei_ctx_borrow *borrow,
			  struct task_struct *cage)
{
	struct mm_struct *mm = get_task_mm(cage);
	if (!mm) {
		return false;
	}

	borrow->old_mm = current->mm;
	task_lock(current);
	current->mm = mm;
	current->active_mm = mm;
	switch_mm(borrow->old_mm, mm, current);
	task_unlock(current);
	borrow->cage_mm = mm;
	return true;
}

static void ctx_restore_mm(struct threei_ctx_borrow *borrow)
{
	if (!borrow->cage_mm) {
		return;
	}

	task_lock(current);
	current->mm = borrow->old_mm;
	current->active_mm = borrow->old_mm;
	switch_mm(borrow->cage_mm, borrow->old_mm, current);
	task_unlock(current);
	mmput(borrow->cage_mm);
	borrow->cage_mm = NULL;
}

static bool ctx_borrow_files(struct threei_ctx_borrow *borrow,
			     struct task_struct *cage)
{
	struct files_struct *files = NULL;

	task_lock(cage);
	files = cage->files;
	if (files) {
		atomic_inc(&files->count);
	}
	task_unlock(cage);

	if (!files) {
		return false;
	}

	task_lock(current);
	borrow->old_files = current->files;
	current->files = files;
	task_unlock(current);
	borrow->cage_files = files;
	return true;
}

static void ctx_restore_files(struct threei_ctx_borrow *borrow)
{
	if (!borrow->cage_files) {
		return;
	}

	task_lock(current);
	current->files = borrow->old_files;
	task_unlock(current);
	put_files_struct(borrow->cage_files);
	borrow->cage_files = NULL;
}

static bool ctx_borrow_fs(struct threei_ctx_borrow *borrow,
			  struct task_struct *cage)
{
	struct fs_struct *fs = NULL;

	task_lock(cage);
	fs = cage->fs;
	if (fs) {
		read_seqlock_excl(&fs->seq);
		fs->users++;
		read_sequnlock_excl(&fs->seq);
	}
	task_unlock(cage);

	if (!fs) {
		return false;
	}

	task_lock(current);
	borrow->old_fs = current->fs;
	current->fs = fs;
	task_unlock(current);
	borrow->cage_fs = fs;
	return true;
}

static void ctx_restore_fs(struct threei_ctx_borrow *borrow)
{
	int kill;

	if (!borrow->cage_fs) {
		return;
	}
	task_lock(current);
	current->fs = borrow->old_fs;
	task_unlock(current);

	read_seqlock_excl(&borrow->cage_fs->seq);
	kill = !--borrow->cage_fs->users;
	read_sequnlock_excl(&borrow->cage_fs->seq);
	if (kill) {
		free_fs_struct(borrow->cage_fs);
	}

	borrow->cage_fs = NULL;
}

static bool ctx_borrow_nsproxy(struct threei_ctx_borrow *borrow,
			       struct task_struct *cage)
{
	struct nsproxy *ns = NULL;

	task_lock(cage);
	ns = cage->nsproxy;
	if (ns) {
		get_nsproxy(ns);
	}
	task_unlock(cage);

	if (!ns) {
		return false;
	}

	task_lock(current);
	borrow->old_nsproxy = current->nsproxy;
	current->nsproxy = ns;
	task_unlock(current);
	borrow->cage_nsproxy = ns;
	return true;
}

static void ctx_restore_nsproxy(struct threei_ctx_borrow *borrow)
{
	if (!borrow->cage_nsproxy) {
		return;
	}

	task_lock(current);
	current->nsproxy = borrow->old_nsproxy;
	task_unlock(current);
	put_nsproxy(borrow->cage_nsproxy);
	borrow->cage_nsproxy = NULL;
}

static void ctx_restore_all(struct threei_ctx_borrow *borrow)
{
	ctx_restore_nsproxy(borrow);
	ctx_restore_fs(borrow);
	ctx_restore_files(borrow);
	ctx_restore_mm(borrow);
	ctx_restore_cred(borrow);
}

void threei_ctx_restore_emergency(struct task_struct *grate)
{
	struct threei_ctx_borrow *borrow;

	if (grate != current) {
		return;
	}

	borrow = current->threei_ctx_borrow;
	if (!borrow) {
		return;
	}
	current->threei_ctx_borrow = NULL;
	ctx_restore_all(borrow);
}

long threei_run_in_cage_ctx(pid_t target_cage, u32 syscall_nr,
			    unsigned long args[6])
{
	struct threei_ctx_borrow borrow = {};
	struct task_struct *cage;
	struct pt_regs scratch;
	long ret;

	if (syscall_nr >= NR_syscalls) {
		return -ENOSYS;
	}

	if (threei_is_thread_op(syscall_nr)) {
		return -ENOTSUPP;
	}

	cage = find_get_task_by_vpid(target_cage);
	if (!cage) {
		return -ESRCH;
	}
	if (cage->flags & PF_EXITING) {
		put_task_struct(cage);
		return -ESRCH;
	}

	if (!ctx_borrow_cred(&borrow, cage)) {
		ret = -ESRCH;
		goto out_restore;
	}
	if (!ctx_borrow_mm(&borrow, cage)) {
		ret = -ESRCH;
		goto out_restore;
	}
	if (!ctx_borrow_files(&borrow, cage)) {
		ret = -ESRCH;
		goto out_restore;
	}
	if (!ctx_borrow_fs(&borrow, cage)) {
		ret = -ESRCH;
		goto out_restore;
	}
	if (!ctx_borrow_nsproxy(&borrow, cage)) {
		ret = -ESRCH;
		goto out_restore;
	}

	current->threei_ctx_borrow = &borrow;

	/* publish so threei_exit can unwind us if the grate is killed while
	 * blocked in the dispatch below. */
	current->threei_ctx_borrow = &borrow;

	/* Build a scratch pt_regs holding just nr + args. x64_sys_call reads
	 * the 6 args from here; the grate's real regs are untouched. */
	memset(&scratch, 0, sizeof(scratch));
	scratch.orig_ax = syscall_nr;
	scratch.di = args[0];
	scratch.si = args[1];
	scratch.dx = args[2];
	scratch.r10 = args[3];
	scratch.r8 = args[4];
	scratch.r9 = args[5];

	ret = x64_sys_call(&scratch, syscall_nr);

	current->threei_ctx_borrow = NULL;

out_restore:
	ctx_restore_all(&borrow);
	put_task_struct(cage);
	return ret;
}
