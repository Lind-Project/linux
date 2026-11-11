#include <linux/sched.h>
#include <linux/threei.h>
#include <linux/threei_types.h>

/* exec hook */
void threei_exec_commit_notify(void)
{
	struct threei_inject *inj = current->threei_inject;

	if (!inj)
		return;
	if (inj->nr != __NR_execve
#ifdef __NR_execveat
	    && inj->nr != __NR_execveat
#endif
	)
		return;

	/* claim: only the single winner completes + puts + detaches */
	if (atomic_cmpxchg(&inj->completed, 0, 1) != 0)
		return;

	current->threei_inject = NULL;
	inj->ret = 0;
	inj->active = false;
	complete(inj->done);
	threei_inject_put(inj);
}

/* identity hook */
bool threei_is_identity_op(u32 syscall_nr)
{
	switch (syscall_nr) {
	case __NR_getpid:
	case __NR_gettid:
	case __NR_getppid:
	case __NR_getpgid:
	case __NR_getsid:
		return true;
	default:
		return false;
	}
}

long threei_run_identity_op(pid_t target_cage, u32 syscall_nr, unsigned long args[6]) {
	struct threei_ctx_borrow borrow = {};
	struct task_struct *cage;
	long ret;

	cage = find_get_task_by_vpid(target_cage);
	if (!cage) {
		return -ESRCH;
	}

	borrow.id_cage = cage;
	current->threei_ctx_borrow = &borrow;
	ret = native_syscall(syscall_nr, args);
	current->threei_ctx_borrow = NULL;

	put_task_struct(cage);
	return ret;
}

bool threei_identity_override(enum threei_idtype type, pid_t *out) {
	struct threei_ctx_borrow *borrow = current->threei_ctx_borrow;
	struct task_struct *cage = borrow ? borrow->id_cage : NULL;

	if (!cage) {
		return false;
	}

	rcu_read_lock();
	switch (type) {
		case THREEI_ID_GETPID:
			*out = task_tgid_vnr(cage);
			break;
		case THREEI_ID_GETTID:
			*out = task_pid_vnr(cage);
			break;
		case THREEI_ID_GETPPID:
			*out = task_tgid_vnr(rcu_dereference(cage->real_parent));
			break;
		case THREEI_ID_GETPGID:
			*out = task_pgrp_vnr(cage);
			break;
		case THREEI_ID_GETSID:
			*out = task_session_vnr(cage);
			break;
		default:
			rcu_read_unlock();
			return false;
	}
	rcu_read_unlock();
	return true;
}

struct task_struct *threei_identity_task(void)
{
	struct threei_ctx_borrow *b = current->threei_ctx_borrow;

	return (b && b->id_cage) ? b->id_cage : current;
}
