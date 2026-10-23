#include <linux/completion.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/threei.h>

bool threei_is_thread_op(u32 syscall_nr)
{
	switch (syscall_nr) {
#ifdef __NR_fork
	case __NR_fork:
#endif
#ifdef __NR_vfork
	case __NR_vfork:
#endif
#ifdef __NR_clone
	case __NR_clone:
#endif
#ifdef __NR_clone3
	case __NR_clone3:
#endif
#ifdef __NR_execve
	case __NR_execve:
#endif
#ifdef __NR_execveat
	case __NR_execveat:
#endif
#ifdef __NR_rt_sigreturn
	case __NR_rt_sigreturn:
#endif
#ifdef __NR_exit
	case __NR_exit:
#endif
#ifdef __NR_exit_group
	case __NR_exit_group:
#endif
		return true;
	default:
		return false;
	}
}

void threei_inject_put(struct threei_inject *inject)
{
	if (refcount_dec_and_test(&inject->refs)) {
		kfree(inject);
	}
}

/* Service a pending injection from a cage that is blocked forwarding a
 * syscall and has just discovered the grate injected one back at it (the
 * generalized circular-wait break-out). current == cage, so the injected
 * syscall lands on the right thread. */
bool threei_drain_injection(unsigned long self_nr, unsigned long args[6],
			    bool *run_native)
{
	struct threei_inject *inject = READ_ONCE(current->threei_inject);

	*run_native = false;

	if (!inject || !READ_ONCE(inject->active)) {
		return false;
	}

	if (inject->nr == self_nr) {
		current->threei_inject = NULL;
		smp_rmb();
		memcpy(args, inject->args, sizeof(inject->args));
		/* finish the slot exactly once (interlock with any other path) */
		if (atomic_cmpxchg(&inject->completed, 0, 1) == 0) {
			inject->ret = 0;
			inject->active = false;
			complete(inject->done);
			threei_inject_put(inject);
		}
		*run_native = true;
		return true;
	}

	current->threei_inject = NULL;
	smp_rmb();
	threei_run_injected(inject);
	return true;
}

long threei_inject_call(pid_t target, u32 syscall_nr, unsigned long args[6])
{
	struct task_struct *task;
	struct threei_inject *inject;
	struct completion done;
	long ret;

	task = find_get_task_by_vpid(target);
	if (!task) {
		return -ESRCH;
	}

	if (READ_ONCE(task->threei_inject)) {
		put_task_struct(task);
		return -EBUSY;
	}

	inject = kzalloc(sizeof(*inject), GFP_KERNEL);
	if (!inject) {
		put_task_struct(task);
		return -ENOMEM;
	}

	inject->nr = syscall_nr;
	memcpy(inject->args, args, sizeof(inject->args));
	inject->active = true;
	atomic_set(&inject->completed, 0);
	init_completion(&done);
	inject->done = &done;
	/* one for the target, one for us */
	refcount_set(&inject->refs, 2);

	/* publish the slot, then force the target to a return-to-user boundary */
	WRITE_ONCE(task->threei_inject, inject);
	set_tsk_thread_flag(task, TIF_NOTIFY_RESUME);
	set_notify_signal(task);
	wake_up_state(task, TASK_INTERRUPTIBLE);

	ret = wait_for_completion_interruptible(&done);
	if (ret == 0) {
		ret = inject->ret;
	} else {
		/* signaled before the target ran. claim the slot via the
		 * interlock so a late run/commit path can't double-complete */
		if (atomic_cmpxchg(&inject->completed, 0, 1) == 0) {
			WRITE_ONCE(inject->active, false);
			smp_wmb();
			WRITE_ONCE(task->threei_inject, NULL);
		} else {
			ret = inject->ret;
		}
	}

	put_task_struct(task);
	/* drop our ref */
	threei_inject_put(inject);
	return ret;
}
