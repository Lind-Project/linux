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
#ifdef __NR_futex
	case __NR_futex:
#endif
#ifdef __NR_futex_time32
	case __NR_futex_time32:
#endif
#ifdef __NR_futex_waitv
	case __NR_futex_waitv:
#endif
#ifdef __NR_futex_wait
	case __NR_futex_wait:
#endif
#ifdef __NR_futex_wake
	case __NR_futex_wake:
#endif
#ifdef __NR_futex_requeue
	case __NR_futex_requeue:
#endif
#ifdef __NR_set_robust_list
	case __NR_set_robust_list:
#endif
#ifdef __NR_get_robust_list
	case __NR_get_robust_list:
#endif
#ifdef __NR_rt_sigreturn
	case __NR_rt_sigreturn:
#endif
#ifdef __NR_rt_sigaction
	case __NR_rt_sigaction:
#endif
#ifdef __NR_rt_sigprocmask
	case __NR_rt_sigprocmask:
#endif
#ifdef __NR_rt_sigpending
	case __NR_rt_sigpending:
#endif
#ifdef __NR_rt_sigsuspend
	case __NR_rt_sigsuspend:
#endif
#ifdef __NR_rt_sigtimedwait
	case __NR_rt_sigtimedwait:
#endif
#ifdef __NR_rt_sigtimedwait_time64
	case __NR_rt_sigtimedwait_time64:
#endif
#ifdef __NR_sigaltstack
	case __NR_sigaltstack:
#endif
#ifdef __NR_rt_sigqueueinfo
	case __NR_rt_sigqueueinfo:
#endif
#ifdef __NR_rt_tgsigqueueinfo
	case __NR_rt_tgsigqueueinfo:
#endif
#ifdef __NR_kill
	case __NR_kill:
#endif
#ifdef __NR_tkill
	case __NR_tkill:
#endif
#ifdef __NR_tgkill
	case __NR_tgkill:
#endif
#ifdef __NR_pidfd_send_signal
	case __NR_pidfd_send_signal:
#endif
#ifdef __NR_signalfd4
	case __NR_signalfd4:
#endif
#ifdef __NR_signalfd
	case __NR_signalfd:
#endif

#ifdef __NR_setuid
	case __NR_setuid:
#endif
#ifdef __NR_setgid
	case __NR_setgid:
#endif
#ifdef __NR_setreuid
	case __NR_setreuid:
#endif
#ifdef __NR_setregid
	case __NR_setregid:
#endif
#ifdef __NR_setresuid
	case __NR_setresuid:
#endif
#ifdef __NR_setresgid
	case __NR_setresgid:
#endif
#ifdef __NR_setfsuid
	case __NR_setfsuid:
#endif
#ifdef __NR_setfsgid
	case __NR_setfsgid:
#endif
#ifdef __NR_setgroups
	case __NR_setgroups:
#endif
#ifdef __NR_capset
	case __NR_capset:
#endif
#ifdef __NR_setpgid
	case __NR_setpgid:
#endif
#ifdef __NR_setsid
	case __NR_setsid:
#endif

#ifdef __NR_ptrace
	case __NR_ptrace:
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
		clear_notify_signal();
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
	{
		struct threei_request *fwd = READ_ONCE(task->threei_fwd_req);
		if (fwd == THREEI_FWD_SPIN) {
			/* ring spinner: drains itself, needs no wake */
		} else if (fwd) {
			complete(&fwd->done);
		} else {
			set_tsk_thread_flag(task, TIF_NOTIFY_THREEI);
			/* out-of-band: break a foreign sleep */
			set_notify_signal(task);
		}
	}
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
