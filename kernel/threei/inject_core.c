#include <asm/syscall.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/threei.h>

static void threei_seed_regs(struct pt_regs *regs, struct threei_inject *inj)
{
	regs->orig_ax = inj->nr;
	regs->ax = inj->nr; /* some paths read ax before orig_ax is used */
	regs->di = inj->args[0];
	regs->si = inj->args[1];
	regs->dx = inj->args[2];
	regs->r10 = inj->args[3];
	regs->r8 = inj->args[4];
	regs->r9 = inj->args[5];
}

static bool threei_inject_finish(struct threei_inject *inj, long ret)
{
	if (atomic_cmpxchg(&inj->completed, 0, 1) != 0) {
		return false;
	}

	inj->ret = ret;
	inj->active = false;
	complete(inj->done);
	threei_inject_put(inj);
	return true;
}

void threei_run_injected(struct threei_inject *inj)
{
	struct pt_regs *regs = current_pt_regs();
	struct pt_regs saved;
	bool is_exec, is_exit;

	is_exec = (inj->nr == __NR_execve
#ifdef __NR_execveat
		   || inj->nr == __NR_execveat
#endif
	);
	is_exit = (false
#ifdef __NR_exit
		   || inj->nr == __NR_exit
#endif
#ifdef __NR_exit_group
		   || inj->nr == __NR_exit_group
#endif
	);

	if (is_exec) {
		long err;

		threei_seed_regs(regs, inj);
		err = x64_sys_call(regs, inj->nr);
		/* only reached on pre-commit failure */
		threei_inject_finish(inj, err);
		return;
	}

	if (is_exit) {
		threei_seed_regs(regs, inj);
		threei_inject_finish(inj, 0);
		x64_sys_call(regs, inj->nr);
		return;
	}

	saved = *regs;
	threei_seed_regs(regs, inj);
	inj->ret = x64_sys_call(regs, inj->nr);
	*regs = saved;

	threei_inject_finish(inj, inj->ret);
}

void threei_notify_resume(struct pt_regs *regs)
{
	struct threei_inject *inj = current->threei_inject;

	if (!inj || !inj->active) {
		return;
	}

	current->threei_inject = NULL;
	smp_rmb();

	if (!READ_ONCE(inj->active)) {
		threei_inject_put(inj);
		return;
	}

	threei_run_injected(inj);
}
