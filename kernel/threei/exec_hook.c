#include <linux/sched.h>
#include <linux/threei.h>

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
