#include <linux/sched.h>
#include <linux/sched/prio.h>
#include <linux/threei.h>

/* RT priorities */
#define THREEI_GRATE_RT_PRIO 99
#define THREEI_CAGE_RT_PRIO 1

static int threei_set_rr(struct task_struct *task, int prio) {
    struct sched_param sp = {.sched_priority = prio};

    return sched_setscheduler_nocheck(task, SCHED_RR | SCHED_RESET_ON_FORK,
                                      &sp);
}

int threei_promote_grate(struct task_struct *grate) {
    if (!grate) {
        return -ESRCH;
    }

    return threei_set_rr(grate, THREEI_GRATE_RT_PRIO);
}

void threei_set_cage_sched(struct task_struct *cage) {
    if (!cage) {
        return;
    }

    if (threei_set_rr(cage, THREEI_CAGE_RT_PRIO) == 0) {
        return;
    }

    threei_set_cfs(cage);
}

void threei_set_cfs(struct task_struct *task) {
    struct sched_param sp = {.sched_priority = 0};
    int policy;

    if (!task) {
        return;
    }

    policy = task->policy;
    if (policy == SCHED_FIFO || policy == SCHED_RR) {
        sched_setscheduler_nocheck(task, SCHED_NORMAL, &sp);
    }
}
