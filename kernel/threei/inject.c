/* 3i injected syscall path */

/*
 * thread class syscalls like (fork/exec) must land in target's own
 * thread, so we set a pending injection on the target, force it to
 * return-to-user boundary with TIF_NOTIFY_RESUME + IPI, and let the
 * target's own thread execute the syscall.
 */

#include <linux/binfmts.h>
#include <linux/completion.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/threei.h>

bool threei_is_thread_op(u32 syscall_nr) {
    switch (syscall_nr) {
#ifdef __NR_fork
    case __NR_fork:
#endif
#ifdef __NR_execve
    case __NR_execve:
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

void threei_inject_put(struct threei_inject *inj) {
    if (refcount_dec_and_test(&inj->refs)) {
        kfree(inj);
    }
}

static void threei_free_vector(char **kvec) {
    int i;
    if (!kvec) {
        return;
    }

    for (i = 0; kvec[i]; i++) {
        kfree(kvec[i]);
    }
    kfree(kvec);
}

/*
 * Copy a NULL-terminated user vector (in the GRATE = current) into a
 * kernel vector of kernel strings. Bounded at both levels. Returns the
 * vector or ERR_PTR. A NULL uvec yields a NULL return (legal empty
 * vector).
 */
static char **
threei_copy_user_vector(const char __user *const __user *uvec,
                        int max_entries) {
    char **kvec;
    int n;

    if (!uvec) {
        return NULL;
    }

    kvec = kcalloc(max_entries + 1, sizeof(char *), GFP_KERNEL);
    if (!kvec) {
        return ERR_PTR(-ENOMEM);
    }

    for (n = 0; n < max_entries; n++) {
        const char __user *ustr;
        char *kstr;
        long len;

        if (get_user(ustr, uvec + n)) {
            threei_free_vector(kvec);
            return ERR_PTR(-EFAULT);
        }
        if (!ustr) {
            /* NULL terminatory */
            break;
        }

        kstr = kmalloc(PATH_MAX, GFP_KERNEL);
        if (!kstr) {
            threei_free_vector(kvec);
            return ERR_PTR(-ENOMEM);
        }

        len = strncpy_from_user(kstr, ustr, PATH_MAX);
        if (len < 0) {
            kfree(kstr);
            threei_free_vector(kvec);
            return ERR_PTR(-EFAULT);
        }
        if (len == PATH_MAX) {
            kfree(kstr);
            threei_free_vector(kvec);
            return ERR_PTR(-E2BIG);
        }

        kvec[n] = kstr;
    }

    if (n == max_entries) {
        threei_free_vector(kvec);
        return ERR_PTR(-E2BIG);
    }
    kvec[n] = NULL;
    return kvec;
}

/*
 * Build the execve arg bundle from the grate's user argv/envp pointers.
 * Called with current == grate. Returns an exec_args (caller frees with
 * threei_exec_args_free) or ERR_PTR.
 */
static struct threei_exec_args *
threei_exec_args_build(const char __user *upath,
                       const char __user *const __user *uargv,
                       const char __user *const __user *uenvp) {
    struct threei_exec_args *exec_args;
    long n;

    exec_args = kzalloc(sizeof(*exec_args), GFP_KERNEL);
    if (!exec_args) {
        return ERR_PTR(-ENOMEM);
    }

    n = strncpy_from_user(exec_args->path, upath, sizeof(exec_args->path));
    if (n < 0) {
        kfree(exec_args);
        return ERR_PTR(-EFAULT);
    }
    if (n == sizeof(exec_args->path)) {
        kfree(exec_args);
        return ERR_PTR(-ENAMETOOLONG);
    }

    exec_args->kargv = threei_copy_user_vector(uargv, NAME_MAX);
    if (IS_ERR(exec_args->kargv)) {
        long err = PTR_ERR(exec_args->kargv);
        exec_args->kargv = NULL;
        kfree(exec_args);
        return ERR_PTR(err);
    }
    exec_args->kenvp = threei_copy_user_vector(uenvp, NAME_MAX);
    if (IS_ERR(exec_args->kenvp)) {
        long err = PTR_ERR(exec_args->kenvp);
        exec_args->kenvp = NULL;
        threei_free_vector(exec_args->kargv);
        kfree(exec_args);
        return ERR_PTR(err);
    }

    return exec_args;
}

static void threei_exec_args_free(struct threei_exec_args *exec_args) {
    if (!exec_args) {
        return;
    }
    threei_free_vector(exec_args->kargv);
    threei_free_vector(exec_args->kenvp);
    kfree(exec_args);
}

/* runs in the target's context at return-to-user. curent == target.
 * Executes the pending injected syscall in the target's own thread */
void threei_notify_resume(struct pt_regs *regs) {
    struct threei_inject *inj = current->threei_inject;

    if (!inj || !inj->active) {
        return;
    }

    /* detach BEFORE we complete/return */
    current->threei_inject = NULL;
    smp_rmb();

    if (!READ_ONCE(inj->active)) {
        /* grate aborted before we ran; do nothing but release our ref. */
        threei_inject_put(inj);
        return;
    }

    switch (inj->nr) {
#ifdef __NR_fork
    case __NR_fork: {
        // struct pt_regs saved;
        struct kernel_clone_args kargs = {
            .flags = CLONE_AUTOREAP,
            .exit_signal = 0,
        };
        /* we don't need to restore regs here since they are never
         * mutated by the kernel_clone() */
        // saved = *regs;
        inj->ret = kernel_clone(&kargs);
        // *regs = saved;
        break;
    }
#endif
#ifdef __NR_execve
    case __NR_execve: {
        /*
         * execve runs in the TARGET's context (current == target). On
         * SUCCESS the target's image is replaced and control NEVER
         * returns here, so we must complete() the grate BEFORE the exec
         * or it would wait forever on a target that no longer exists.
         */
        static const char *const empty_envp[] = {NULL};
        struct threei_exec_args *exec_args = inj->exec_args;
        const char *path[2];
        const char *const *argv, *const *envp;
        long err;

        if (!exec_args) {
            inj->ret = -EINVAL;
            break;
        }
        path[0] = exec_args->path;
        /* NULL terminator since argv is a char ptr */
        path[1] = NULL;
        argv = exec_args->kargv ? (const char *const *)exec_args->kargv
                                : path;
        envp = exec_args->kenvp ? (const char *const *)exec_args->kenvp
                                : empty_envp;

        err = kernel_execve(exec_args->path, argv, envp);
        inj->active = false;
        inj->ret = err;
        complete(inj->done);
        break;
    }
#endif
#ifdef __NR_exit
    case __NR_exit: {
        int error_code = inj->args[0];
        inj->ret = 0;
        inj->active = false;
        complete(inj->done);
        threei_inject_put(inj);
        do_exit((error_code & 0xff) << 8);
    }
#endif
#ifdef __NR_exit_group
    case __NR_exit_group: {
        int error_code = inj->args[0];
        inj->ret = 0;
        inj->active = false;
        complete(inj->done);
        threei_inject_put(inj);
        do_group_exit((error_code & 0xff) << 8);
    }
#endif

    default:
        inj->ret = -ENOSYS;
        break;
    }

    inj->active = false;
    /* grate unblocks with the pid */
    complete(inj->done);
    threei_inject_put(inj);
}

/*
 * Arm an injected syscall on `target` and drive its own thread to run it.
 * Called from __route_current's thread-class branch. Blocks the grate
 * until the target runs the syscall (right after fork), then returns the
 * pid.
 */
long threei_inject_call(pid_t target, u32 syscall_nr,
                        unsigned long args[6]) {
    struct task_struct *task;
    struct threei_inject *inj;
    struct threei_exec_args *exec_args = NULL;
    struct completion done;
    long ret;

    task = find_get_task_by_vpid(target);
    if (!task) {
        return -ESRCH;
    }

    /* one injection in flight per target */
    if (READ_ONCE(task->threei_inject)) {
        put_task_struct(task);
        return -EBUSY;
    }

    inj = kzalloc(sizeof(*inj), GFP_KERNEL);
    if (!inj) {
        put_task_struct(task);
        return -ENOMEM;
    }

    inj->nr = syscall_nr;
    memcpy(inj->args, args, sizeof(inj->args));
    inj->active = true;
    init_completion(&done);
    inj->done = &done;
    refcount_set(&inj->refs, 2);

#ifdef __NR_execve
    if (syscall_nr == __NR_execve) {
        exec_args = threei_exec_args_build(
            (const char __user *)args[0],
            (const char __user *const __user *)args[1],
            (const char __user *const __user *)args[2]);
        if (IS_ERR(exec_args)) {
            ret = PTR_ERR(exec_args);
            exec_args = NULL;
            kfree(inj);
            put_task_struct(task);
            threei_exec_args_free(exec_args);
            return ret;
        }
        inj->exec_args = exec_args;
    }
#endif
    /*
     * publish the slot, then force the target to a return-to-user boundary
     */
    WRITE_ONCE(task->threei_inject, inj);
    set_tsk_thread_flag(task, TIF_NOTIFY_RESUME);
    /* IPI: pull it out of userspace promptly */
    set_notify_signal(task);
    wake_up_state(task, TASK_INTERRUPTIBLE);
    ret = wait_for_completion_interruptible(&done);
    if (ret == 0) {
        /* child pid (or -errno) */
        ret = inj->ret;
    } else {
        /* signaled before the hook ran: mark slot inactive & detach */
        WRITE_ONCE(inj->active, false);
        smp_wmb();
        WRITE_ONCE(task->threei_inject, NULL);
    }

    put_task_struct(task);
    /* drop grate's ref */
    threei_inject_put(inj);
    threei_exec_args_free(exec_args);
    return ret;
}
