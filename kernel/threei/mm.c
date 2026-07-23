#include <asm/mmu_context.h>
#include <linux/mman.h>
#include <linux/sched/mm.h>
#include <linux/threei.h>

/*
 * threei_is_mm_op(u32 nr) - memory mapping operations that
 * can be run against targted cage's mm by borrowing it.
 */
bool threei_is_mm_op(u32 nr) {
    switch (nr) {
#ifdef __NR_munmap
    case __NR_munmap:
#endif
#ifdef __NR_mprotect
    case __NR_mprotect:
#endif
#ifdef __NR_pkey_mprotect
    case __NR_pkey_mprotect:
#endif
#ifdef __NR_madvise
    case __NR_madvise:
#endif
#ifdef __NR_mmap
    case __NR_mmap:
#endif
#ifdef __NR_mremap
    case __NR_mremap:
#endif
        return true;
    default:
        return false;
    }
}

/* Executes system calls performing memory mapping operation in
 * target cage's address space. It replaces current->mm with target's
 * mm and performs system call in the target's address space. Restores
 * mm post-operation to resume grate execution without causing faultis.
 * current is grate here. */
long threei_run_mm_op(u32 nr, pid_t target_cage, const s32 arg_cage[6],
                      unsigned long args[6]) {
    struct task_struct *task;
    struct mm_struct *mm;
    struct mm_struct *old_mm;
    long ret;

    task = find_get_task_by_vpid(target_cage);
    if (!task) {
        return -ESRCH;
    }

    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) {
        return -ESRCH;
    }

    /* create a copy of current's mm and borrow target cage's mm */
    old_mm = current->mm;
    task_lock(current);
    current->mm = mm;
    current->active_mm = mm;
    switch_mm(old_mm, mm, current);
    task_unlock(current);

    switch (nr) {
#ifdef __NR_munmap
    case __NR_munmap:
        ret = vm_munmap(args[0], args[1]);
        break;
#endif
#ifdef __NR_mmap
    case __NR_mmap: {
        unsigned long flags = args[3];
        struct file *file = NULL;

        if (flags & MAP_ANONYMOUS) {
            ret = vm_mmap(NULL, args[0], args[1], args[2], flags, 0);
            break;
        }

        /* File backed mmap call. The fd (args[4]) is owned by the
         * arg_cage[4] (0 = targeted cage). Resolve fd in target
         * cage's context by checking the 3i vfd table first, then the
         * cage's real fd table */
        {
            pid_t fd_cage =
                (arg_cage && arg_cage[4]) ? arg_cage[4] : target_cage;
            int fd = (int)args[4];
            struct task_struct *fd_task;
            struct threei_handler *handler;
            struct threei_fdtable *fdtable;

            fd_task = find_get_task_by_vpid(fd_cage);
            if (!fd_task) {
                ret = -ESRCH;
                break;
            }

            rcu_read_lock();
            handler = rcu_dereference(fd_task->threei_handler);
            rcu_read_unlock();

            fdtable = handler ? READ_ONCE(handler->fdtable) : NULL;
            if (fdtable) {
                /* borrowed file struct */
                file = threei_vfd_lookup(fdtable, fd);
            }

            if (file) {
                /* increment ref count to file */
                get_file(file);
            } else {
                /* real fd table + ref */
                file = fget_task(fd_task, fd);
            }
            put_task_struct(fd_task);
        }

        ret = vm_mmap(file, args[0], args[1], args[2], flags, args[5]);

        fput(file);
        break;
    }
#endif
#ifdef __NR_mprotect
    case __NR_mprotect:
        /* do_mprotect_pkey is exported; vm-level mprotect on
         * targeted cage */
        ret = do_mprotect_pkey(args[0], args[1], args[2], -1);
        break;
#endif
#ifdef __NR_pkey_mprotect
    case __NR_pkey_mprotect:
        /* uses do_mprotect_pkey */
        ret = do_mprotect_pkey(args[0], args[1], args[2], args[3]);
        break;
#endif
#ifdef __NR_madvise
    case __NR_madvise:
        ret = do_madvise(current->mm, args[0], args[1], args[2]);
        break;
#endif
#ifdef __NR_mremap
    case __NR_mremap: {
        ret = threei_mremap(args[0], args[1], args[2], args[3], args[4]);
        break;
    }
#endif
    default:
        ret = -ENOSYS;
        break;
    }

    /* retore the grate's mm */
    task_lock(current);
    current->mm = old_mm;
    current->active_mm = old_mm;
    switch_mm(mm, old_mm, current);
    task_unlock(current);

    /* drop the ref taken by get_task_mm */
    mmput(mm);
    return ret;
}
