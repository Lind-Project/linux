#include <linux/bitmap.h>
#include <linux/entry-common.h>
#include <linux/pid.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/threei.h>

/* allocate threei_handler. bitmap + zero-filled*/
static struct threei_handler *threei_handler_alloc(gfp_t gfp) {
    struct threei_handler *handler;

    handler = kzalloc(sizeof(*handler), gfp);
    if (!handler) {
        return NULL;
    }

    refcount_set(&handler->refs, 1);

    return handler;
}

static void threei_handler_free_rcu(struct rcu_head *rcu) {
    struct threei_handler *handler =
        container_of(rcu, struct threei_handler, rcu);

    kfree(handler);
}

static void threei_handler_put(struct threei_handler *handler) {
    if (handler && refcount_dec_and_test(&handler->refs)) {
        call_rcu(&handler->rcu, threei_handler_free_rcu);
    }
}

/* handler helpers */

/*
 * Clone an immutable source object. The source is never mutated in place,
 * so no lock on it is required — an rcu_dereference'd pointer is a stable
 * snapshot. Each copied entry takes its own pid reference.
 *
 * gfp is GFP_ATOMIC at call sites that hold task_lock (a spinlock).
 */
static struct threei_handler *
threei_handler_clone(const struct threei_handler *src, gfp_t gfp) {
    struct threei_handler *dst;

    dst = kzalloc(sizeof(*dst), gfp);
    if (!dst) {
        return NULL;
    }

    refcount_set(&dst->refs, 1);
    bitmap_copy(dst->registered, src->registered, NR_syscalls);
    memcpy(dst->table, src->table, sizeof(dst->table));

    return dst;
}

/* Resolve a cageid to a task, taking a reference. Call inside
 * rcu_read_lock. */
static struct task_struct *threei_get_task(pid_t cageid) {
    struct task_struct *task;
    task = find_task_by_vpid(cageid);

    if (task) {
        get_task_struct(task);
    }

    return task;
}

/*
 * Produce a fresh clone of target's current handler object (or a brand-new
 * empty one if it has none) for the caller to mutate, with task_lock held.
 * Returns the clone in *newp and the old object in *oldp (caller publishes
 * *newp and then threei_handler_put(*oldp) AFTER dropping task_lock).
 *
 * Must be called with task_lock(target) held. Allocates GFP_ATOMIC.
 */
static int threei_begin_update(struct task_struct *target,
                               struct threei_handler **oldp,
                               struct threei_handler **newp) {
    struct threei_handler *old, *new;

    old = rcu_dereference_protected(target->threei_handler,
                                    lockdep_is_held(&target->alloc_lock));

    if (old) {
        new = threei_handler_clone(old, GFP_ATOMIC);
    } else {
        new = threei_handler_alloc(GFP_ATOMIC);
    }

    if (!new) {
        return -ENOMEM;
    }

    *oldp = old;
    *newp = new;
    return 0;
}

static void threei_publish(struct task_struct *target,
                           struct threei_handler *new) {
    if (bitmap_empty(new->registered, NR_syscalls)) {
        clear_task_syscall_work(target, THREEI);
    } else {
        set_task_syscall_work(target, THREEI);
    }

    rcu_assign_pointer(target->threei_handler, new);
}

/*
 * register or overwrite a single entry.
 * overwriting preserves one entry per (cage, syscall).
 */
int threei_register_handler(pid_t cageid, u32 syscall_nr, pid_t grateid,
                            void *handler_addr) {
    struct task_struct *cage;
    struct threei_handler *old, *new;
    int ret;

    if (unlikely(syscall_nr >= NR_syscalls)) {
        return -EINVAL;
    }

    rcu_read_lock();
    cage = threei_get_task(cageid);
    rcu_read_unlock();
    if (!cage) {
        return -ESRCH;
    }

    task_lock(cage);
    ret = threei_begin_update(cage, &old, &new);
    if (ret) {
        task_unlock(cage);
        put_task_struct(cage);
        return ret;
    }

    new->table[syscall_nr].grateid = grateid;
    new->table[syscall_nr].handler_addr = handler_addr;
    set_bit(syscall_nr, new->registered);

    threei_publish(cage, new);
    task_unlock(cage);

    {
        struct threei_fdtable *table = threei_fdtable_get_or_create(cage);
        if (table) {
            threei_vfd_install_stdio(table);
        }
    }

    threei_handler_put(old);
    put_task_struct(cage);
    return 0;
}

int deregister_handler(pid_t cageid, u32 syscall_nr) {
    struct task_struct *cage;
    struct threei_handler *old, *new;

    if (unlikely(syscall_nr >= NR_syscalls)) {
        return -EINVAL;
    }

    rcu_read_lock();
    cage = threei_get_task(cageid);
    rcu_read_unlock();
    if (!cage) {
        return -EINVAL;
    }

    task_lock(cage);
    old = rcu_dereference_protected(cage->threei_handler,
                                    lockdep_is_held(&cage->alloc_lock));
    if (!old || !test_bit(syscall_nr, old->registered)) {
        task_unlock(cage);
        put_task_struct(cage);
        return -ENOENT;
    }

    new = threei_handler_clone(old, GFP_ATOMIC);
    if (!new) {
        task_unlock(cage);
        put_task_struct(cage);
        return -ENOENT;
    }

    new->table[syscall_nr].grateid = THREEI_INVALID_GRATEID;
    new->table[syscall_nr].handler_addr = NULL;
    clear_bit(syscall_nr, new->registered);

    threei_publish(cage, new);
    task_unlock(cage);

    threei_handler_put(old);
    put_task_struct(cage);
    return 0;
}

int get_handler(u32 syscall_nr, struct handler_result *out) {
    struct threei_handler *handler;

    if (unlikely(syscall_nr >= NR_syscalls)) {
        return -EINVAL;
    }

    rcu_read_lock();
    handler = rcu_dereference(current->threei_handler);
    if (!handler || !test_bit(syscall_nr, handler->registered)) {
        rcu_read_unlock();
        return -ENOENT;
    }

    out->grateid = handler->table[syscall_nr].grateid;
    out->handler_addr = handler->table[syscall_nr].handler_addr;
    rcu_read_unlock();
    return 0;
}

void put_handler_result(struct handler_result *res) {
    if (res->grateid) {
        res->grateid = THREEI_INVALID_GRATEID;
    }
}

bool check_handler_exists(pid_t cageid) {
    struct task_struct *task;
    struct threei_handler *handler;
    bool ret = false;

    rcu_read_lock();
    task = find_task_by_vpid(cageid);
    if (task) {
        handler = rcu_dereference(task->threei_handler);
        if (handler && !bitmap_empty(handler->registered, NR_syscalls)) {
            ret = true;
        }
    }
    rcu_read_unlock();
    return ret;
}

/* drop a task's entire table (task-direct core) */
void __drop_handlers(struct task_struct *task) {
    struct threei_handler *old;

    task_lock(task);
    old = rcu_dereference_protected(task->threei_handler,
                                    lockdep_is_held(&task->alloc_lock));
    rcu_assign_pointer(task->threei_handler, NULL);
    clear_task_syscall_work(task, THREEI);
    task_unlock(task);

    threei_handler_put(old);
}

void rm_cage_from_handler(pid_t cageid) {
    struct task_struct *task;

    rcu_read_lock();
    task = threei_get_task(cageid);
    rcu_read_unlock();
    if (!task) {
        return;
    }

    __drop_handlers(task);
    put_task_struct(task);
}

void rm_grate_from_handler(pid_t grateid) {
    struct task_struct *task;

    read_lock(&tasklist_lock);
    for_each_process(task) {
        struct threei_handler *old, *new;
        unsigned int nr;
        bool any = false;

        rcu_read_lock();
        old = rcu_dereference(task->threei_handler);
        rcu_read_unlock();
        if (!old) {
            continue;
        }

        rcu_read_lock();
        for_each_set_bit(nr, old->registered, NR_syscalls) {
            if (old->table[nr].grateid == grateid) {
                any = true;
                break;
            }
        }
        rcu_read_unlock();
        if (!any) {
            continue;
        }

        task_lock(task);
        old = rcu_dereference_protected(
            task->threei_handler, lockdep_is_held(&task->alloc_lock));

        if (!old) {
            task_unlock(task);
            continue;
        }

        new = threei_handler_clone(old, GFP_ATOMIC);
        if (!new) {
            task_unlock(task);
            continue;
        }

        for_each_set_bit(nr, new->registered, NR_syscalls) {
            if (new->table[nr].grateid != grateid) {
                continue;
            }
            new->table[nr].grateid = THREEI_INVALID_GRATEID;
            new->table[nr].handler_addr = NULL;
            clear_bit(nr, new->registered);
        }

        threei_publish(task, new);
        task_unlock(task);
        threei_handler_put(old);
    }
    read_unlock(&tasklist_lock);
}

/* clone one cage's table onto another */
int copy_handler_table_to_cage(pid_t srccage, pid_t targetcage) {
    struct task_struct *src_task = NULL, *dst_task = NULL;
    struct threei_handler *src, *new, *old;
    int ret = 0;

    if (srccage == targetcage) {
        return 0;
    }

    rcu_read_lock();
    src_task = threei_get_task(srccage);
    if (!src_task) {
        rcu_read_unlock();
        return -ESRCH;
    }

    dst_task = threei_get_task(targetcage);
    if (!dst_task) {
        rcu_read_unlock();
        put_task_struct(src_task);
        return -ESRCH;
    }

    if ((src_task->flags & PF_EXITING) || (dst_task->flags & PF_EXITING)) {
        rcu_read_unlock();
        ret = -ESRCH;
        goto out;
    }

    /* Source is immutable once published: clone the snapshot under RCU. */
    src = rcu_dereference(src_task->threei_handler);
    if (!src) {
        rcu_read_unlock();
        ret = -ENODATA;
        goto out;
    }

    new = threei_handler_clone(src, GFP_ATOMIC);
    rcu_read_unlock();
    if (!new) {
        ret = -ENOMEM;
        goto out;
    }

    task_lock(dst_task);
    old = rcu_dereference_protected(
        dst_task->threei_handler, lockdep_is_held(&dst_task->alloc_lock));
    threei_publish(dst_task, new);
    task_unlock(dst_task);

    threei_handler_put(old);

out:
    if (src_task) {
        put_task_struct(src_task);
    }
    if (dst_task) {
        put_task_struct(dst_task);
    }

    return ret;
}

SYSCALL_DEFINE4(register_handler, pid_t, cageid, u32, syscall_nr, pid_t,
                grateid, unsigned long, handler_addr) {
    return threei_register_handler(cageid, syscall_nr, grateid,
                                   (void *)handler_addr);
}
