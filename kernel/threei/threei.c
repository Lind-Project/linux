#include <asm/io.h>
#include <linux/completion.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/gfp.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/pid.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/threei.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <uapi/linux/threei.h>

/*
 * threei_ring_alloc - allocates ring slot required for forwarding
 * grate via fast path.
 *
 * @ctx: a reference to the current executing grate ctx struct
 *
 */
static int threei_ring_alloc(struct threei_grate_ctx *ctx) {
    unsigned long order = get_order(sizeof(struct threei_ring));
    struct page *pages;

    pages = alloc_pages(GFP_KERNEL | __GFP_ZERO, order);
    if (!pages) {
        return -ENOMEM;
    }

    ctx->ring = page_address(pages);
    ctx->ring_order = order;
    ctx->ring->nr_slots = THREEI_RING_SLOTS;
    return 0;
}

/*
 * threei_ctx_free_rcu - free pages allocated to shared ring and
 * frees object of threei_grate_ctx.
 */
static void threei_ctx_free_rcu(struct rcu_head *rcu) {
    struct threei_grate_ctx *ctx =
        container_of(rcu, struct threei_grate_ctx, rcu);

    if (ctx->ring) {
        free_pages((unsigned long)ctx->ring, ctx->ring_order);
    }
    kfree(ctx);
}

static void threei_ctx_put(struct threei_grate_ctx *ctx) {
    if (refcount_dec_and_test(&ctx->refs)) {
        call_rcu(&ctx->rcu, threei_ctx_free_rcu);
    }
}

/*
 * Take a transient reference on a ctx read under RCU. Returns true if
 * pinned. Used by the cage before it spins on the ring, so the ctx and
 * ring pages cannot be freed under it.
 */
static bool threei_ctx_tryget(struct threei_grate_ctx *ctx) {
    return refcount_inc_not_zero(&ctx->refs);
}

/* per-grate receive context */
static struct threei_grate_ctx *grate_ctx_alloc(void) {
    struct threei_grate_ctx *ctx;

    ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx) {
        return NULL;
    }

    spin_lock_init(&ctx->lock);
    INIT_LIST_HEAD(&ctx->requests);
    INIT_LIST_HEAD(&ctx->inflight);
    init_waitqueue_head(&ctx->recv_wq);
    atomic64_set(&ctx->next_id, 0);
    refcount_set(&ctx->refs, 1);

    return ctx;
}

static struct threei_grate_ctx *grate_ctx_get(struct task_struct *grate) {
    struct threei_grate_ctx *ctx, *fresh;

    rcu_read_lock();
    ctx = rcu_dereference(grate->threei_grate_ctx);
    rcu_read_unlock();
    if (ctx) {
        return ctx;
    }

    fresh = grate_ctx_alloc();
    if (!fresh) {
        return NULL;
    }

    task_lock(grate);
    ctx = rcu_dereference_protected(grate->threei_grate_ctx,
                                    lockdep_is_held(&grate->alloc_lock));

    if (ctx) {
        task_unlock(grate);
        kfree(fresh);
        return ctx;
    }

    rcu_assign_pointer(grate->threei_grate_ctx, fresh);
    task_unlock(grate);
    return fresh;
}

static bool has_pending(struct threei_grate_ctx *ctx) {
    bool ret;

    spin_lock(&ctx->lock);
    ret = !list_empty(&ctx->requests);
    spin_unlock(&ctx->lock);
    return ret;
}

static struct threei_request *find_inflight(struct threei_grate_ctx *ctx,
                                            u64 id) {
    struct threei_request *req;

    list_for_each_entry(req, &ctx->inflight, node) {
        if (req->id == id) {
            return req;
        }
    }

    return NULL;
}

/*
 * depricated since copy should be only made when requested explicitly.
 * will remove it in the future Only syscalls listed here get their
 * pointer arguments copied into the slot's inline data[] buffer so the
 * grate can dereference them directly. Anything not listed is treated as
 * all-scalar (no marshaling), which is correct for syscalls like geteuid.
 */

/*
static const struct threei_syscall_desc *threei_get_desc(u32 nr) {
    if (nr < ARRAY_SIZE(threei_descs)) {
        return &threei_descs[nr];
    }
    return NULL; // scalrs
}

static long threei_marshal_into_slot(struct threei_ring_slot *slot, u32 nr,
                                     unsigned long args[6]) {
    const struct threei_syscall_desc *desc = threei_get_desc(nr);
    u32 off = 0;
    int i;

    slot->arg_is_ptr = 0;

    for (i = 0; i < 6; i++) {
        if (desc && desc->args[i].type == ARG_IN_PTR && args[i]) {
            if (desc->args[i].size == 0) {
                long n = strncpy_from_user(slot->data + off,
                                           (void __user *)args[i],
                                           THREEI_SLOT_DATA - off);
                if (n < 0) {
                    return -EFAULT;
                }
                if (n >= (long)(THREEI_SLOT_DATA - off)) {
                    return -E2BIG;
                }
                slot->args[i] = off;
                slot->arg_is_ptr |= (1ULL << i);
                off += n + 1;
            } else {
                u32 sz = desc->args[i].size;

                if (off + sz > THREEI_SLOT_DATA) {
                    return -E2BIG;
                }
                if (copy_from_user(slot->data + off,
                                   (void __user *)args[i], sz)) {
                    return -EFAULT;
                }
                slot->args[i] = off;
                slot->arg_is_ptr |= (1ULL << i);
                off += sz;
            }
        } else {
            slot->args[i] = args[i];
        }
    }
    return 0;
}
*/

/* fast path: shared-ring spin
 *
 * Try to forward via the shared ring. Returns true if the ring path was
 * used (and writes the syscall result into *out). Returns false if no ring
 * exists yet, in which case the caller falls back to the completion path.
 *
 * Lifetime: the caller has already pinned ctx with threei_ctx_tryget(), so
 * ctx and its ring pages are guaranteed live for the whole of this call,
 * including the spin (which may cond_resched / sleep). We never drop that
 * pin here instead the caller releases it.
 *
 * The cage spins in kernel context waiting for the grate to flip the slot
 * to DONE. The spin is bounded: on each budget expiry we check ctx->dead
 * and for a fatal signal, then cond_resched(), so a stuck or dead grate
 * cannot wedge the cage uninterruptibly.
 */
static bool forward_via_ring(struct threei_grate_ctx *ctx,
                             struct handler_result *handler, u32 nr,
                             pid_t primary_cage, const s32 arg_cage[6],
                             unsigned long args[6], long *out) {
    struct threei_ring *ring = ctx->ring;
    struct threei_ring_slot *slot = NULL;
    int i, spins;

    if (!ring || !ctx->ring_uaddr) {
        return false;
    }

    /* claim a FREE slot */
    for (i = 0; i < ring->nr_slots; i++) {
        u32 expected = THREEI_SLOT_FREE;

        if (try_cmpxchg(&ring->slots[i].state, &expected,
                        THREEI_SLOT_CLAIMED)) {
            slot = &ring->slots[i];
            break;
        }
    }
    if (!slot) {
        return false; /* ring momentarily full: use slow path */
    }

    slot->nr = nr;
    slot->handler_addr = (u64)handler->handler_addr;
    slot->cage = primary_cage;
    slot->arg_is_ptr = 0;
    memcpy(slot->args, args, sizeof(slot->args));
    if (arg_cage) {
        memcpy(slot->arg_cage, arg_cage, sizeof(slot->arg_cage));
    } else {
        memset(slot->arg_cage, 0, sizeof(slot->arg_cage));
    }

    /* removed support for automated pointer argument translation */

    /*
    ret = threei_marshal_into_slot(slot, nr, args);
    if (ret) {
                                    smp_store_release(&slot->state,
    THREEI_SLOT_FREE); *out = ret; return true;
    }
    */

    /* publish: CLAIMED -> PENDING */
    smp_store_release(&slot->state, THREEI_SLOT_PENDING);

    /* spin for the grate's reply */
    spins = 0;
    while (smp_load_acquire(&slot->state) != THREEI_SLOT_DONE) {
        cpu_relax();
        if (++spins >= THREEI_SPIN_BUDGET) {
            spins = 0;
            if (READ_ONCE(ctx->dead)) {
                smp_store_release(&slot->state, THREEI_SLOT_FREE);
                *out = -ESRCH;
                return true;
            }
            if (fatal_signal_pending(current)) {
                smp_store_release(&slot->state, THREEI_SLOT_FREE);
                *out = -EINTR;
                return true;
            }
            cond_resched();
        }
    }

    *out = (long)slot->retval;
    smp_store_release(&slot->state, THREEI_SLOT_FREE);
    return true;
}

/* slow path: completion + waitqueue */
static long forward_via_completion(struct threei_grate_ctx *ctx,
                                   struct handler_result *handler, u32 nr,
                                   pid_t primary_cage,
                                   unsigned long args[6]) {
    struct threei_request req;
    long ret;

    memset(&req, 0, sizeof(req));
    req.id = atomic64_inc_return(&ctx->next_id);
    req.nr = nr;
    req.handler_addr = handler->handler_addr;
    req.cage = primary_cage;
    memcpy(req.args, args, sizeof(req.args));
    init_completion(&req.done);
    req.completed = false;

    spin_lock(&ctx->lock);
    if (ctx->dead) {
        spin_unlock(&ctx->lock);
        return -ESRCH;
    }
    list_add_tail(&req.node, &ctx->requests);
    spin_unlock(&ctx->lock);
    wake_up(&ctx->recv_wq);

    ret = wait_for_completion_interruptible(&req.done);
    if (ret) {
        spin_lock(&ctx->lock);
        if (!req.completed) {
            list_del(&req.node);
            spin_unlock(&ctx->lock);
            return -EINTR;
        }
        /* grate completed it between our wakeup and the lock */
        spin_unlock(&ctx->lock);
    }
    return req.retval;
}

/* forward to a grate and block until it responds */
static long forward_to_grate(struct handler_result *handler,
                             u32 syscall_nr, pid_t primary_cage,
                             const s32 arg_cage[6],
                             unsigned long args[6]) {
    struct task_struct *grate;
    struct threei_grate_ctx *ctx;
    long ret;

    rcu_read_lock();
    grate = find_task_by_vpid(handler->grateid);
    if (grate) {
        get_task_struct(grate);
    }
    rcu_read_unlock();

    if (!grate) {
        return -ESRCH;
    }

    ctx = grate_ctx_get(grate);
    if (!ctx || (grate->flags & PF_EXITING)) {
        put_task_struct(grate);
        return -ESRCH;
    }

    /*
     * Pin the ctx once for the whole forward so neither it nor its ring
     * pages can be freed while we spin (the spin may cond_resched, so we
     * cannot stay in an RCU read section). grate_ctx_get returned a ctx
     * that is live right now, threei_ctx_tryget makes that a counted ref.
     */
    if (!threei_ctx_tryget(ctx)) {
        put_task_struct(grate);
        return -ESRCH;
    }

    /* fast path: shared ring spin */
    if (forward_via_ring(ctx, handler, syscall_nr, primary_cage, arg_cage,
                         args, &ret)) {
        threei_ctx_put(ctx);
        put_task_struct(grate);
        return ret;
    }

    /* slow path: completion + waitqueue */
    ret = forward_via_completion(ctx, handler, syscall_nr, primary_cage,
                                 args);
    threei_ctx_put(ctx);
    put_task_struct(grate);
    return ret;
}

/* FD Translation routine */

/*
 * translate any fd-typed argument from virtual to real before
 * forwarding. need to cover all fd related syscalls
 */
static const struct threei_fd_desc threei_fd_descs[] = {
#ifdef __NR_openat
    [__NR_openat] = {.flags = THREEI_RET_IS_FD},
#endif
#ifdef __NR_read
    [__NR_read] = {.arg_is_fd = 0x01,
                   .buf = {.ptr_arg = 1,
                           .len_arg = 2,
                           .dir = THREEI_BUF_OUT}},
#endif
#ifdef __NR_write
    [__NR_write] = {.arg_is_fd = 0x01,
                    .buf = {.ptr_arg = 1,
                            .len_arg = 2,
                            .dir = THREEI_BUF_IN}},
#endif
#ifdef __NR_pread64
    [__NR_pread64] = {.arg_is_fd = 0x01,
                      .buf = {.ptr_arg = 1,
                              .len_arg = 2,
                              .dir = THREEI_BUF_OUT}},
#endif
#ifdef __NR_pwrite64
    [__NR_pwrite64] = {.arg_is_fd = 0x01,
                       .buf = {.ptr_arg = 1,
                               .len_arg = 2,
                               .dir = THREEI_BUF_IN}},
#endif
#ifdef __NR_fstat
    [__NR_fstat] = {.arg_is_fd = 0x01,
                    .buf = {.ptr_arg = 1,
                            .len_arg = THREEI_LEN_FIXED,
                            .fixed_len = sizeof(struct stat),
                            .dir = THREEI_BUF_OUT}},
#endif
#ifdef __NR_lseek
    [__NR_lseek] = {.arg_is_fd = 0x01},
#endif
#ifdef __NR_close
    [__NR_close] = {.arg_is_fd = 0x01, .flags = THREEI_FREES_FD0},
#endif
#ifdef __NR_mmap
    [__NR_mmap] = {.flags = THREEI_ARG_IS_FD_MAP, .map_fd = 1 << 4},
#endif
};

static inline const struct threei_fd_desc *threei_get_fd_desc(u32 nr) {
    if (nr < ARRAY_SIZE(threei_fd_descs)) {
        return &threei_fd_descs[nr];
    }
    return NULL;
}

/* virtualize retval if RET_IS_FD, or free the vfd if FREES_FD0
 * and the free-target arg was already translated */
static long threei_postprocess_fd(struct threei_handler *cage_handler,
                                  u32 syscall_nr, pid_t grateid,
                                  int orig_vfd_arg0, long verdict) {
    const struct threei_fd_desc *desc = threei_get_fd_desc(syscall_nr);
    struct threei_fdtable *table;

    if (!desc) {
        return verdict;
    }

    if (verdict < 0) {
        return verdict;
    }

    if (desc->flags & THREEI_RET_IS_FD) {
        struct file *file;
        int grate_fd = (int)verdict;
        int vfd;

        table = threei_fdtable_get(cage_handler);
        if (!table) {
            return -ENOMEM;
        }

        /* current is the grate here (openat ran native in the grate).
         * Pin the file*, then close the grate's fd so it doesn't leak. */
        file = fget(grate_fd);
        if (!file) {
            return -EBADF;
        }

        vfd = threei_vfd_alloc(table, file, task_tgid_nr(current));
        if (vfd < 0) {
            fput(file);
            return -EMFILE;
        }

        close_fd(grate_fd);

        return vfd;
    }

    if (desc->flags & THREEI_FREES_FD0) {
        table = READ_ONCE(cage_handler->fdtable);
        if (table) {
            threei_vfd_free(table, orig_vfd_arg0);
        }
    }

    return verdict;
}

/* The shared routing decision, against current's table. */
static long __route_current(u32 syscall_nr, pid_t primary_cage,
                            const s32 arg_cage[6], unsigned long args[6]) {
    struct handler_result handler;
    struct threei_handler *cage_handler = NULL;
    struct task_struct *cage_task;
    const struct threei_fd_desc *desc;
    int orig_vfd_arg0 = (int)args[0]; /* save before translation */
    bool have_handler, handled = false;
    long ret;

    rcu_read_lock();
    cage_task = find_task_by_vpid(primary_cage);
    if (cage_task) {
        cage_handler = rcu_dereference(cage_task->threei_handler);
        if (cage_handler && !refcount_inc_not_zero(&cage_handler->refs)) {
            cage_handler = NULL;
        }
    }
    rcu_read_unlock();

    have_handler = (get_handler(syscall_nr, &handler) == 0);
    desc = threei_get_fd_desc(syscall_nr);
    /*
     * Generic isolation-preserving path: descriptor exists, takes an fd,
     * but the grate registered NO handler for it. Execute against the
     * grate's file* here. current is the cage -> copies are
     * copy_to/from_user. Only attempt when we have the cage_handler (need
     * its fdtable) and the syscall isn't the RET_IS_FD/openat kind (those
     * still forward to the openat handler to actually open).
     */
    if (!have_handler && cage_handler && desc && desc->arg_is_fd) {
        ret = threei_generic_fd_exec(cage_handler, syscall_nr, desc, args,
                                     &handled);
        if (handled) {
            /* postprocess for FREES_FD0 (close): free the vfd slot.
             * orig_vfd_arg0 holds the pre-translation vfd. */
            ret = threei_postprocess_fd(cage_handler, syscall_nr, 0,
                                        orig_vfd_arg0, ret);
            refcount_dec(&cage_handler->refs);
            return ret;
        }
        /* not handled (e.g. native fd, or syscall we don't implement).
         * fall through to normal translate + forward/native below */
    }

    /*
     * run the syscall: forward to a further grate if one is registered
     * against current, else run it natively here. Either way we get a
     * return value we then postprocess.
     */
    have_handler = (get_handler(syscall_nr, &handler) == 0);
    if (have_handler) {
        ret = forward_to_grate(&handler, syscall_nr, primary_cage,
                               arg_cage, args);
    } else if (primary_cage != 0 && primary_cage != task_tgid_nr(current)
		    && threei_is_thread_op(syscall_nr)) {
	ret = threei_inject_call(primary_cage, syscall_nr, args);
    } else if (primary_cage != 0 && primary_cage != task_tgid_nr(current)
		    && threei_is_mm_op(syscall_nr)) {
        ret = threei_run_mm_op(syscall_nr, primary_cage, arg_cage, args);
    } else {
        ret = native_syscall(syscall_nr, args);
    }

    if (cage_handler) {
        pid_t grateid =
            have_handler ? handler.grateid : task_tgid_nr(current);
        ret = threei_postprocess_fd(cage_handler, syscall_nr, grateid,
                                    orig_vfd_arg0, ret);
        refcount_dec(&cage_handler->refs);
    }
    return ret;
}

/*
static int threei_install_grate_fd_into_cage(pid_t grateid, int real_fd) {
    struct task_struct *grate;
    struct file *file;
    int cage_fd;

    rcu_read_lock();
    grate = find_task_by_vpid(grateid);
    if (grate) {
        get_task_struct(grate);
    }
    rcu_read_unlock();
    if (!grate) {
        return -ESRCH;
    }

    // get struct file* for an fd in a specific task
    file = fget_task(grate, real_fd);
    put_task_struct(grate);
    if (!file) {
        return -EBADF;
    }

    cage_fd = get_unused_fd_flags(0);
    if (cage_fd < 0) {
        fput(file);
        return cage_fd;
    }
    fd_install(cage_fd, file);
    return cage_fd;
}
*/

/*
 * Generalized gate handling for THREEI_ARG_IS_FD_MAP syscalls (mmap
 * and any address-space syscall that consumes an fd). current is the
 * cage here.
 *
 * desc->map_fd names which argument holds the vfd (lowest set bit).
 * We look it up in the cage's vfd table, install the real file into
 * the cage's own table, and rewrite that arg to the new real cage fd.
 */

static void threei_gate_map_fd(const struct threei_fd_desc *desc,
                               unsigned long args[6]) {
    struct threei_handler *ch;
    struct threei_fdtable *table;
    struct file *file;
    int idx, cage_fd, vfd;

    /* which arg holds the map fd (lowest set bit of map_fd) */
    if (!desc->map_fd) {
        return;
    }
    idx = __builtin_ffs(desc->map_fd) - 1;
    if (idx < 0 || idx >= 6) {
        return;
    }

    vfd = (int)args[idx];
    if (vfd < 0) {
        return;
    }

    rcu_read_lock();
    ch = rcu_dereference(current->threei_handler);
    rcu_read_unlock();
    if (!ch) {
        return;
    }

    table = READ_ONCE(ch->fdtable);
    if (!table) {
        return;
    }

    file = threei_vfd_lookup(table, vfd);
    if (!file) {
        return;
    }

    cage_fd = get_unused_fd_flags(0);
    if (cage_fd < 0) {
        return;
    }
    get_file(file);
    fd_install(cage_fd, file);
    args[idx] = (unsigned long)cage_fd;
}

/*
 * threei entry gate. all the syscalls made by a cage which has handler
 * registered against it lands here. This path is userful for:
 *
 * 1. address-space specific syscalls like mmap/brk/mprotect/etc to
 * be executed in cage's context natively using THREEI_ALLOW.
 *
 * 2. if a grate only registers a handler for syscall like openat()
 * which returns a fd by forwarding it via make_threei_call(). Returned
 * fd is valid in grate's context, if a subsequent syscall uses that fd,
 * it will fail, thus such syscalls goes through per-syscall fd table
 * and performs translation, executing that syscall natively in cage's
 * context.
 */
bool threei_entry(u32 syscall_nr, unsigned long args[6], long *result) {
    struct handler_result handler;
    const struct threei_fd_desc *fdesc;
    long verdict;

    if (get_handler(syscall_nr, &handler) == 0) {
        verdict = forward_to_grate(&handler, syscall_nr,
                                   task_tgid_nr(current), NULL, args);
        /* handler exists: forward to the grate (active mediation) */
        if (verdict == THREEI_ALLOW) {
            return false;
        }
        *result = verdict;
        return true;
    }

    fdesc = threei_get_fd_desc(syscall_nr);
    if (fdesc && (fdesc->flags & THREEI_ARG_IS_FD_MAP)) {
        threei_gate_map_fd(fdesc, args);
        return false;
    }

    if (fdesc && fdesc->arg_is_fd) {
        struct threei_handler *ch;
        bool handled = false;
        long ret;

        rcu_read_lock();
        ch = rcu_dereference(current->threei_handler);
        if (ch && !refcount_inc_not_zero(&ch->refs)) {
            ch = NULL;
        }
        rcu_read_unlock();

        if (ch) {
            int orig_vfd = (int)args[0];

            ret = threei_generic_fd_exec(ch, syscall_nr, fdesc, args,
                                         &handled);

            if (handled) {
                /* FREES_FD0 (close): free the vfd slot */
                ret = threei_postprocess_fd(ch, syscall_nr, 0, orig_vfd,
                                            ret);
                refcount_dec(&ch->refs);
                *result = ret;
                return true;
            }
            refcount_dec(&ch->refs);
        }
    }
    return false;
}

/*
 * verifies whether forwarder is the registered grate for (cageid,
 * syscall_nr) prevents memory leak via copy_data_between_cages (not
 * integrated yet).
 */
static bool threei_verify_forwarder(pid_t cageid, u32 syscall_nr,
                                    struct task_struct *forwarder) {
    struct task_struct *cage;
    struct threei_handler *handler;
    bool verified = false;

    if (syscall_nr >= NR_syscalls) {
        return false;
    }

    rcu_read_lock();
    cage = find_task_by_vpid(cageid);
    if (cage) {
        handler = rcu_dereference(cage->threei_handler);
        if (handler && test_bit(syscall_nr, handler->registered) &&
            handler->table[syscall_nr].grateid ==
                task_tgid_nr(forwarder)) {
            verified = true;
        }
    }
    rcu_read_unlock();

    return verified;
}

/*
 * Verify authorization for the primary_cage and arg_cage[]. A grate may
 * only attribute an argument to a cage it is a registered handler for.
 */
static bool threei_verify_all_cages(pid_t primary_cage, u32 syscall_nr,
                                    const s32 arg_cage[6],
                                    struct task_struct *forwarder) {
    int i, j;

    if (!threei_verify_forwarder(primary_cage, syscall_nr, forwarder)) {
        return false;
    }

    /* all args default to primary_cage i.e already checked */
    if (!arg_cage) {
        return true;
    }

    for (i = 0; i < 6; i++) {
        pid_t cage = arg_cage[i];

        if (cage == 0 || cage == primary_cage) {
            continue;
        }

        /* skip verification of duplicate entries */
        for (j = 0; j < i; j++) {
            if (arg_cage[j] == cage) {
                break;
            }
        }
        if (j < i) {
            continue;
        }

        if (!threei_verify_forwarder(cage, syscall_nr, forwarder)) {
            return false;
        }
    }
    return true;
}

/* make_threei_call - syscall */
SYSCALL_DEFINE4(make_threei_call, u32, syscall_nr, pid_t, primary_cage,
                const s32 __user *, user_arg_cage,
                const unsigned long __user *, user_args) {
    unsigned long args[6];
    s32 arg_cage[6];
    s32 *arg_cage_p = NULL;

    if (copy_from_user(args, user_args, sizeof(args))) {
        return -EFAULT;
    }

    if (user_arg_cage) {
        if (copy_from_user(arg_cage, user_arg_cage, sizeof(arg_cage))) {
            return -EFAULT;
        }
        arg_cage_p = arg_cage;
    }

    /* commented out verification routine */
    /*
    if (!threei_verify_all_cages(primary_cage, syscall_nr, arg_cage_p,
    current)) { return -EPERM;
    }
    */

    return __route_current(syscall_nr, primary_cage, arg_cage_p, args);
}

/*
 * copy_data_between_cages - Moves memory between two cages'
 * address spaces via access_process_vm. Neither cage need
 * be the caller (a handler copies a cage's buffers).
 */
SYSCALL_DEFINE5(copy_data_between_cages, pid_t, src_cage, unsigned long,
                src_addr, pid_t, dst_cage, unsigned long, dst_addr, size_t,
                len) {
    struct task_struct *src_task = NULL, *dst_task = NULL;
    void *buf;
    long copied, ret = 0;

    if (!len || len > THREEI_MAX_COPY) {
        return -EINVAL;
    }

    buf = kvmalloc(len, GFP_KERNEL);
    if (!buf) {
        return -ENOMEM;
    }

    rcu_read_lock();
    src_task = find_task_by_vpid(src_cage);
    if (src_task) {
        get_task_struct(src_task);
    }
    dst_task = find_task_by_vpid(dst_cage);
    if (dst_task) {
        get_task_struct(dst_task);
    }
    rcu_read_unlock();

    if (!src_task || !dst_task) {
        ret = -ESRCH;
        goto out;
    }

    copied = access_process_vm(src_task, src_addr, buf, len, 0);
    if (copied != (long)len) {
        ret = -EFAULT;
        goto out;
    }
    copied = access_process_vm(dst_task, dst_addr, buf, len, FOLL_WRITE);
    if (copied != (long)len) {
        ret = -EFAULT;
    }

out:
    if (src_task) {
        put_task_struct(src_task);
    }
    if (dst_task) {
        put_task_struct(dst_task);
    }
    kvfree(buf);
    return ret;
}

/*
 * Establish the ring for the calling grate: allocate it and map it into
 * the grate's own address space. current IS the grate here (threei_recv is
 * called by the grate in its own context), so vm_mmap + remap_pfn_range
 * land in the right mm. Returns the userspace address, or 0 on failure.
 * Idempotent: a second call returns the already-mapped address.
 */
static unsigned long threei_create_ring(struct threei_grate_ctx *ctx) {
    unsigned long uaddr;
    struct vm_area_struct *vma;
    int ret;

    if (ctx->ring_uaddr) {
        return ctx->ring_uaddr;
    }

    if (!ctx->ring) {
        if (threei_ring_alloc(ctx)) {
            return 0;
        }
    }

    uaddr = vm_mmap(NULL, 0, PAGE_ALIGN(sizeof(struct threei_ring)),
                    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0);
    if (IS_ERR_VALUE(uaddr)) {
        return 0;
    }

    if (mmap_write_lock_killable(current->mm)) {
        vm_munmap(uaddr, PAGE_ALIGN(sizeof(struct threei_ring)));
        return 0;
    }

    vma = find_vma(current->mm, uaddr);
    if (!vma) {
        mmap_write_unlock(current->mm);
        vm_munmap(uaddr, PAGE_ALIGN(sizeof(struct threei_ring)));
        return 0;
    }

    /* prevent the anonymous mapping from being merged/swapped under us */
    vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);

    ret = remap_pfn_range(
        vma, uaddr, virt_to_phys(ctx->ring) >> PAGE_SHIFT,
        PAGE_ALIGN(sizeof(struct threei_ring)), vma->vm_page_prot);
    mmap_write_unlock(current->mm);

    if (ret) {
        vm_munmap(uaddr, PAGE_ALIGN(sizeof(struct threei_ring)));
        return 0;
    }

    ctx->ring_uaddr = uaddr;
    return uaddr;
}

/*
 * threei_grate_setup - establish the calling grate's shared ring and map
 * it into the grate's own address space, returning its userspace address
 * (or a negative errno). Called once by the grate at startup (from the
 * threei.h constructor), before the cage makes any interposed syscall.
 * current is the grate here, so the mapping lands in the grate's mm.
 *
 * A second call returns the already-mapped address.
 */
SYSCALL_DEFINE0(threei_grate_setup) {
    struct threei_grate_ctx *ctx;
    unsigned long uaddr;

    ctx = grate_ctx_get(current);
    if (!ctx) {
        return -ENOMEM;
    }

    uaddr = threei_create_ring(ctx);
    if (!uaddr) {
        return -ENOMEM;
    }

    return (long)uaddr;
}

SYSCALL_DEFINE2(threei_recv, struct threei_req_user __user *, ureq,
                unsigned int, size) {
    struct threei_grate_ctx *ctx;
    struct threei_request *req;
    struct threei_req_user out;
    unsigned long ring_uaddr;

    /*
     * The grate may not have been targeted yet; create its ctx so it can
     * block waiting rather than failing.
     */

    ctx = grate_ctx_get(current);
    if (!ctx) {
        return -ENOMEM;
    }

    /* establish the ring on first recv (no-op afterwards) */
    ring_uaddr = threei_create_ring(ctx);

    if (wait_event_interruptible(ctx->recv_wq,
                                 has_pending(ctx) || ctx->dead)) {
        return -EINTR;
    }

    if (ctx->dead && !has_pending(ctx)) {
        /*signal grate to exit*/
        return -ENODEV;
    }

    spin_lock(&ctx->lock);
    req = list_first_entry_or_null(&ctx->requests, struct threei_request,
                                   node);
    if (req) {
        list_move_tail(&req->node, &ctx->inflight);
    }
    spin_unlock(&ctx->lock);
    if (!req) {
        return -EAGAIN;
    }

    memset(&out, 0, sizeof(out));
    out.id = req->id;
    out.nr = req->nr;
    out.handler_addr = (unsigned long)req->handler_addr;
    out.cage = req->cage;
    memcpy(out.args, req->args, sizeof(out.args));

    if (copy_to_user(ureq, &out, min_t(unsigned int, size, sizeof(out)))) {
        return -EFAULT;
    }
    return 0;
}

SYSCALL_DEFINE2(threei_respond, u64, id, long, retval) {
    struct threei_grate_ctx *ctx;
    struct threei_request *req;

    rcu_read_lock();
    ctx = rcu_dereference(current->threei_grate_ctx);
    rcu_read_unlock();
    if (!ctx) {
        return -EINVAL;
    }

    spin_lock(&ctx->lock);
    req = find_inflight(ctx, id);
    if (req) {
        list_del(&req->node);
        req->retval = retval;
        req->completed = true;
        /* wakes the blocked cage */
        complete(&req->done);
    }
    spin_unlock(&ctx->lock);

    return req ? 0 : -ENOENT;
}

/* LIFECYCLE HOOKS */

/* copy_threei - fork inheritance */
int copy_threei(struct task_struct *p) {
    struct threei_handler *handler;

    /* a fork must never inherit a pending injection */
    p->threei_inject = NULL;
    /*
     * A grate receive context is per-task and must NOT be inherited: the
     * child is a different task with its own (initially absent) context.
     */
    p->threei_grate_ctx = NULL;

    rcu_read_lock();
    handler = rcu_dereference(current->threei_handler);

    /*
     * refcount_inc_not_zero guards against the object being torn down
     * concurrently (a sharing thread, or a grate dropping the cage's
     * table).
     */
    if (handler && !refcount_inc_not_zero(&handler->refs)) {
        handler = NULL;
    }
    rcu_read_unlock();

    /* p is not yet visible to other CPUs: a plain store is sufficient. */
    p->threei_handler = handler;

    if (handler && !bitmap_empty(handler->registered, NR_syscalls)) {
        set_task_syscall_work(p, THREEI);
    } else {
        clear_task_syscall_work(p, THREEI);
    }

    return 0;
}

/* threei_exit - exit teardown */
void threei_exit(struct task_struct *task) {
    struct threei_grate_ctx *ctx;
    struct threei_handler *handler;
    struct task_struct *grate;
    struct threei_inject *inj;

    /* If this task dies with an injected syscall still pending, unblock the
     * arming grate (waiting in threei_inject_call) so it doesn't hang. */
    inj = task->threei_inject;
    if (inj) {
	    task->threei_inject = NULL;
	    if (READ_ONCE(inj->active)) {
	        inj->ret = -ESRCH;
		    inj->active = false;
		    complete(inj->done);
	    }
        threei_inject_put(inj);
    }

    task->threei_inject = NULL;

    /* before dropping the table, find any registered grate and wake it */
    rcu_read_lock();
    handler = rcu_dereference(task->threei_handler);
    if (handler) {
        unsigned int nr;

        for_each_set_bit(nr, handler->registered, NR_syscalls) {
            grate = find_task_by_vpid(handler->table[nr].grateid);
            if (grate) {
                ctx = rcu_dereference(grate->threei_grate_ctx);
                if (ctx) {
                    spin_lock(&ctx->lock);
                    ctx->dead = true;
                    spin_unlock(&ctx->lock);
                    wake_up(&ctx->recv_wq);
                }
            }
            /*one wake is enough*/
            break;
        }
    }
    rcu_read_unlock();

    /* 1. Drop this task's interposition table (task-direct, no lookup). */
    __drop_handlers(task);

    /* 2. Tear down its grate receive context, if it had one. */
    task_lock(task);
    ctx = rcu_dereference_protected(task->threei_grate_ctx,
                                    lockdep_is_held(&task->alloc_lock));
    rcu_assign_pointer(task->threei_grate_ctx, NULL);
    task_unlock(task);

    if (ctx) {
        struct threei_request *req, *tmp;

        spin_lock(&ctx->lock);
        ctx->dead = true;
        /*
         * Fail every request still pending or in flight: the grate is
         * gone and will never respond, so unblock the waiting cages.
         */
        list_for_each_entry_safe(req, tmp, &ctx->requests, node) {
            list_del(&req->node);
            req->retval = -ESRCH;
            req->completed = true;
            complete(&req->done);
        }
        list_for_each_entry_safe(req, tmp, &ctx->inflight, node) {
            list_del(&req->node);
            req->retval = -ESRCH;
            req->completed = true;
            complete(&req->done);
        }
        spin_unlock(&ctx->lock);

        threei_ctx_put(ctx);
    }
}
