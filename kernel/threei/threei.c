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
#include <linux/threei_types.h>
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
static int threei_ring_alloc(struct threei_grate_ctx *ctx)
{
	unsigned long order = get_order(sizeof(struct threei_ring));
	struct page *pages;

	pages = alloc_pages(GFP_KERNEL | __GFP_ZERO, order);
	if (!pages) {
		return -ENOMEM;
	}

	ctx->ring = page_address(pages);
	ctx->ring->serviced = 0;
	ctx->ring_order = order;
	ctx->ring->free_mask = (THREEI_RING_SLOTS == 64) ?
				       ~0ULL :
				       ((1ULL << THREEI_RING_SLOTS) - 1);
	ctx->ring->pending_mask = 0;
	return 0;
}

/*
 * threei_ctx_free_rcu - free pages allocated to shared ring and
 * frees object of threei_grate_ctx.
 */
static void threei_ctx_free_rcu(struct rcu_head *rcu)
{
	struct threei_grate_ctx *ctx =
		container_of(rcu, struct threei_grate_ctx, rcu);

	if (ctx->ring) {
		free_pages((unsigned long)ctx->ring, ctx->ring_order);
	}
	kfree(ctx);
}

static void threei_ctx_put(struct threei_grate_ctx *ctx)
{
	if (refcount_dec_and_test(&ctx->refs)) {
		call_rcu(&ctx->rcu, threei_ctx_free_rcu);
	}
}

/*
 * Take a transient reference on a ctx read under RCU. Returns true if
 * pinned. Used by the cage before it spins on the ring, so the ctx and
 * ring pages cannot be freed under it.
 */
static bool threei_ctx_tryget(struct threei_grate_ctx *ctx)
{
	return refcount_inc_not_zero(&ctx->refs);
}

/* per-grate receive context */
static struct threei_grate_ctx *grate_ctx_alloc(void)
{
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

static struct threei_grate_ctx *grate_ctx_get(struct task_struct *grate)
{
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

static bool has_pending(struct threei_grate_ctx *ctx)
{
	bool ret;

	spin_lock(&ctx->lock);
	ret = !list_empty(&ctx->requests);
	spin_unlock(&ctx->lock);
	return ret;
}

static struct threei_request *find_inflight(struct threei_grate_ctx *ctx,
					    u64 id)
{
	struct threei_request *req;

	list_for_each_entry(req, &ctx->inflight, node) {
		if (req->id == id) {
			return req;
		}
	}

	return NULL;
}

static struct threei_grate_ctx *threei_resolve_ctx(pid_t grateid)
{
	struct task_struct *grate;
	struct threei_grate_ctx *ctx;

	rcu_read_lock();
	grate = find_task_by_vpid(grateid);
	if (!grate || (grate->flags & PF_EXITING)) {
		rcu_read_unlock();
		return NULL;
	}

	ctx = rcu_dereference(grate->threei_grate_ctx);
	if (ctx && !threei_ctx_tryget(ctx)) {
		/* torn down */
		ctx = NULL;
	}
	if (ctx) {
		rcu_read_unlock();
		return ctx;
	}

	/* edge-case: if grate has no ctx yet, it has not called
	* threei_recv or threei_grate_setup. grate_ctx_get() allocates with
	* GFP_KERNEL and may sleep i.e. it cannot run under RCU. we hold task instead */
	get_task_struct(grate);
	rcu_read_unlock();

	grate_ctx_get(grate);

	/* pin it */
	rcu_read_lock();
	if (!(grate->flags & PF_EXITING)) {
		ctx = rcu_dereference(grate->threei_grate_ctx);
		if (ctx && !threei_ctx_tryget(ctx)) {
			ctx = NULL;
		}
	}
	rcu_read_unlock();
	put_task_struct(grate);
	return ctx;
}

/* helpers for caching grate context */

static void threei_cache_drop_slot(struct threei_ctx_cache *ctx_cache, int i)
{
	struct threei_grate_ctx *old = ctx_cache->ctx[i];

	__clear_bit(i, &ctx_cache->valid);
	ctx_cache->ctx[i] = NULL;
	ctx_cache->grateid[i] = 0;
	if (old) {
		threei_ctx_put(old);
	}
}

/* returns the lowest holding grateid or -1 if none */
static inline int threei_cache_find(const struct threei_ctx_cache *ctx_cache,
				    pid_t grateid)
{
	unsigned long mask = ctx_cache->valid;

	while (mask) {
		int i = __ffs(mask);
		if (ctx_cache->grateid[i] == grateid) {
			return i;
		}
		/* clear that bit and try the next */
		mask &= mask - 1;
	}
	return -1;
}

/* stores a pinned ctx */
static void threei_cache_insert(struct threei_ctx_cache *ctx_cache,
				pid_t grateid, struct threei_grate_ctx *ctx)
{
	int i;

	if (ctx_cache->valid != THREEI_CTX_CACHE_FULL) {
		i = ffz(ctx_cache->valid);
	} else {
		/* full: only reached with more than THREEI_CTX_CACHE_MAX grates */
		i = ctx_cache->next;
		ctx_cache->next = (ctx_cache->next + 1) % THREEI_CTX_CACHE_MAX;
		threei_cache_drop_slot(ctx_cache, i);
	}
	ctx_cache->grateid[i] = grateid;
	ctx_cache->ctx[i] = ctx;
	__set_bit(i, &ctx_cache->valid);
}

static void threei_cache_free(struct task_struct *task)
{
	struct threei_ctx_cache *ctx_cache = task->threei_ctx_cache;
	unsigned long mask;
	int i;

	if (!ctx_cache) {
		return;
	}

	task->threei_ctx_cache = NULL;
	mask = ctx_cache->valid;
	for_each_set_bit(i, &mask, THREEI_CTX_CACHE_MAX) {
		threei_cache_drop_slot(ctx_cache, i);
	}
	kfree(ctx_cache);
}

/* release the slot only if it is still PENDING. returns true if we
 * freed it. the caller abandons the forward either way. the return
 * value only says whether the slot was ours to hand back */
static inline bool threei_slot_reclaim(struct threei_ring *ring, int idx)
{
	/* only the taker of the pending bit owns the request */
	if (!test_and_clear_bit(idx, (unsigned long *)&ring->pending_mask)) {
		return false;
	}
	WRITE_ONCE(ring->slots[idx].state, THREEI_SLOT_FREE);
	smp_mb__before_atomic();
	set_bit(idx, (unsigned long *)&ring->free_mask);
	return true;
}

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
			     unsigned long args[6], long *out)
{
	struct threei_ring *ring = ctx->ring;
	struct threei_ring_slot *slot = NULL;
	int slot_idx, spins;
	bool grate_claimed = false;

	if (!ring || !ctx->ring_uaddr) {
		return false;
	}

	/* nobody is polling this ring, so publishing to it would spin the
     * full budget for nothing. Go straight to the completion path. */
	if (!READ_ONCE(ring->serviced)) {
		return false;
	}

	/* claim a FREE slot */
	for (;;) {
		u64 free_mask = READ_ONCE(ring->free_mask);

		if (!free_mask) {
			return false; /* ring full -> completion path */
		}
		slot_idx = __ffs64(free_mask);
		if (test_and_clear_bit(slot_idx,
				       (unsigned long *)&ring->free_mask)) {
			break; /* exclusive ownership of this slot */
		}
		/* another cage took it between the load and the RMW: retry */
	}

	slot = &ring->slots[slot_idx];
	WRITE_ONCE(slot->state, THREEI_SLOT_CLAIMED);

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

	/* publish: CLAIMED -> PENDING, then the bit */
	smp_store_release(&slot->state, THREEI_SLOT_PENDING);
	smp_mb__before_atomic();
	set_bit(slot_idx, (unsigned long *)&ring->pending_mask);

	/* spin for the grate's reply */
	spins = 0;
	u64 deadline = local_clock() + THREEI_SPIN_BUDGET;
	while (smp_load_acquire(&slot->state) != THREEI_SLOT_DONE) {
		cpu_relax();
		if (++spins >= THREEI_SPIN_BUDGET) {
			bool run_native = false;

			spins = 0;
			if (READ_ONCE(ctx->dead)) {
				threei_slot_reclaim(ring, slot_idx);
				*out = -ESRCH;
				return true;
			}
			if (fatal_signal_pending(current)) {
				threei_slot_reclaim(ring, slot_idx);
				*out = -EINTR;
				return true;
			}

			if (threei_drain_injection(nr, args, &run_native) &&
			    run_native) {
				threei_slot_reclaim(ring, slot_idx);
				*out = THREEI_ALLOW;
				return true;
			}

			if (local_clock() > deadline) {
				if (threei_slot_reclaim(ring, slot_idx)) {
					/* reclaimed: the grate never saw it. safe to resubmit */
					return false; /* forward_via_completion */
				}
				grate_claimed = true;
			}

			cond_resched();
		}
	}

	/* read the result befor handling the slot back */
	*out = (long)slot->retval;
	WRITE_ONCE(slot->state, THREEI_SLOT_FREE);
	smp_mb__before_atomic();
	set_bit(slot_idx, (unsigned long *)&ring->free_mask);
	return true;
}

/* poll interval for checking an injection while blocked on the completion
 * path (completions don't wake us for injections; TIF_NOTIFY_RESUME also
 * pulls us out, this is the backstop). */
#define THREEI_INJECT_POLL_MS 20

/* slow path: completion + waitqueue */
static long forward_via_completion(struct threei_grate_ctx *ctx,
				   struct handler_result *handler, u32 nr,
				   pid_t primary_cage, unsigned long args[6])
{
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
	wake_up_interruptible_sync(&ctx->recv_wq);

	for (;;) {
		ret = wait_for_completion_interruptible_timeout(
			&req.done, msecs_to_jiffies(THREEI_INJECT_POLL_MS));

		if (ret > 0) {
			break;
		}

		if (ret == 0) {
			bool run_native = false;

			if (threei_drain_injection(nr, args, &run_native) &&
			    run_native) {
				spin_lock(&ctx->lock);
				if (!req.completed) {
					list_del(&req.node);
				}
				spin_unlock(&ctx->lock);
				return native_syscall(nr, args);
			}
			continue;
		}
		spin_lock(&ctx->lock);
		if (!req.completed) {
			list_del(&req.node);
			spin_unlock(&ctx->lock);
			return -EINTR;
		}
		spin_unlock(&ctx->lock);
		break;
	}
	return req.retval;
}

/* forward to a grate and block until it responds */
static long forward_to_grate(struct handler_result *handler, u32 syscall_nr,
			     pid_t primary_cage, const s32 arg_cage[6],
			     unsigned long args[6])
{
	struct threei_ctx_cache *ctx_cache = current->threei_ctx_cache;
	struct threei_grate_ctx *ctx;
	long ret;
	int slot;

	BUILD_BUG_ON(THREEI_CTX_CACHE_MAX < 1 ||
		     THREEI_CTX_CACHE_MAX >= BITS_PER_LONG);

	/*fast path: grate is cached and alive */
	if (likely(ctx_cache)) {
		slot = threei_cache_find(ctx_cache, handler->grateid);
		if (likely(slot >= 0)) {
			ctx = ctx_cache->ctx[slot];
			if (likely(!READ_ONCE(ctx->dead))) {
				goto forward;
			}
			threei_cache_drop_slot(ctx_cache, slot);
		}
	}

	/* slow path (uses find_task_by_vpid) which performs heavy radix tree lookup */
	ctx = threei_resolve_ctx(handler->grateid);
	if (!ctx) {
		return -ESRCH;
	}

	/* first forward, allocate memory */
	if (unlikely(!ctx_cache)) {
		ctx_cache = kzalloc(sizeof(*ctx_cache), GFP_KERNEL);
		current->threei_ctx_cache = ctx_cache;
	}

	if (likely(ctx_cache)) {
		threei_cache_insert(ctx_cache, handler->grateid, ctx);
		goto forward;
	}

	/* these forward calls holds the reference to resolved ctx. we drop it here */

	/* fast path: shared ring spin */
	if (forward_via_ring(ctx, handler, syscall_nr, primary_cage, arg_cage,
			     args, &ret)) {
		threei_ctx_put(ctx);
		return ret;
	}

	/* slow path: completion + waitqueue */
	ret = forward_via_completion(ctx, handler, syscall_nr, primary_cage,
				     args);
	threei_ctx_put(ctx);
	return ret;

forward:
	if (forward_via_ring(ctx, handler, syscall_nr, primary_cage, arg_cage,
			     args, &ret)) {
		return ret;
	}

	return forward_via_completion(ctx, handler, syscall_nr, primary_cage,
				      args);
}

long threei_forward_dispatch(pid_t cage, u32 syscall_nr, const s32 arg_cage[6],
			     unsigned long args[6])
{
	if (threei_is_thread_op(syscall_nr)) {
		return threei_inject_call(cage, syscall_nr, args);
	}

	return threei_run_in_cage_ctx(cage, syscall_nr, args);
}

/* FD Translation routine */

/* The shared routing decision, against current's table. */
static long __route_current(u32 syscall_nr, pid_t primary_cage,
			    const s32 arg_cage[6], unsigned long args[6])
{
	struct handler_result handler;

	if (get_handler(syscall_nr, &handler) == 0) {
		return forward_to_grate(&handler, syscall_nr, primary_cage,
					arg_cage, args);
	}

	if (primary_cage != 0 && primary_cage != task_tgid_nr(current)) {
		return threei_forward_dispatch(primary_cage, syscall_nr,
					       arg_cage, args);
	}

	return native_syscall(syscall_nr, args);
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
bool threei_entry(u32 syscall_nr, unsigned long args[6], long *result)
{
	struct handler_result handler;
	long verdict;

	if (get_handler(syscall_nr, &handler) == 0) {
		verdict = forward_to_grate(&handler, syscall_nr,
					   task_tgid_nr(current), NULL, args);
		if (verdict == THREEI_ALLOW) {
			return false;
		}
		*result = verdict;
		return true;
	}
	return false;
}

/*
 * verifies whether forwarder is the registered grate for (cageid,
 * syscall_nr) prevents memory leak via copy_data_between_cages (not
 * integrated yet).
 */
static bool threei_verify_forwarder(pid_t cageid, u32 syscall_nr,
				    struct task_struct *forwarder)
{
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
				    struct task_struct *forwarder)
{
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
		const s32 __user *, user_arg_cage, const unsigned long __user *,
		user_args)
{
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
				     current)) {
		return -EPERM;
	}
	*/
	return __route_current(syscall_nr, primary_cage, arg_cage_p, args);
}

/*
 * copy_data_between_cages - Moves memory between two cages'
 * address spaces via access_process_vm. Neither cage need
 * be the caller (a handler copies a cage's buffers).
 */
SYSCALL_DEFINE6(copy_data_between_cages, pid_t, src_cage, unsigned long,
		src_addr, pid_t, dst_cage, unsigned long, dst_addr, size_t, len,
		unsigned long, copytype)
{
	struct task_struct *src_task = NULL, *dst_task = NULL;
	void *buf;
	long copied, ret = 0;

	if (!len || len > THREEI_MAX_COPY) {
		return -EINVAL;
	}
	if (copytype != THREEI_COPY_MEMCPY && copytype != THREEI_COPY_STRNCPY) {
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

	if (copytype == THREEI_COPY_MEMCPY) {
		/* RawMemcpy: exact-length, all-or-nothing (UNCHANGED) */
		copied = access_process_vm(src_task, src_addr, buf, len, 0);
		if (copied != (long)len) {
			ret = -EFAULT;
			goto out;
		}
		copied = access_process_vm(dst_task, dst_addr, buf, len,
					   FOLL_WRITE);
		if (copied != (long)len) {
			ret = -EFAULT;
		}
	} else {
		/*
		* Strncpy: NUL-terminated within len, short-read tolerant
		* access_process_vm returns the bytes actually readable,
		* which is < len when the source range runs into an unmapped page
		* (the stack-edge case that made a fixed-len read EFAULT on a
		* short path). Scan the readable prefix for '\0'; copy strlen+1
		* (including the terminator).
		*/
		size_t slen;

		copied = access_process_vm(src_task, src_addr, buf, len, 0);
		if (copied <= 0) {
			ret = -EFAULT; /* not even the first byte readable */
			goto out;
		}

		slen = strnlen(buf, copied);
		if (slen == (size_t)copied) {
			/* no '\0' within the readable prefix / within len: like lind's
			* "null terminator not found within max length" */
			ret = -ENAMETOOLONG;
			goto out;
		}

		slen += 1; /* include '\0' (lind: n + 1) */

		copied = access_process_vm(dst_task, dst_addr, buf, slen,
					   FOLL_WRITE);
		if (copied != (long)slen) {
			ret = -EFAULT;
			goto out;
		}

		ret = (long)slen; /* bytes copied, including '\0' */
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
static unsigned long threei_create_ring(struct threei_grate_ctx *ctx)
{
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

	ret = remap_pfn_range(vma, uaddr, virt_to_phys(ctx->ring) >> PAGE_SHIFT,
			      PAGE_ALIGN(sizeof(struct threei_ring)),
			      vma->vm_page_prot);
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
SYSCALL_DEFINE0(threei_grate_setup)
{
	struct threei_grate_ctx *ctx;
	unsigned long uaddr;

	ctx = grate_ctx_get(current->group_leader);
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
		unsigned int, size)
{
	struct threei_grate_ctx *ctx;
	struct threei_request *req;
	struct threei_req_user out;
	unsigned long ring_uaddr;

	/*
	* The grate may not have been targeted yet; create its ctx so it can
	* block waiting rather than failing.
	*/
	ctx = grate_ctx_get(current->group_leader);
	if (!ctx) {
		return -ENOMEM;
	}

	/* establish the ring on first recv (no-op afterwards) */
	ring_uaddr = threei_create_ring(ctx);

	if (current->policy != SCHED_RR) {
		threei_promote_grate(current);
	}

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

SYSCALL_DEFINE2(threei_respond, u64, id, long, retval)
{
	struct threei_grate_ctx *ctx;
	struct threei_request *req;

	rcu_read_lock();
	ctx = rcu_dereference(current->group_leader->threei_grate_ctx);
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
int copy_threei(struct task_struct *p)
{
	struct threei_handler *handler;

	p->threei_inject = NULL;
	p->threei_grate_ctx = NULL;
	p->threei_ctx_cache = NULL;
	p->threei_ctx_borrow = NULL;
	p->threei_arena = NULL;

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
void threei_exit(struct task_struct *task)
{
	struct threei_grate_ctx *ctx;
	struct threei_handler *handler;
	struct task_struct *grate;
	struct threei_inject *inj;

	/*
	 * If we are dying mid-forward with a borrowed cage context still
	 * installed (killed while blocked in threei_run_in_cage_ctx), unwind
	 * it first.
	 */
	threei_ctx_restore_emergency(task);

	/* free the lazily-reserved arena tracker (mapping dies with the mm) */
	threei_arena_free(task);

	/*
	* If this task dies with an injected syscall still pending, unblock
	* the arming grate (waiting in threei_inject_call) so it doesn't hang.
	*/
	inj = task->threei_inject;
	if (inj) {
		task->threei_inject = NULL;
		if (atomic_cmpxchg(&inj->completed, 0, 1) == 0) {
			inj->ret = -ESRCH;
			inj->active = false;
			complete(inj->done);
		}
		threei_inject_put(inj);
	}

	/* free cache for the cage */
	threei_cache_free(task);

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
	if (task == task->group_leader) {
		task_lock(task);
		ctx = rcu_dereference_protected(
			task->threei_grate_ctx,
			lockdep_is_held(&task->alloc_lock));
		rcu_assign_pointer(task->threei_grate_ctx, NULL);
		task_unlock(task);
	}

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
