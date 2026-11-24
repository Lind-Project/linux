#ifndef _TOOLS_THREEI_H
#define _TOOLS_THREEI_H

#include <errno.h>
#include <linux/sched.h>
#include <linux/threei.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef THREEI_COPY_MEMCPY
#define THREEI_COPY_MEMCPY 0 /* exact `len` bytes */
#endif
#ifndef THREEI_COPY_STRNCPY
#define THREEI_COPY_STRNCPY 1 /* NUL-terminated, bounded by len */
#endif

#ifndef THREEI_NR_POLLERS
#define THREEI_NR_POLLERS 0
#endif

typedef long (*threei_handler_fn)(pid_t cageid, const int arg_cage[6],
				  unsigned long args[6]);

static inline long make_threei_call(__u32 nr, pid_t primary_cage,
				    const int arg_cage[6],
				    unsigned long args[6])
{
	long ret;
	register long r10 __asm__("r10") = (long)args; /* 4th arg: user_args */
	__asm__ volatile("syscall"
			 : "=a"(ret)
			 : "a"((long)__NR_make_threei_call),
			   "D"((long)nr), /* rdi = syscall_nr   */
			   "S"((long)primary_cage), /* rsi = primary_cage */
			   "d"((long)arg_cage), /* rdx = user_arg_cage*/
			   "r"(r10)
			 : "rcx", "r11", "memory");
	return ret;
}

static inline long copy_data_between_cages(pid_t src_cage,
					   unsigned long src_addr,
					   pid_t dst_cage,
					   unsigned long dst_addr, size_t len,
					   unsigned long copytype)
{
	return syscall(__NR_copy_data_between_cages, src_cage, src_addr,
		       dst_cage, dst_addr, len, copytype);
}

static inline int copy_handler_table_to_cage(pid_t srccage, pid_t targetcage)
{
	return (int)syscall(__NR_copy_handler_table_to_cage, srccage, targetcage);
}

static inline int threei_recv(struct threei_req_user *req, pid_t cage_tid)
{
	return (int)syscall(__NR_threei_recv, req, sizeof(*req), cage_tid);
}

static inline long threei_wait_spawn(void)
{
	return syscall(__NR_threei_wait_spawn);
}

static inline int threei_respond(__u64 id, long retval)
{
	return (int)syscall(__NR_threei_respond, id, retval);
}

static inline struct threei_ring *threei_grate_setup(void)
{
	long r = syscall(__NR_threei_grate_setup);

	return (r < 0) ? NULL : (struct threei_ring *)(unsigned long)r;
}

/* dispatch helpers */
static inline long __threei_dispatch(struct threei_req_user *req)
{
	threei_handler_fn fn =
		(threei_handler_fn)(unsigned long)req->handler_addr;
	return fn((pid_t)req->cage, (const int *)req->arg_cage,
		  (unsigned long *)req->args);
}


static inline void __threei_pin_self(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
}

/*
 * Transparent runtime: state + constructor + spin loop.
 * All state and functions are static: one copy, one constructor
 * invocation, one spin thread. The grate must be a single translation
 * unit.
 */
static struct threei_ring *__threei_ring;
static atomic_int __threei_cage_pid = -1;
static pthread_once_t __threei_once = PTHREAD_ONCE_INIT;
static atomic_int __threei_pin_cpu = -1;
static cpu_set_t __threei_orig_mask;
static pthread_mutex_t __threei_core_lock = PTHREAD_MUTEX_INITIALIZER;
static cpu_set_t __threei_free_cores;
static int __threei_cores_init;

static int __threei_core_acquire(void)
{
	int cpu = -1, c;

	pthread_mutex_lock(&__threei_core_lock);
	if (!__threei_cores_init) {
		__threei_free_cores = __threei_orig_mask;
		__threei_cores_init = 1;
	}
	for (c = 0; c < CPU_SETSIZE; c++) {
		if (CPU_ISSET(c, &__threei_free_cores)) {
			CPU_CLR(c, &__threei_free_cores);
			cpu = c;
			break;
		}
	}
	pthread_mutex_unlock(&__threei_core_lock);
	return cpu;
}

static void __threei_core_release(int cpu)
{
	if (cpu < 0) {
		return;
	}
	pthread_mutex_lock(&__threei_core_lock);
	CPU_SET(cpu, &__threei_free_cores);
	pthread_mutex_unlock(&__threei_core_lock);
}

/* one servicer per cage thread; follows the cage thread's cpu */
static void *__threei_servicer(void *arg)
{
	pid_t tid = (pid_t)(long)arg;
	int cpu = __threei_core_acquire();

	if (cpu >= 0) {
		cpu_set_t set;

		CPU_ZERO(&set);
		CPU_SET(cpu, &set);
		sched_setaffinity(tid, sizeof(set), &set);
		__threei_pin_self(cpu);
	}

	for (;;) {
		struct threei_req_user req;

		if (threei_recv(&req, tid) < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			}
			break; /* -ESRCH: cage thread exited */
		}
		threei_respond(req.id, __threei_dispatch(&req));
	}
	__threei_core_release(cpu);
	return NULL;
}

static inline int threei_run(void)
{
	for (;;) {
		long tid = threei_wait_spawn();

		if (tid < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			}
			return 0;
		}

		pthread_t srv;
		if (pthread_create(&srv, NULL, __threei_servicer,
				   (void *)(long)tid) == 0) {
			pthread_detach(srv);
		}
	}
}

static void *__threei_manager_loop(void *arg)
{
	(void)arg;
	threei_run();
	return NULL;
}

static int register_handler(pid_t srccage, __u32 nr, pid_t dest_grate,
			    unsigned long handler_addr)
{
	int expected = -1;
	int ret;
	atomic_compare_exchange_strong(&__threei_cage_pid, &expected,
				       (int)srccage);

	ret = (int)syscall(__NR_register_handler, srccage, nr, dest_grate,
			   handler_addr);

#ifndef THREEI_NO_RUNTIME
	if (ret == 0 && dest_grate == getpid()) {
		atomic_store_explicit(&__threei_pin_cpu, sched_getcpu(),
				      memory_order_release);
	}
#endif

	return ret;
}

static inline void __threei_handle_slot(struct threei_ring_slot *slot)
{
	threei_handler_fn fn =
		(threei_handler_fn)(unsigned long)slot->handler_addr;
	atomic_store_explicit((atomic_uint *)&slot->state, THREEI_SLOT_CLAIMED,
			      memory_order_release);
	slot->retval = (long)fn((pid_t)slot->cage, (const int *)slot->arg_cage,
				(unsigned long *)slot->args);

	atomic_store_explicit((atomic_uint *)&slot->state, THREEI_SLOT_DONE,
			      memory_order_release);
}

static void *__threei_spin_loop(void *arg)
{
	struct threei_ring *ring = __threei_ring;
	_Atomic unsigned long long *pending =
		(_Atomic unsigned long long *)&ring->pending_mask;
	unsigned idle = 0;
	(void)arg;

	/* poll from any cpu we started with except the one the services and
     * cage share: a poller on that core would compete wit cage it serves */
	{
		cpu_set_t mask = __threei_orig_mask;
		int pc = atomic_load_explicit(&__threei_pin_cpu,
					      memory_order_acquire);

		if (pc >= 0) {
			CPU_CLR(pc, &mask);
		}
		if (CPU_COUNT(&mask) > 0) {
			pthread_setaffinity_np(pthread_self(), sizeof(mask),
					       &mask);
		}
	}

	/* announce that this ring now has a poller */
	atomic_store_explicit((_Atomic unsigned *)&ring->serviced, 1,
			      memory_order_release);

	for (;;) {
		unsigned long long mask =
			atomic_load_explicit(pending, memory_order_acquire);
		unsigned long long bit;
		int i;

		if (!mask) {
			__asm__ volatile("pause" ::: "memory");
			if ((++idle & 0xFFFF) == 0) {
				pid_t c =
					(pid_t)atomic_load(&__threei_cage_pid);

				if (c > 0 && waitpid(c, NULL, WNOHANG) == c) {
					goto stop;
				}
			}
			if (idle >= THREEI_GRATE_IDLE_BUDGET) {
				goto stop;
			}
			continue;
		}

		idle = 0;

		i = __builtin_ctzll(mask); /* get lowest pending bit slot */
		bit = 1ULL << i;

		if (!(atomic_fetch_and_explicit(pending, ~bit,
						memory_order_acq_rel) &
		      bit)) {
			continue; /* cage reclamimed it, or a peer won */
		}
		__threei_handle_slot(&ring->slots[i]);
	}
stop:
	/*
     * Tell cages to stop using the ring BEFORE this thread disappears.
     * Without this they would spin 8x our idle budget on every forward,
     * forever.
     */
	atomic_store_explicit((_Atomic unsigned *)&ring->serviced, 0,
			      memory_order_release);
	return NULL;
}

/*
 * Start the shared-ring poller pool. Each poller runs __threei_spin_loop,
 * self-affinitizes off the registering core, and cooperatively drains the
 * ring's pending_mask, so several pollers service a multi-threaded cage's fast
 * path in parallel. Skipped entirely under THREEI_NO_RING.
 */
static void __threei_start_pollers(void)
{
#ifndef THREEI_NO_RING
	int n = THREEI_NR_POLLERS;
	int i;

	if (n < 1) {
		n = 1;
	}

	for (i = 0; i < n; i++) {
		pthread_t p;

		if (pthread_create(&p, NULL, __threei_spin_loop, NULL) == 0) {
			pthread_detach(p);
		}
	}
#endif
}

static void __threei_do_init(void)
{
	struct threei_ring *ring = threei_grate_setup();

	if (!ring) {
		return;
	}
	__threei_ring = ring;

	/* save original cpu mask. poller needs a core other than
	* servicer's/cages's */
	if (sched_getaffinity(0, sizeof(__threei_orig_mask),
			      &__threei_orig_mask) != 0) {
		CPU_ZERO(&__threei_orig_mask);
	}

	__threei_start_pollers();

	pthread_t mgr;
	if (pthread_create(&mgr, NULL, __threei_manager_loop, NULL) == 0) {
		pthread_detach(mgr);
	}
}

#ifndef THREEI_NO_RUNTIME
__attribute__((constructor)) static void __threei_library_init(void)
{
	pthread_once(&__threei_once, __threei_do_init);
}
#endif

#endif /* _TOOLS_THREEI_H */
