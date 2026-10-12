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

typedef long (*threei_handler_fn)(pid_t cageid, const int arg_cage[6],
                                  unsigned long args[6]);

static inline long make_threei_call(__u32 nr, pid_t primary_cage,
                                    const int arg_cage[6],
                                    unsigned long args[6]) {
    return syscall(__NR_make_threei_call, nr, primary_cage, arg_cage,
                   args);
}

static inline long
copy_data_between_cages(pid_t src_cage, unsigned long src_addr,
                        pid_t dst_cage, unsigned long dst_addr, size_t len,
                        unsigned long copytype) {
    return syscall(__NR_copy_data_between_cages, src_cage, src_addr,
                   dst_cage, dst_addr, len, copytype);
}

static inline int threei_recv(struct threei_req_user *req) {
    return (int)syscall(__NR_threei_recv, req, sizeof(*req));
}

static inline int threei_respond(__u64 id, long retval) {
    return (int)syscall(__NR_threei_respond, id, retval);
}

static inline struct threei_ring *threei_grate_setup(void) {
    long r = syscall(__NR_threei_grate_setup);

    return (r < 0) ? NULL : (struct threei_ring *)(unsigned long)r;
}

/* dispatch helpers */
static inline long __threei_dispatch(struct threei_req_user *req) {
    threei_handler_fn fn =
        (threei_handler_fn)(unsigned long)req->handler_addr;
    return fn((pid_t)req->cage, (const int *)req->arg_cage,
              (unsigned long *)req->args);
}

static inline void __threei_handle_slot(struct threei_ring_slot *slot) {
    /*
    unsigned long a[6];
    int j;

    for (j = 0; j < 6; j++) {
            if (slot->arg_is_ptr & (1ULL << j)) {
                    a[j] = (unsigned long)(slot->data + slot->args[j]);
            } else {
                    a[j] = slot->args[j];
            }
    }
    */
    threei_handler_fn fn =
        (threei_handler_fn)(unsigned long)slot->handler_addr;
    atomic_store_explicit((atomic_uint *)&slot->state, THREEI_SLOT_CLAIMED,
                          memory_order_release);
    slot->retval = (long)fn((pid_t)slot->cage, (const int *)slot->arg_cage,
                            (unsigned long *)slot->args);

    atomic_store_explicit((atomic_uint *)&slot->state, THREEI_SLOT_DONE,
                          memory_order_release);
}

static inline void __threei_pin_self(int cpu) {
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
}

#ifndef THREEI_RT_POLICY
#define THREEI_RT_POLICY SCHED_RR
#endif
#ifndef THREEI_GRATE_RT_PRIO
#define THREEI_GRATE_RT_PRIO 99
#endif
#ifndef THREEI_CAGE_RT_PRIO
#define THREEI_CAGE_RT_PRIO 1
#endif
#if THREEI_GRATE_RT_PRIO > 0 && THREEI_CAGE_RT_PRIO >= THREEI_GRATE_RT_PRIO
#error
    "THREEI_CAGE_RT_PRIO must be less priority than THREEI_GRATE_RT_PRIO"
#endif

/*
 * servicer's priority once its promotion has been attempted:
 * -1 not yet, 0 if failed (fallbacks to SCHED_OTHER), else it got lower
 *  priority than requested if RLIMIT_RTPRIO clamped it.
 */
static atomic_int __threei_services_prio = -1;

static int __threei_rt_promote_self(int priority) {
    struct sched_param sp;
    struct rlimit r1;
    int max = sched_get_priority_max(THREEI_RT_POLICY);

    if (priority <= 0) {
        return 0;
    }
    if (max > 0 && priority > max) {
        priority = max;
    }
    sp.sched_priority = priority;
    if (sched_setscheduler(0, THREEI_RT_POLICY | SCHED_RESET_ON_FORK,
                           &sp) == 0) {
        return priority;
    }

    if (errno == EPERM && getrlimit(RLIMIT_RTPRIO, &r1) == 0 &&
        r1.rlim_cur != RLIM_INFINITY && r1.rlim_cur >= 1 &&
        (int)r1.rlim_cur < priority) {
        sp.sched_priority = (int)r1.rlim_cur;
        if (sched_setscheduler(0, THREEI_RT_POLICY | SCHED_RESET_ON_FORK,
                               &sp) == 0) {
            return sp.sched_priority;
        }
    }
    return 0;
}

static void __threei_cfs(pid_t pid) {
    struct sched_param sp = {.sched_priority = 0};
    int pol = sched_getscheduler(pid);

    if (pol < 0) {
        return;
    }
    pol &= ~SCHED_RESET_ON_FORK;
    if (pol == SCHED_FIFO || pol == SCHED_RR) {
        sched_setscheduler(pid, SCHED_OTHER, &sp);
    }
}

/*
 * sets THREEI_RT_POLICY for a cage, strictly below the servicer's policy.
 * fails back to SCHED_OTHER if the servicer is not RT.
 *
 * RESET_ON_FORK: the cage's own children and threads start in CFS, so an
 * untrusted cage cannot multiply RT tasks. Requires CAP_SYS_NICE to clear
 * the flag.
 * */
static void __threei_cage_sched(pid_t cage) {
    int sp_prio = atomic_load_explicit(&__threei_services_prio,
                                       memory_order_acquire);
    int priority = THREEI_CAGE_RT_PRIO;

    if (priority > sp_prio - 1) {
        /* stay below the servicer */
        priority = sp_prio - 1;
    }
    if (priority >= 1) {
        struct sched_param sp = {.sched_priority = priority};

        if (sched_setscheduler(
                cage, THREEI_RT_POLICY | SCHED_RESET_ON_FORK, &sp) == 0) {
            return;
        }
        fprintf(stderr, "threei: cage %d stays SCHED_OTHER (%s)\n",
                (int)(cage), strerror(errno));
    }
    __threei_cfs(cage);
}

/*
 * Transparent runtime: state + constructor + spin loop.
 * All state and functions are static: one copy, one constructor
 * invocation, one spin thread. The grate must be a single translation
 * unit.
 */
static struct threei_ring *__threei_ring;
static pthread_t __threei_spin_thread;
static pthread_t __threei_recv_thread;
static atomic_int __threei_cage_pid = -1;
static pthread_once_t __threei_once = PTHREAD_ONCE_INIT;
static atomic_int __threei_pin_cpu = -1;
static cpu_set_t __threei_orig_mask;

static void *__threei_recv_loop(void *arg) {
    int pinned = -1;
    (void)arg;

#if THREEI_GRATE_RT_PRIO > 0
    /*
     * Only this thread is promoted: it is the one the cage waits on.
     * RESET_ON_FORK keeps a handler that forks from leaking RT to
     * children.
     */
    {
        int priority = __threei_rt_promote_self(THREEI_GRATE_RT_PRIO);

        if (priority == 0) {
            fprintf(stderr,
                    "threei: servicer stays SCHED_OTHER (needs "
                    "CAP_SYS_NICE or RLIMIT_RTPRIO); cages stay in "
                    "CFS too\n");
        }
        atomic_store_explicit(&__threei_services_prio, priority,
                              memory_order_release);
    }
#endif
    for (;;) {
        struct threei_req_user req;
        int cpu =
            atomic_load_explicit(&__threei_pin_cpu, memory_order_relaxed);

        if (cpu >= 0 && cpu != pinned) {
            __threei_pin_self(cpu);
            pinned = cpu;
        }

        if (threei_recv(&req) < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            return NULL;
        }
        threei_respond(req.id, __threei_dispatch(&req));
    }
}

static int register_handler(pid_t srccage, __u32 nr, pid_t dest_grate,
                            unsigned long handler_addr) {
    int expected = -1;
    int ret;
    atomic_compare_exchange_strong(&__threei_cage_pid, &expected,
                                   (int)srccage);

    ret = (int)syscall(__NR_register_handler, srccage, nr, dest_grate,
                       handler_addr);

#ifndef THREEI_NO_RUNTIME
    if (ret == 0 && dest_grate == getpid()) {
        int cpu =
            atomic_load_explicit(&__threei_pin_cpu, memory_order_acquire);
        cpu_set_t one;

        if (cpu < 0) {
            cpu = sched_getcpu();
            atomic_store_explicit(&__threei_pin_cpu, cpu,
                                  memory_order_relaxed);
        }
        CPU_ZERO(&one);
        CPU_SET(cpu, &one);
        sched_setaffinity(srccage, sizeof(one), &one);
    }
#endif

#if THREEI_GRATE_RT_PRIO > 0
    if (ret == 0) {
        struct rlimit none = {0, 0};
        /* policy first: without CAP_SYS_NICE it is checked against the
         * cage's RLIMIT_RTPRIO, which is about to become 0 */
        __threei_cage_sched(srccage);

        prlimit(srccage, RLIMIT_RTPRIO, &none, NULL);
    }
#endif
    return ret;
}

static void *__threei_spin_loop(void *arg) {
    struct threei_ring *ring = __threei_ring;
    _Atomic unsigned long long *pending =
        (_Atomic unsigned long long *)&ring->pending_mask;
    unsigned idle = 0;
    (void)arg;

    /* a busy-poller must never be RT */
    __threei_cfs(0);

    /* poll from any cpu we started with except the one the services and cage
     * share: a poller on that core would compete wit cage it serves */
    {
	cpu_set_t mask = __threei_orig_mask;
	int pc = atomic_load_explicit(&__threei_pin_cpu, memory_order_acquire);

	if (pc >= 0) {
	    CPU_CLR(pc, &mask);
	}
	if (CPU_COUNT(&mask) > 0) {
	    pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask);
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
                pid_t c = (pid_t)atomic_load(&__threei_cage_pid);

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

static void __threei_do_init(void) {
    struct threei_ring *ring = threei_grate_setup();
    int cpu __attribute__((unused));

    if (!ring) {
        return;
    }
    __threei_ring = ring;

#ifndef THREEI_NO_PIN
    cpu = sched_getcpu();
    __threei_pin_self(cpu);
    atomic_store_explicit(&__threei_pin_cpu, cpu, memory_order_relaxed);
#endif
    /* ring poller only if there is a cpu other than the pinned one: on a
     * single allowed cpu (e.g. taskset -c 1) it could only steal the cage's
     * core, so the ring stays unserviced and cages use the completion path */
    {
	cpu_set_t others = __threei_orig_mask;
	int pc = atomic_load_explicit(&__threei_pin_cpu, memory_order_relaxed);

	if (pc >= 0) {
	    CPU_CLR(pc, &others);
	}
	if (CPU_COUNT(&others) > 0) {
	    pthread_create(&__threei_spin_thread, NULL, memory_order_relaxed, NULL);
	}
    }
    if (pthread_create(&__threei_recv_thread, NULL, __threei_recv_loop,
                       NULL) != 0) {
        return;
    }
#if THREEI_GRATE_RT_PRIO > 0
    /* wait once before main for the servicer to settle its priority, so
       register_handler knows where cages may go */
    while (atomic_load_explicit(&__threei_services_prio,
                                memory_order_acquire) < 0) {
        sched_yield();
    }
#endif
}

#ifndef THREEI_NO_RUNTIME
__attribute__((constructor)) static void __threei_library_init(void) {
    pthread_once(&__threei_once, __threei_do_init);
}
#endif

static void *__threei_spin_loop(void *arg) __attribute__((unused));
static void *__threei_recv_loop(void *arg) __attribute__((unused));

#endif /* _TOOLS_THREEI_H */
