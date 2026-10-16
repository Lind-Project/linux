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
        atomic_store_explicit(&__threei_pin_cpu, sched_getcpu(),
                              memory_order_release);
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

    /* poll from any cpu we started with except the one the services and
     * cage share: a poller on that core would compete wit cage it serves */
    {
        cpu_set_t mask = __threei_orig_mask;
        int pc =
            atomic_load_explicit(&__threei_pin_cpu, memory_order_acquire);

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

    /* save original cpu mask. poller needs a core other than
     * servicer's/cages's */
    if (sched_getaffinity(0, sizeof(__threei_orig_mask),
                          &__threei_orig_mask) != 0) {
        CPU_ZERO(&__threei_orig_mask);
    }

#ifndef THREEI_NO_PIN
    cpu = sched_getcpu();
    __threei_pin_self(cpu);
    atomic_store_explicit(&__threei_pin_cpu, cpu, memory_order_relaxed);
#endif
    /* ring poller only if there is a cpu other than the pinned one: on a
     * single allowed cpu (e.g. taskset -c 1) it could only steal the
     * cage's core, so the ring stays unserviced and cages use the
     * completion path */
    {
        cpu_set_t others = __threei_orig_mask;
        int pc =
            atomic_load_explicit(&__threei_pin_cpu, memory_order_relaxed);

        if (pc >= 0) {
            CPU_CLR(pc, &others);
        }
        if (CPU_COUNT(&others) > 0) {
            pthread_create(&__threei_spin_thread, NULL, __threei_spin_loop,
                           NULL);
        }
    }
    if (pthread_create(&__threei_recv_thread, NULL, __threei_recv_loop,
                       NULL) != 0) {
        return;
    }
}

#ifndef THREEI_NO_RUNTIME
__attribute__((constructor)) static void __threei_library_init(void) {
    pthread_once(&__threei_once, __threei_do_init);
}
#endif

static void *__threei_spin_loop(void *arg) __attribute__((unused));
static void *__threei_recv_loop(void *arg) __attribute__((unused));

#endif /* _TOOLS_THREEI_H */
