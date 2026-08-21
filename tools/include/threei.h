#ifndef _TOOLS_THREEI_H
#define _TOOLS_THREEI_H

#include <errno.h>
#include <linux/sched.h>
#include <linux/threei.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
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

static inline long copy_data_between_cages(pid_t src_cage,
                                              unsigned long src_addr,
                                              pid_t dst_cage,
                                              unsigned long dst_addr,
                                              size_t len,
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
    slot->retval = (long)fn((pid_t)slot->cage, (const int *)slot->arg_cage,
                            (unsigned long *)slot->args);

    atomic_store_explicit((atomic_uint *)&slot->state, THREEI_SLOT_DONE,
                          memory_order_release);
}

/*
static inline int threei_pin_self(int cpu) {
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    return sched_setaffinity(0, sizeof(set), &set);
}
*/

/*
 * Transparent runtime: state + constructor + spin loop.
 * All state and functions are static: one copy, one constructor
 * invocation, one spin thread. The grate must be a single translation unit.
 */
static struct threei_ring *__threei_ring;
static pthread_t __threei_spin_thread;
static atomic_int __threei_cage_pid = -1;
static pthread_once_t __threei_once = PTHREAD_ONCE_INIT;

static int register_handler(pid_t srccage, __u32 nr, pid_t dest_grate,
                            unsigned long handler_addr) {
    int expected = -1;
    atomic_compare_exchange_strong(&__threei_cage_pid, &expected,
                                   (int)srccage);

    return (int)syscall(__NR_register_handler, srccage, nr, dest_grate,
                        handler_addr);
}

static void *__threei_spin_loop(void *arg) {
    struct threei_ring *ring = __threei_ring;
    (void)arg;

    for (;;) {
        int i, found = 0;

        for (i = 0; i < (int)ring->nr_slots; i++) {
            struct threei_ring_slot *slot = &ring->slots[i];

            unsigned expected = THREEI_SLOT_PENDING;
            /*
             * Atomically CLAIM the slot (PENDING -> CLAIMED) before handling.
             * The compare-exchange ensures exactly one dispatch per slot.
             */
            if (!atomic_compare_exchange_strong_explicit(
                    (atomic_uint *)&slot->state, &expected,
                    THREEI_SLOT_CLAIMED,
                    memory_order_acq_rel, memory_order_acquire)) {
                continue;   /* not PENDING, or another pass claimed it */
            }
            found = 1;
            __threei_handle_slot(slot);
        }
        if (!found) {
            __asm__ volatile("pause" ::: "memory");
            {
                pid_t c = (pid_t)atomic_load(&__threei_cage_pid);

                if (c > 0 && waitpid(c, NULL, WNOHANG) == c) {
                    return NULL;
                }
            }
        }
    }
}

static void __threei_do_init(void) {
    struct threei_ring *ring = threei_grate_setup();

    if (!ring) {
        return;
    }
    __threei_ring = ring;
    pthread_create(&__threei_spin_thread, NULL, __threei_spin_loop, NULL);
}

__attribute__((constructor)) static void __threei_library_init(void) {
    pthread_once(&__threei_once, __threei_do_init);
}

#endif /* _TOOLS_THREEI_H */
