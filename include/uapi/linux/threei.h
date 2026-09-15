#ifndef _UAPI_LINUX_THREEI_H
#define _UAPI_LINUX_THREEI_H

#include <linux/types.h>

/* Request as delivered to the grate by threei_recv. */
struct threei_req_user {
	__u64	id;
	__u32	nr;
	__s32	arg_cage[6];
	__u64	args[6];
	__u64	handler_addr;
	__s32	cage;
	__u64	ring_uaddr;
};

/*
 * Handler verdict: returned by a handler to let the cage's original syscall
 * proceed natively in the cage's own context (valid pointers, correct fd
 * table). Distinct from any real syscall return: fds are >= 0 and errnos are
 * > -4096, so -4096 is unambiguous.
 */
#define THREEI_ALLOW		(-4096L)

#define THREEI_DEREGISTER	((__s32)-1)

/* shared ring (fast path) */

/* total spin budget = THREEI_SPIN_BUDGET + THREEI_RING_ROUNDS */
#define THREEI_RING_ROUNDS 8

#define THREEI_RING_SLOTS   64
#define THREEI_SLOT_DATA    512

/* slot states */
#define THREEI_SLOT_FREE    0
#define THREEI_SLOT_CLAIMED 1
#define THREEI_SLOT_PENDING 2
#define THREEI_SLOT_DONE    3

struct threei_ring_slot {
    __u32   state;
    __u32   nr;
    __s32   arg_cage[6];
    __u64   args[6];
    __u64   arg_is_ptr;
    __u64   handler_addr;
    __s32   cage;
    __s64   retval;
    __u8    data[THREEI_SLOT_DATA];
};

struct threei_ring {
    /* seperate lines: free_mask is cage-only, pending_mask is the hot
     * bitmap the grate polls continuously. keeping them apart stops a
     * polling grate from stealing the line a cage is claiming on.*/
    __u64 free_mask	__attribute__((aligned(64)));
    __u64 pending_mask	__attribute__((aligned(64)));
    struct threei_ring_slot slots[THREEI_RING_SLOTS]	__attribute__((aligned(64)));
};

#endif /* _UAPI_LINUX_THREEI_H */
