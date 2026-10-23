#ifndef _LINUX_THREEI_H
#define _LINUX_THREEI_H

#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/limits.h>
#include <linux/sched/clock.h>

/* grate related constants */
#define THREEI_INVALID_GRATEID ((pid_t) - 1)
#define THREEI_MAX_COPY (16UL << 20)

/* ring constant */
#define THREEI_SPIN_BUDGET 1700

/* fd translation */
#define THREEI_VFD_MAX 256

#define THREEI_VFD_INHERITED (pid_t)-1

#define THREEI_BUF_NONE 0
#define THREEI_BUF_IN 1
#define THREEI_BUF_OUT 2
#define THREEI_LEN_FIXED 0xff

#define THREEI_GENERIC_MAX_BUF (1UL << 20) /* 1 MiB cap per call */

enum threei_copy_type {
    THREEI_COPY_MEMCPY  = 0,   /* RawMemcpy: exact `len` bytes            */
    THREEI_COPY_STRNCPY = 1,   /* Strncpy:   NUL-terminated, bounded by len */
};


/* Per-cage virtual fdtable. Have same lifetime as threei_handler */
struct threei_fdtable {
    refcount_t refs;
    spinlock_t lock;
    struct file *file[THREEI_VFD_MAX];
    pid_t owner_grate[THREEI_VFD_MAX];
};

enum {
    THREEI_RET_IS_FD = 1 << 0,
    THREEI_FREES_FD0 = 1 << 1,
    THREEI_ARG_IS_FD_MAP = 1 << 2,
};

struct threei_fd_buf {
    u8 ptr_arg;
    u8 len_arg;
    u16 fixed_len;
    u8 dir;
};

/* per-syscall fd descriptor table. required for fd virtualization
 * since making changes to each syscall is not a viable choice.
 * It describes syscall behaviour with respect to  fd */
struct threei_fd_desc {
    u32 flags;
    u8 arg_is_fd;
    u8 map_fd;
    struct threei_fd_buf buf;
};

/* inner map of handler table. attributes grateid to handler addrress*/
struct target_map {
    /* pid of grate */
    pid_t grateid;

    /* syscall handler address */
    void *handler_addr;
};

/* Per-task threei syscall handler table. It maps syscalls that
 * grate has registered against this cage, and those syscalls to
 * grate and handler address. You can visualize it as:
 *
 *      <cageid <syscall_nr <grateid, handler_address>>>
 *
 * Uses RCU + refcount to determine lifetime of the table.
 */
struct threei_handler {
    /* reference count to manage object lifetime */
    refcount_t refs;

    /* used for dealocating ring pages and to free grate ctx */
    struct rcu_head rcu;

    /* bitmap representing registered syscall */
    DECLARE_BITMAP(registered, NR_syscalls);

    /* inner map - attributes grateid with handler address*/
    struct target_map table[NR_syscalls];
};

/* duplicate defination of handler table's inner map.
 * used for storing results (reuse target_map in the future) */
struct handler_result {
    pid_t grateid;
    void *handler_addr;
};

/*
 * Handler verdict: returned by a handler to let the cage's original
 * syscall proceed natively in the cage's own context (valid pointers,
 * correct fd table). Distinct from any real syscall return: fds are >= 0
 * and errnos are > -4096, so -4096 is unambiguous.
 */
#define THREEI_ALLOW (-4096L)

/*
 * A single forwarded syscall in flight. Lives on the cage's kernel stack
 * while the cage blocks in threei_forward_to_grate(); the grate references
 * it through the grate context lists. Valid for exactly the duration of
 * that block.
 *
 * Used by completion grate forwarding path.
 */
struct threei_request {
    u64 id;
    u32 nr;
    unsigned long args[6];
    void *handler_addr;
    pid_t cage;
    long retval;
    bool completed;
    struct completion done;
    struct list_head node;
};

struct threei_grate_ctx {
    spinlock_t lock;
    struct list_head requests;
    struct list_head inflight;
    wait_queue_head_t recv_wq;
    atomic64_t next_id;
    bool dead;
    struct threei_ring *ring;
    unsigned long ring_order;
    unsigned long ring_uaddr;
    refcount_t refs;
    struct rcu_head rcu;
};

/* execve specific args */
struct threei_exec_args {
    char path[NAME_MAX];
    char **kargv;
    char **kenvp;
};

/*
 * A pending injected syscall to run in the TARGET's own thread at its next
 * return-to-user boundary (stop-fork-resume). The slot lives on the arming
 * grate's kernel stack while it blocks in threei_inject_call(); the target's
 * threei_notify_resume() fills ret and completes done. 
 */
struct threei_inject {
    u32 nr;
    unsigned long args[6];
    long ret;
    bool active;
    atomic_t completed;
    refcount_t refs;
    struct completion *done;
};

/*
 * Transient full-context borrow taken by a grate thread running a
 * forwarded syscall as the cage (ctx.c). A non-NULL cage_* is the record
 * that a ref is held and must be restored + dropped.
 */
struct threei_ctx_borrow;

/*
 * Reserved-but-lazily-backed scratch region in a cage's address space,
 * used by a grate to stage foreign pointer args (arena.c). The kernel only
 * reserves + reports the base; the grate moves bytes via
 * copy_data_between_cages.
 */
struct threei_arena {
	unsigned long base;
	size_t size;
};

void put_handler_result(struct handler_result *res);
bool check_handler_exists(pid_t cageid);
void __drop_handlers(struct task_struct *task);
int get_handler(u32 syscall_nr, struct handler_result *out);
void rm_cage_from_handler(pid_t cageid);
void rm_grate_from_handler(pid_t grateid);
int threei_register_handler(pid_t cageid, u32 syscall_nr, pid_t grateid,
                            void *in_grate_fn_addr);
int deregister_handler(pid_t cageid, u32 syscall_nr);
int copy_handler_table_to_cage(pid_t srccageid, pid_t targetcageid);

bool threei_entry(u32 syscall_nr, unsigned long args[6], long *result);
int copy_threei(struct task_struct *p);
void threei_exit(struct task_struct *task);

long threei_forward_dispatch(pid_t cage, u32 syscall_nr, const s32 arg_cage[6],
                             unsigned long args[6]);
long threei_run_in_cage_ctx(pid_t target_cage, u32 syscall_nr,
                            unsigned long args[6]);
void threei_ctx_restore_emergency(struct task_struct *grate);

extern long native_syscall(u32 nr, unsigned long args[6]);

bool threei_is_thread_op(u32 syscall_nr);
void threei_inject_put(struct threei_inject *inj);
long threei_inject_call(pid_t target, u32 syscall_nr, unsigned long args[6]);

void threei_notify_resume(struct pt_regs *regs);

bool threei_is_thread_op(u32 syscall_nr);
void threei_inject_put(struct threei_inject *inj);
long threei_inject_call(pid_t target, u32 syscall_nr, unsigned long args[6]);
void threei_run_injected(struct threei_inject *inj);
void threei_notify_resume(struct pt_regs *regs);
bool threei_drain_injection(unsigned long self_nr, unsigned long args[6],
                            bool *run_native);

void threei_exec_commit_notify(void);

unsigned long threei_arena_get(struct task_struct *cage);
void threei_arena_free(struct task_struct *task);

int  threei_promote_grate(struct task_struct *grate);
void threei_set_cage_sched(struct task_struct *cage);
void threei_set_cfs(struct task_struct *task);

#endif // _LINUX_THREEI_H
