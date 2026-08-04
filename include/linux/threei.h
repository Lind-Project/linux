#ifndef _LINUX_THREEI_H
#define _LINUX_THREEI_H

#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/limits.h>

/* grate related constants */
#define THREEI_INVALID_GRATEID ((pid_t) - 1)
#define THREEI_MAX_COPY (16UL << 20)

/* ring constant */
#define THREEI_SPIN_BUDGET 200000

/* fd translation */
#define THREEI_VFD_MAX 256

#define THREEI_VFD_INHERITED 0

#define THREEI_BUF_NONE 0
#define THREEI_BUF_IN 1
#define THREEI_BUF_OUT 2
#define THREEI_LEN_FIXED 0xff

#define THREEI_GENERIC_MAX_BUF (1UL << 20) /* 1 MiB cap per call */

/* Per-cage virtual fdtable. Have same lifetime as threei_handler */
struct threei_fdtable {
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

    struct threei_fdtable *fdtable;
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

/* marshaling descriptor table */
/* Only syscalls listed here get their pointer arguments copied into the
 * slot's inline data[] buffer so the grate can dereference them directly.
 * Anything not listed is treated as all-scalar (no marshaling), which is
 */

/*
enum { ARG_SCALAR = 0, ARG_IN_PTR = 1 };

struct threei_arg_desc {
    u8  type;
    u32 size;   // 0 => null-terminated string (strncpy_from_user)
};

struct threei_syscall_desc {
    struct threei_arg_desc args[6];
};

const struct threei_syscall_desc threei_descs[] = {
#ifdef __NR_openat
        [__NR_openat] = { .args = {
                { ARG_SCALAR }, { ARG_IN_PTR, 0 }, { ARG_SCALAR }, {
ARG_SCALAR }, } }, #endif #ifdef __NR_open
        [__NR_open] = { .args = {
                { ARG_IN_PTR, 0 }, { ARG_SCALAR }, { ARG_SCALAR },
        } },
#endif
};
*/

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
    refcount_t refs;
    struct completion *done;
    struct threei_exec_args *exec_args;
};

void put_handler_result(struct handler_result *res);
bool check_handler_exists(pid_t cageid);
void __drop_handlers(struct task_struct *task);
bool check_cage_handler_exists(pid_t cageid);
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

extern long native_syscall(u32 nr, unsigned long args[6]);

struct threei_fdtable *threei_fdtable_get(struct threei_handler *handler);
int threei_vfd_alloc(struct threei_fdtable *table, struct file *file,
                     pid_t owner_grate);
struct file *threei_vfd_lookup(struct threei_fdtable *table, int vfd);
void threei_vfd_free(struct threei_fdtable *table, int vfd);
void threei_fdtable_teardown(struct threei_fdtable *table);
long threei_generic_fd_exec(struct threei_handler *cage_handler,
                            u32 syscall_nr,
                            const struct threei_fd_desc *desc,
                            unsigned long args[6], bool *handled);

bool threei_is_mm_op(u32 nr);
long threei_run_mm_op(u32 nr, pid_t target_cage, const s32 arg_cage[6],
                      unsigned long args[6]);

bool threei_is_thread_op(u32 syscall_nr);
void threei_inject_put(struct threei_inject *inj);
long threei_inject_call(pid_t target, u32 syscall_nr, unsigned long args[6]);
void threei_notify_resume(struct pt_regs *regs);

#endif // _LINUX_THREEI_H
