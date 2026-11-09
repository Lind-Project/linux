#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/threei.h>
#include <linux/threei_types.h>

enum threei_argkind {
	THREEI_A_SCALAR = 0, /* pass through */
	THREEI_A_STR, /* NUL-terminated string (input) */
	THREEI_A_BUF_IN, /* counted buffer (input); byte length is args[len_arg] */
	THREEI_A_BUF_FIX,
	THREEI_A_IOVEC,
};

struct threei_argdesc {
	u8 kind;
	u8 len_arg;
	u16 fixed_len;
};
struct threei_sysdesc {
	u8 described;
	struct threei_argdesc args[6];
};

/*
 * Keyed by __NR_*, so numbers are whatever this kernel assigns. Classic/legacy
 * entries are unguarded (present on x86-64); post-3.x and brand-new ones are
 * #ifdef-guarded so this builds on a kernel that lacks them.
 */
static const struct threei_sysdesc threei_desc[NR_syscalls] = {

	/* path: one string */
	[__NR_open] = { 1, { [0] = { THREEI_A_STR } } },
	[__NR_openat] = { 1, { [1] = { THREEI_A_STR } } },
	[__NR_creat] = { 1, { [0] = { THREEI_A_STR } } },
	[__NR_stat] = { 1, { [0] = { THREEI_A_STR } } },
	[__NR_lstat] = { 1, { [0] = { THREEI_A_STR } } },
	[__NR_access] = { 1, { [0] = { THREEI_A_STR } } },
	[__NR_newfstatat] = { 1, { [1] = { THREEI_A_STR } } }, /* statbuf OUT */
	[__NR_faccessat] = { 1, { [1] = { THREEI_A_STR } } },
	[__NR_readlink] = { 1, { [0] = { THREEI_A_STR } } }, /* buf OUT */
	[__NR_readlinkat] = { 1, { [1] = { THREEI_A_STR } } }, /* buf OUT */
	[__NR_chdir] = { 1, { [0] = { THREEI_A_STR } } },
	[__NR_chmod] = { 1, { [0] = { THREEI_A_STR } } },
	[__NR_fchmodat] = { 1, { [1] = { THREEI_A_STR } } },
	[__NR_chown] = { 1, { [0] = { THREEI_A_STR } } },
	[__NR_lchown] = { 1, { [0] = { THREEI_A_STR } } },
	[__NR_fchownat] = { 1, { [1] = { THREEI_A_STR } } },
	[__NR_mkdir] = { 1, { [0] = { THREEI_A_STR } } },
	[__NR_mkdirat] = { 1, { [1] = { THREEI_A_STR } } },
	[__NR_rmdir] = { 1, { [0] = { THREEI_A_STR } } },
	[__NR_unlink] = { 1, { [0] = { THREEI_A_STR } } },
	[__NR_unlinkat] = { 1, { [1] = { THREEI_A_STR } } },
	[__NR_mknod] = { 1, { [0] = { THREEI_A_STR } } },
	[__NR_mknodat] = { 1, { [1] = { THREEI_A_STR } } },
	[__NR_truncate] = { 1, { [0] = { THREEI_A_STR } } },
	[__NR_statfs] = { 1, { [0] = { THREEI_A_STR } } }, /* buf OUT */
	[__NR_chroot] = { 1, { [0] = { THREEI_A_STR } } },
	[__NR_acct] = { 1, { [0] = { THREEI_A_STR } } },
	[__NR_swapon] = { 1, { [0] = { THREEI_A_STR } } },
	[__NR_swapoff] = { 1, { [0] = { THREEI_A_STR } } },
	[__NR_umount2] = { 1,
			   { [0] = { THREEI_A_STR } } }, /* entry: sys_umount(name, flags) */
	[__NR_inotify_add_watch] = { 1, { [1] = { THREEI_A_STR } } },
	[__NR_execve] = { 1,
			  { [0] = { THREEI_A_STR } } }, /* argv/envp: vectors, not staged */

	/* path: two strings */
	[__NR_rename] = { 1,
			  { [0] = { THREEI_A_STR }, [1] = { THREEI_A_STR } } },
	[__NR_renameat] = { 1,
			    { [1] = { THREEI_A_STR }, [3] = { THREEI_A_STR } } },
	[__NR_link] = { 1, { [0] = { THREEI_A_STR }, [1] = { THREEI_A_STR } } },
	[__NR_linkat] = { 1,
			  { [1] = { THREEI_A_STR }, [3] = { THREEI_A_STR } } },
	[__NR_symlink] = { 1,
			   { [0] = { THREEI_A_STR }, [1] = { THREEI_A_STR } } },
	[__NR_symlinkat] = { 1,
			     { [0] = { THREEI_A_STR }, [2] = { THREEI_A_STR } } },
	[__NR_pivot_root] = { 1,
			      { [0] = { THREEI_A_STR }, [1] = { THREEI_A_STR } } },

	/* mount: src, target, fstype (data is fs-specific; left alone) */
	[__NR_mount] = { 1,
			 { [0] = { THREEI_A_STR },
			   [1] = { THREEI_A_STR },
			   [2] = { THREEI_A_STR } } },

	/* xattr: path+name strings; value BUF_IN on set, OUT on get */
	[__NR_setxattr] = { 1,
			    { [0] = { THREEI_A_STR },
			      [1] = { THREEI_A_STR },
			      [2] = { THREEI_A_BUF_IN, 3 } } },
	[__NR_lsetxattr] = { 1,
			     { [0] = { THREEI_A_STR },
			       [1] = { THREEI_A_STR },
			       [2] = { THREEI_A_BUF_IN, 3 } } },
	[__NR_fsetxattr] = { 1,
			     { [1] = { THREEI_A_STR },
			       [2] = { THREEI_A_BUF_IN, 3 } } },
	[__NR_getxattr] = { 1,
			    { [0] = { THREEI_A_STR },
			      [1] = { THREEI_A_STR } } }, /* value OUT */
	[__NR_lgetxattr] = { 1,
			     { [0] = { THREEI_A_STR }, [1] = { THREEI_A_STR } } },
	[__NR_fgetxattr] = { 1, { [1] = { THREEI_A_STR } } },
	[__NR_removexattr] = { 1,
			       { [0] = { THREEI_A_STR },
				 [1] = { THREEI_A_STR } } },
	[__NR_lremovexattr] = { 1,
				{ [0] = { THREEI_A_STR },
				  [1] = { THREEI_A_STR } } },
	[__NR_fremovexattr] = { 1, { [1] = { THREEI_A_STR } } },
	[__NR_listxattr] = { 1, { [0] = { THREEI_A_STR } } }, /* list OUT */
	[__NR_llistxattr] = { 1, { [0] = { THREEI_A_STR } } },

	/* keys */
	[__NR_add_key] = { 1,
			   { [0] = { THREEI_A_STR },
			     [1] = { THREEI_A_STR },
			     [2] = { THREEI_A_BUF_IN, 3 } } },
	[__NR_request_key] = { 1,
			       { [0] = { THREEI_A_STR },
				 [1] = { THREEI_A_STR },
				 [2] = { THREEI_A_STR } } },

	/* modules */
	[__NR_init_module] = { 1,
			       { [0] = { THREEI_A_BUF_IN, 1 },
				 [2] = { THREEI_A_STR } } },
	[__NR_finit_module] = { 1, { [1] = { THREEI_A_STR } } },
	[__NR_delete_module] = { 1, { [0] = { THREEI_A_STR } } },

	/* host/domain names (counted) */
	[__NR_sethostname] = { 1, { [0] = { THREEI_A_BUF_IN, 1 } } },
	[__NR_setdomainname] = { 1, { [0] = { THREEI_A_BUF_IN, 1 } } },

	/* counted input buffers */
	[__NR_write] = { 1, { [1] = { THREEI_A_BUF_IN, 2 } } },
	[__NR_pwrite64] = { 1, { [1] = { THREEI_A_BUF_IN, 2 } } },

	/* sockets: sockaddr / optval carry explicit lengths */
	[__NR_connect] = { 1, { [1] = { THREEI_A_BUF_IN, 2 } } },
	[__NR_bind] = { 1, { [1] = { THREEI_A_BUF_IN, 2 } } },
	[__NR_sendto] = { 1,
			  { [1] = { THREEI_A_BUF_IN, 2 },
			    [4] = { THREEI_A_BUF_IN, 5 } } },
	[__NR_setsockopt] = { 1, { [3] = { THREEI_A_BUF_IN, 4 } } },

	/* signal masks: sigset is exactly sigsetsize bytes */
	[__NR_rt_sigprocmask] = { 1,
				  { [1] = { THREEI_A_BUF_IN,
					    3 } } }, /* oldset[2] OUT */
	[__NR_rt_sigsuspend] = { 1, { [0] = { THREEI_A_BUF_IN, 1 } } },

	/* iovec vectors: writev-family is INPUT. readv-family is OUTPUT
	 * (fills the cage's own buffers) and stays undescribed. The whole
	 * vector -- the array and every iov_base -- is owned by arg_cage[iov]. */
	[__NR_writev] = { 1, { [1] = { THREEI_A_IOVEC, 2 } } },
	[__NR_pwritev] = { 1, { [1] = { THREEI_A_IOVEC, 2 } } },
#ifdef __NR_pwritev2
	[__NR_pwritev2] = { 1, { [1] = { THREEI_A_IOVEC, 2 } } },
#endif

	/* fixed-size struct inputs (no length arg; size via sizeof)
	 * len_arg is 0/unused; the third initializer is fixed_len. */
	[__NR_nanosleep] = { 1,
			     { [0] = { THREEI_A_BUF_FIX, 0,
				       sizeof(struct __kernel_timespec) } } }, /* rmtp[1] OUT */
	[__NR_clock_nanosleep] = { 1,
				   { [2] = { THREEI_A_BUF_FIX, 0,
					     sizeof(struct __kernel_timespec) } } }, /* rmtp[3] OUT */
	[__NR_clock_settime] = { 1,
				 { [1] = { THREEI_A_BUF_FIX, 0,
					   sizeof(struct __kernel_timespec) } } },
	[__NR_timer_settime] = { 1,
				 { [2] = { THREEI_A_BUF_FIX, 0,
					   sizeof(struct __kernel_itimerspec) } } }, /* old[3] OUT */
	[__NR_timerfd_settime] = { 1,
				   { [2] = { THREEI_A_BUF_FIX, 0,
					     sizeof(struct __kernel_itimerspec) } } }, /* old[3] OUT */
	[__NR_utimensat] = { 1,
			     { [1] = { THREEI_A_STR },
			       [2] = { THREEI_A_BUF_FIX, 0,
				       2 * sizeof(struct __kernel_timespec) } } },

	/* quota / memfd (old enough to be unguarded on x86-64) */
	[__NR_quotactl] = { 1,
			    { [1] = { THREEI_A_STR } } }, /* special; addr[3] cmd-specific */
	[__NR_memfd_create] = { 1, { [0] = { THREEI_A_STR } } },

/* newer syscalls (guarded: may be absent on your build) */
#ifdef __NR_openat2
	[__NR_openat2] = { 1,
			   { [1] = { THREEI_A_STR },
			     [2] = { THREEI_A_BUF_IN,
				     3 } } }, /* how: open_how of usize */
#endif
#ifdef __NR_statx
	[__NR_statx] = { 1, { [1] = { THREEI_A_STR } } }, /* statxbuf OUT */
#endif
#ifdef __NR_execveat
	[__NR_execveat] = { 1, { [1] = { THREEI_A_STR } } },
#endif
#ifdef __NR_renameat2
	[__NR_renameat2] = { 1,
			     { [1] = { THREEI_A_STR }, [3] = { THREEI_A_STR } } },
#endif
#ifdef __NR_faccessat2
	[__NR_faccessat2] = { 1, { [1] = { THREEI_A_STR } } },
#endif
#ifdef __NR_fchmodat2
	[__NR_fchmodat2] = { 1, { [1] = { THREEI_A_STR } } },
#endif
#ifdef __NR_name_to_handle_at
	[__NR_name_to_handle_at] = { 1,
				     { [1] = { THREEI_A_STR } } }, /* handle OUT */
#endif
#ifdef __NR_fanotify_mark
	/* pathname is arg[4] on x86-64 (non-split-arg64); it is arg[5] under
	 * CONFIG_ARCH_SPLIT_ARG64 (32-bit arches). */
	[__NR_fanotify_mark] = { 1, { [4] = { THREEI_A_STR } } },
#endif
#ifdef __NR_mq_open
	[__NR_mq_open] = { 1,
			   { [0] = { THREEI_A_STR } } }, /* attr: fixed struct, not staged */
#endif
#ifdef __NR_mq_unlink
	[__NR_mq_unlink] = { 1, { [0] = { THREEI_A_STR } } },
#endif
#ifdef __NR_mq_timedsend
	[__NR_mq_timedsend] = { 1,
				{ [1] = { THREEI_A_BUF_IN,
					  2 } } }, /* abs_timeout fixed, not staged */
#endif

/* newer mount / fs api (guarded) */
#ifdef __NR_fsopen
	[__NR_fsopen] = { 1, { [0] = { THREEI_A_STR } } },
#endif
#ifdef __NR_fspick
	[__NR_fspick] = { 1, { [1] = { THREEI_A_STR } } },
#endif
#ifdef __NR_fsconfig
	[__NR_fsconfig] = { 1,
			    { [2] = { THREEI_A_STR } } }, /* key; value[3] cmd-specific */
#endif
#ifdef __NR_open_tree
	[__NR_open_tree] = { 1, { [1] = { THREEI_A_STR } } },
#endif
#ifdef __NR_move_mount
	[__NR_move_mount] = { 1,
			      { [1] = { THREEI_A_STR }, [3] = { THREEI_A_STR } } },
#endif
#ifdef __NR_mount_setattr
	[__NR_mount_setattr] = { 1,
				 { [1] = { THREEI_A_STR },
				   [3] = { THREEI_A_BUF_IN,
					   4 } } }, /* uattr: mount_attr of usize */
#endif
#ifdef __NR_open_tree_attr
	[__NR_open_tree_attr] = { 1,
				  { [1] = { THREEI_A_STR },
				    [3] = { THREEI_A_BUF_IN, 4 } } },
#endif
};

/*
 * Read `len` bytes (or a NUL string) from owner@uaddr into kbuf. We run while
 * current IS the grate, so a grate-owned arg is a direct strncpy_from_user/
 * copy_from_user; another cage uses access_process_vm. String mode bounds at
 * the NUL and returns len incl NUL; buffer mode returns len.
 */
static long threei_read_owner(pid_t owner, unsigned long uaddr, void *kbuf,
			      size_t len, bool str)
{
	if (owner == task_tgid_vnr(current)) {
		if (str) {
			long n = strncpy_from_user(
				kbuf, (const char __user *)uaddr, len);

			return n < 0 ? -EFAULT :
				       (n >= (long)len ? -ENAMETOOLONG : n + 1);
		}
		return copy_from_user(kbuf, (const void __user *)uaddr, len) ?
			       -EFAULT :
			       (long)len;
	} else {
		struct task_struct *arg_cage = find_get_task_by_vpid(owner);
		long got;

		if (!arg_cage) {
			return -ESRCH;
		}

		got = access_process_vm(arg_cage, uaddr, kbuf, len, 0);
		put_task_struct(arg_cage);
		if (str) {
			size_t sl;

			if (got <= 0)
				return -EFAULT;
			sl = strnlen(kbuf, got);
			return sl == (size_t)got ? -ENAMETOOLONG : (long)sl + 1;
		}
		return got == (long)len ? (long)len : -EFAULT;
	}
}

static long threei_arena_put(struct task_struct *cage, unsigned long *cursor,
			     unsigned long limit, const void *kbuf, size_t len)
{
	unsigned long cursor_at = *cursor;

	if (cursor_at + ALIGN(len, 8) > limit) {
		return -EFAULT;
	}
	if (threei_arena_write(cage->threei_arena, cursor_at, kbuf, len) != 0) {
		return -EFAULT;
	}
	*cursor = cursor_at + ALIGN(len, 8);
	return cursor_at;
}

static long threei_iovec_size(pid_t owner, unsigned long arr_uaddr,
			      unsigned long count, size_t *need)
{
	struct iovec *iov;
	size_t arrsz, total;
	unsigned long j;
	long rc = 0;

	if (!count || count > UIO_MAXIOV) {
		return -EINVAL;
	}
	arrsz = count * sizeof(struct iovec);
	iov = kvmalloc(arrsz, GFP_KERNEL);
	if (!iov) {
		return -EINVAL;
	}
	if (threei_read_owner(owner, arr_uaddr, iov, arrsz, false) < 0) {
		rc = -EFAULT;
		goto out;
	}
	total = ALIGN(arrsz, 8);
	for (j = 0; j < count; j++) {
		size_t blen = iov[j].iov_len;

		if (blen > THREEI_MAX_COPY) {
			rc = -EINVAL;
			goto out;
		}
		total += ALIGN(blen, 8);
		if (total > THREEI_MAX_COPY) {
			rc = -EINVAL;
			goto out;
		}
	}
	*need += total;
out:
	kvfree(iov);
	return rc;
}

static long threei_stage_iovec(struct task_struct *cage, pid_t owner,
			       unsigned long arr_uaddr, unsigned long count,
			       unsigned long *cursor, unsigned long limit,
			       unsigned long *out)
{
	struct iovec *iov;
	size_t arrsz;
	unsigned long j, arr_at;
	long rc = 0;

	if (!count || count > UIO_MAXIOV) {
		return -EINVAL;
	}
	arrsz = count * sizeof(struct iovec);
	iov = kvmalloc(arrsz, GFP_KERNEL);
	if (!iov) {
		return -ENOMEM;
	}
	if (threei_read_owner(owner, arr_uaddr, iov, arrsz, false) < 0) {
		rc = -EFAULT;
		goto out;
	}

	arr_at = *cursor;
	if (arr_at + ALIGN(arrsz, 8) > limit) {
		rc = -EFAULT;
		goto out;
	}
	*cursor = arr_at + ALIGN(arrsz, 8);

	for (j = 0; j < count; j++) {
		size_t blen = iov[j].iov_len;
		void *buf;
		long cursor_at;

		if (!blen) {
			iov[j].iov_base = (void __user *)arr_at;
			continue;
		}

		if (blen > THREEI_MAX_COPY) {
			rc = -EINVAL;
			goto out;
		}

		buf = kvmalloc(blen, GFP_KERNEL);
		if (!buf) {
			rc = -ENOMEM;
			goto out;
		}
		if (threei_read_owner(owner, (unsigned long)iov[j].iov_base,
				      buf, blen, false) < 0) {
			kvfree(buf);
			rc = -EFAULT;
			goto out;
		}
		cursor_at = threei_arena_put(cage, cursor, limit, buf, blen);
		kvfree(buf);
		if (cursor_at < 0) {
			rc = cursor_at;
			goto out;
		}
		iov[j].iov_base = (void __user *)(unsigned long)cursor_at;
	}

	if (threei_arena_write(cage->threei_arena, arr_at, iov, arrsz) != 0) {
		rc = -EFAULT;
		goto out;
	}
	*out = arr_at;
out:
	kvfree(iov);
	return rc;
}

/*
 * Pre-syscall, current == grate: stage every foreign-owned INPUT pointer into
 * the primary cage's arena and rewrite args[]  to the arena address. Two passes
 * so the arena is sized once to this call's exact need and the base never moves
 * mid-fill. No state is carried past the call (outputs stay in the cage).
 */
long threei_stage_in_args(pid_t primary, u32 nr, const s32 arg_cage[6],
			  unsigned long args[6])
{
	const struct threei_sysdesc *desc =
		(nr < NR_syscalls) ? &threei_desc[nr] : NULL;
	struct task_struct *cage = NULL;
	unsigned long base, cursor = 0, limit = 0;
	size_t need = 0;
	long ret = 0;
	int i;

	if (!arg_cage)
		return 0;

	/* pass 1: validate shapes and total the exact bytes needed */
	for (i = 0; i < 6; i++) {
		u8 kind;

		if (arg_cage[i] <= 0 || arg_cage[i] == primary) {
			continue;
		}
		if (!desc || !desc->described) {
			return -EOPNOTSUPP;
		}

		kind = desc->args[i].kind;

		if (desc->args[i].kind == THREEI_A_STR) {
			need += ALIGN(PATH_MAX, 8);
		} else if (kind == THREEI_A_BUF_FIX) {
			if (!desc->args[i].fixed_len) {
				return -EINVAL;
			}
			need += ALIGN(desc->args[i].fixed_len, 8);
		} else if (kind == THREEI_A_BUF_IN || kind == THREEI_A_IOVEC) {
			u8 li = desc->args[i].len_arg;

			if (li >= 6) {
				return -EINVAL;
			}

			if (kind == THREEI_A_BUF_IN) {
				size_t len = (size_t)args[li];

				if (!len || len > THREEI_MAX_COPY) {
					return -EINVAL;
				}
				need += ALIGN(len, 8);
			} else {
				long rc = threei_iovec_size(
					arg_cage[i], args[i], args[li], &need);

				if (rc) {
					return rc;
				}
			}

		} else {
			return -EINVAL; /* foreign tag on a scalar/undescribed arg */
		}
	}
	if (!need)
		return 0;

	cage = find_get_task_by_vpid(primary);

	if (!cage) {
		return -ESRCH;
	}
	base = cursor = threei_arena_get(cage, need);
	limit = base ? base + need : 0;
	if (!base) {
		ret = -ENOMEM;
		goto out;
	}

	/* pass 2: copy each input into the arena, rewrite the pointer */
	for (i = 0; i < 6; i++) {
		s32 owner = arg_cage[i];
		u8 kind;
		size_t len;
		long got, cursor_at;
		void *buffer;

		if (arg_cage[i] <= 0 || arg_cage[i] == primary) {
			continue;
		}
		kind = desc->args[i].kind;

		if (kind == THREEI_A_IOVEC) {
			ret = threei_stage_iovec(cage, owner, args[i],
						 args[desc->args[i].len_arg],
						 &cursor, limit, &args[i]);

			if (ret) {
				goto out;
			}

			continue;
		}

		len = (kind == THREEI_A_STR) ?
			      PATH_MAX :
		      (kind == THREEI_A_BUF_FIX) ?
			      desc->args[i].fixed_len :
			      (size_t)args[desc->args[i].len_arg];

		buffer = kvmalloc(len, GFP_KERNEL);
		if (!buffer) {
			ret = -ENOMEM;
			goto out;
		}
		got = threei_read_owner(arg_cage[i], args[i], buffer, len,
					kind == THREEI_A_STR);
		if (got < 0) {
			kvfree(buffer);
			ret = got;
			goto out;
		}
		if (kind == THREEI_A_STR) {
			len = got;
		}

		cursor_at = threei_arena_put(cage, &cursor, limit, buffer, len);
		kvfree(buffer);
		if (cursor_at < 0) {
			ret = cursor_at;
			goto out;
		}
		args[i] = cursor_at;
	}
out:
	if (cage)
		put_task_struct(cage);
	return ret;
}
