#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/threei.h>

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
#ifdef __NR_dup
    [__NR_dup] = {.arg_is_fd = 0x01, .flags = THREEI_RET_IS_FD},
#endif
#ifdef __NR_ftruncate
    [__NR_ftruncate] = {.arg_is_fd = 0x01},
#endif
#ifdef __NR_fcntl
    [__NR_fcntl]     = {.arg_is_fd = 0x01},
#endif
#ifdef __NR_readv
    /* readv(fd, iov, iovcnt): fd@0, iov@1 is a NESTED pointer array; the flat
     * buf descriptor can't express it, so buf stays NONE and the switch case
     * marshals the iovec explicitly. */
    [__NR_readv]     = {.arg_is_fd = 0x01},
#endif
#ifdef __NR_writev
    [__NR_writev]    = {.arg_is_fd = 0x01},
#endif
#ifdef __NR_dup2
    [__NR_dup2] = {.arg_is_fd = 0x01},
#endif
#ifdef __NR_dup3
    [__NR_dup3] = {.arg_is_fd = 0x01},
#endif
};

/*
 * translate any fd-typed argument from virtual to real before
 * forwarding. need to cover all fd related syscalls
 */
inline const struct threei_fd_desc *threei_get_fd_desc(u32 nr) {
    if (nr < ARRAY_SIZE(threei_fd_descs)) {
        return &threei_fd_descs[nr];
    }
    return NULL;
}

/* virtualize retval if RET_IS_FD, or free the vfd if FREES_FD0
 * and the free-target arg was already translated */
long threei_postprocess_fd(struct threei_handler *cage_handler,
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


struct threei_fdtable *threei_fdtable_get(struct threei_handler *handler) {
    struct threei_fdtable *table, *fresh;
    int i;

    table = READ_ONCE(handler->fdtable);
    if (table) {
        return table;
    }

    fresh = kzalloc(sizeof(*fresh), GFP_KERNEL);
    if (!fresh) {
        return NULL;
    }
    spin_lock_init(&fresh->lock);
    for (i = 0; i < THREEI_VFD_MAX; i++) {
        fresh->file[i] = NULL;
        fresh->owner_grate[i] = 0;
    }

    /*
     * Identity-map inherited stdio (0,1,2) so the cage's very first
     * write()/read() to stdout/stdin/stderr works without ever having
     * gone through openat. owner_grate == THREEI_VFD_INHERITED marks
     * these as "not ours to close" during teardown.
     */
    for (i = 0; i < 3; i++) {
        fresh->owner_grate[i] = THREEI_VFD_INHERITED;
    }

    /* racing allocators: whichever cmpxchg wins is used; loser is freed */
    if (cmpxchg(&handler->fdtable, NULL, fresh) != NULL) {
        kfree(fresh);
        return READ_ONCE(handler->fdtable);
    }

    return fresh;
}

int threei_vfd_alloc(struct threei_fdtable *table, struct file *file,
                     pid_t owner_grate) {
    int i, vfd = -1;

    spin_lock(&table->lock);
    for (i = 3; i < THREEI_VFD_MAX; i++) {
        if (table->file[i] == NULL) {
            table->file[i] = file;
            table->owner_grate[i] = owner_grate;
            vfd = i;
            break;
        }
    }
    spin_unlock(&table->lock);
    return vfd;
}

int threei_vfd_install_at(struct threei_fdtable *table, int newfd,
		struct file *file, pid_t owner_grate) {
    struct file *target;

    if (newfd < 0 || newfd >= THREEI_VFD_MAX) {
        return -EBADF;
    }

    get_file(file);
    spin_lock(&table->lock);
    target = table->file[newfd];
    table->file[newfd] = file;
    table->owner_grate[newfd] = owner_grate;
    spin_unlock(&table->lock);

    if (target) {
        /* close the old newfd */
        fput(target);
    }

    return newfd;
}

/* returns the pinned struct file* (borrowed), or NULL if vfd is not a
 * valid allocated entry. */
struct file *threei_vfd_lookup(struct threei_fdtable *table, int vfd) {
    struct file *file;

    if (vfd < 0 || vfd >= THREEI_VFD_MAX) {
        return NULL;
    }

    spin_lock(&table->lock);
    file = table->file[vfd];
    spin_unlock(&table->lock);

    return file;
}

void threei_vfd_free(struct threei_fdtable *table, int vfd) {
    struct file *file = NULL;
    if (vfd < 0 || vfd >= THREEI_VFD_MAX) {
        return;
    }
    spin_lock(&table->lock);
    file = table->file[vfd];
    table->file[vfd] = NULL;
    spin_unlock(&table->lock);
    if (file) {
        fput(file);
    }
}

void threei_fdtable_teardown(struct threei_fdtable *table) {
    int i;
    if (!table) {
        return;
    }

    for (i = 0; i < THREEI_VFD_MAX; i++) {
        if (table->file[i]) {
            fput(table->file[i]);
            table->file[i] = NULL;
        }
    }
    kfree(table);
}

/* Run one fd syscall generically against the grate's file*, with isolation
 *	- current is cage here.
 *	- args[] fd arg is STILL the vfd (we translate here, we need the
 * vfd to find the owner grate and the real fd)
 *	- desc is the descriptor for syscall_nr, with arg_is_fd set
 *
 * Returns the syscall result, or negative errno. Sets *handled=true if
 * this routine took responsibility for the syscall.
 */
long threei_generic_fd_exec(struct threei_handler *cage_handler,
                            u32 syscall_nr,
                            const struct threei_fd_desc *desc,
                            unsigned long args[6], bool *handled) {
    struct threei_fdtable *fdtable;
    struct file *file = NULL;
    void *kbuf = NULL;
    int fd_idx, vfd;
    size_t len = 0;
    loff_t pos;
    long ret;

    *handled = false;

    if (!desc || !desc->arg_is_fd) {
        return 0;
    }

    fd_idx = __builtin_ffs(desc->arg_is_fd) - 1;
    if (fd_idx < 0 || fd_idx >= 6) {
        return 0;
    }

    vfd = (int)args[fd_idx];

    fdtable = READ_ONCE(cage_handler->fdtable);
    if (!fdtable) {
        return 0;
    }

    file = threei_vfd_lookup(fdtable, vfd);
    if (!file) {
        return 0;
    }

    *handled = true;

    /* from here on we OWN this call: mark handled and translate the fd */
    if (desc->buf.dir != THREEI_BUF_NONE) {
        if (desc->buf.len_arg == THREEI_LEN_FIXED) {
            len = desc->buf.fixed_len;
        } else {
            len = (size_t)args[desc->buf.len_arg];
        }

        if (len > THREEI_GENERIC_MAX_BUF) {
            len = THREEI_GENERIC_MAX_BUF;
        }

        if (len) {
            kbuf = kvmalloc(len, GFP_KERNEL);
            if (!kbuf) {
                ret = -ENOMEM;
                goto out;
            }
        }
    }

    /* IN buffers (write): copy cage -> kbuf BEFORE the op */
    if (desc->buf.dir == THREEI_BUF_IN && len) {
        if (copy_from_user(kbuf, (void __user *)args[desc->buf.ptr_arg],
                           len)) {
            ret = -EFAULT;
            goto out;
        }
    }

    /* dispatch by syscall against the grate's file* */
    switch (syscall_nr) {
#ifdef __NR_read
    case __NR_read:
        pos = file->f_pos;
        ret = kernel_read(file, kbuf, len, &pos);
        if (ret >= 0) {
            file->f_pos = pos;
        }
        break;
#endif
#ifdef __NR_write
    case __NR_write:
        pos = file->f_pos;
        ret = kernel_write(file, kbuf, len, &pos);
        if (ret >= 0)
            file->f_pos = pos;
        break;
#endif
#ifdef __NR_pread64
    case __NR_pread64:
        pos = (loff_t)args[3]; /* explicit offset, no f_pos */
        ret = kernel_read(file, kbuf, len, &pos);
        break;
#endif
#ifdef __NR_pwrite64
    case __NR_pwrite64:
        pos = (loff_t)args[3];
        ret = kernel_write(file, kbuf, len, &pos);
        break;
#endif
#ifdef __NR_lseek
    case __NR_lseek:
        ret = vfs_llseek(file, (loff_t)args[1], (int)args[2]);
        break;
#endif
#ifdef __NR_fstat
    case __NR_fstat: {
        struct kstat kst;
        struct stat ust; /* userspace layout */

        ret = vfs_getattr(&file->f_path, &kst, STATX_BASIC_STATS,
                          AT_STATX_SYNC_AS_STAT);
        if (ret) {
            break;
        }

        memset(&ust, 0, sizeof(ust));
        ust.st_dev = new_encode_dev(kst.dev);
        ust.st_ino = kst.ino;
        ust.st_nlink = kst.nlink;
        ust.st_mode = kst.mode;
        ust.st_uid = from_kuid_munged(current_user_ns(), kst.uid);
        ust.st_gid = from_kgid_munged(current_user_ns(), kst.gid);
        ust.st_rdev = new_encode_dev(kst.rdev);
        ust.st_size = kst.size;
        ust.st_blksize = kst.blksize;
        ust.st_blocks = kst.blocks;
        ust.st_atime = kst.atime.tv_sec; /* scalar, not st_atim.tv_sec */
        ust.st_atime_nsec = kst.atime.tv_nsec;
        ust.st_mtime = kst.mtime.tv_sec;
        ust.st_mtime_nsec = kst.mtime.tv_nsec;
        ust.st_ctime = kst.ctime.tv_sec;
        ust.st_ctime_nsec = kst.ctime.tv_nsec;

        if (copy_to_user((void __user *)args[desc->buf.ptr_arg], &ust,
                         sizeof(ust))) {
            ret = -EFAULT;
        }

        goto out;
    }
#endif
#ifdef __NR_close
    case __NR_close:
        *handled = true;
        ret = 0;
        goto out; /* handled=true already set */
#endif
#ifdef __NR_ftruncate
    case __NR_ftruncate: {
        /* do_ftruncate() lives in fs/internal.h, which is PRIVATE to fs/
         * use do_truncate instead*/
        loff_t lenght = (loff_t)args[1];

        if (lenght < 0) {
            ret = -EINVAL;
            goto out;
        }
        if (!(file->f_mode & FMODE_WRITE)) {
            ret = -EINVAL;
            goto out;
        }
        /* small-file rlimit check that do_ftruncate does for the "small"
    caller
    +   * is skipped: ftruncate(2) uses the large path
    (do_ftruncate(...,0)). */
        ret = mnt_want_write_file(file);
        if (ret)
            goto out;
        ret = security_file_truncate(file);
        if (!ret) {
            ret = do_truncate(file_mnt_idmap(file), file->f_path.dentry,
                              lenght, ATTR_MTIME | ATTR_CTIME, file);
        }
        mnt_drop_write_file(file);
        goto out;
    }
#endif
#ifdef __NR_fcntl
    case __NR_fcntl: {
        unsigned int cmd = (unsigned int)args[1];

        switch (cmd) {
        case F_GETFL:
            /* file status + access mode flags, as fcntl(F_GETFL) returns
             */
            ret = file->f_flags &
                  (O_ACCMODE | O_APPEND | O_NONBLOCK | O_DSYNC | __O_SYNC |
                   O_DIRECT | O_NOATIME);
            break;
        case F_SETFL:
            /* SETFL_MASK is private to fs/fcntl.c (not a public header) ->
             * not visible from kernel/threei/fd.c (build error). Inline
             * the same settable-status-flag mask here. */
            const unsigned int setfl_mask =
                O_APPEND | O_NONBLOCK | O_NDELAY | O_DIRECT | O_NOATIME;

            /* apply settable status flags to the grate's file */
            ret = 0;
            spin_lock(&file->f_lock);
            file->f_flags = (file->f_flags & ~setfl_mask) |
                            ((unsigned int)args[2] & setfl_mask);
            spin_unlock(&file->f_lock);
            break;
        case F_GETFD:
            /* CLOEXEC not tracked on the vfd; report unset */
            ret = 0;
            break;
        case F_SETFD:
            /* no-op on the vfd */
            ret = 0;
            break;
        default:
            /* struct-arg or fd-returning cmds (F_GETLK/F_SETLK/F_DUPFD)
not
+               * handled generically */
            ret = -EINVAL;
            break;
        }
        goto out;
    }
#endif
#ifdef __NR_dup
    case __NR_dup: {
        int newfd = get_unused_fd_flags(0);

        if (newfd < 0) {
            ret = newfd;
            goto out;
        }
        get_file(file);
        fd_install(newfd, file);
        /* THREEI_RET_IS_FD postprocess -> cage vfd */
        ret = newfd;
        goto out;
    }
#endif
#if defined(__NR_readv) || defined(__NR_writev)
    case __NR_readv:
    case __NR_writev: {
        /* Nested-pointer marshaling: iov@1 is an array of struct iovec
         * {iov_base, iov_len}. Copy the array from the cage, then for each
         * element copy the base buffer (IN for writev, OUT for readv)
         * through a kernel bounce buffer and run kernel_read/kernel_write
         * against the grate's file*. current is the cage here, so
         * copy_*_user targets the cage correctly */
        int iovcnt = (int)args[2];
        struct iovec kiov_small[UIO_FASTIOV];
        struct iovec *kiov = kiov_small;
        bool is_write = (syscall_nr == __NR_writev);
        loff_t pos = file->f_pos;
        ssize_t total = 0;
        int i;

        if (iovcnt < 0 || iovcnt > UIO_MAXIOV) {
            ret = -EINVAL;
            goto out;
        }
        if (iovcnt == 0) {
            ret = 0;
            goto out;
        }
        if (iovcnt > UIO_FASTIOV) {
            kiov = kmalloc_array(iovcnt, sizeof(*kiov), GFP_KERNEL);
            if (!kiov) {
                ret = -ENOMEM;
                goto out;
            }
        }
        if (copy_from_user(kiov, (void __user *)args[1],
                           iovcnt * sizeof(struct iovec))) {
            ret = -EFAULT;
            goto iov_free;
        }
        for (i = 0; i < iovcnt; i++) {
            void __user *ubase = (void __user *)kiov[i].iov_base;
            size_t ilen = kiov[i].iov_len;
            void *bb;
            ssize_t n;

            if (!ilen) {
                continue;
            }
            if (ilen > THREEI_GENERIC_MAX_BUF) {
                ilen = THREEI_GENERIC_MAX_BUF;
            }
            bb = kvmalloc(ilen, GFP_KERNEL);
            if (!bb) {
                ret = total ? total : -ENOMEM;
                goto iov_free;
            }

            if (is_write) {
                if (copy_from_user(bb, ubase, ilen)) {
                    kvfree(bb);
                    ret = total ? total : -EFAULT;
                    goto iov_free;
                }
                n = kernel_write(file, bb, ilen, &pos);
            } else {
                n = kernel_read(file, bb, ilen, &pos);
                if (n > 0 && copy_to_user(ubase, bb, n)) {
                    kvfree(bb);
                    ret = total ? total : -EFAULT;
                    goto iov_free;
                }
            }
            kvfree(bb);
            if (n < 0) {
                ret = total ? total : n;
                goto iov_free;
            }
            total += n;
            /* short read/write: stop */
            if ((size_t)n < ilen) {
                break;
            }
        }
        file->f_pos = pos;
        ret = total;
    iov_free:
        if (kiov != kiov_small) {
            kfree(kiov);
        }
        goto out;
    }
#endif
#if defined(__NR_dup2) || defined(__NR_dup3)
    case __NR_dup2:
    case __NR_dup3: {
        int oldfd = (int)args[0];
        int newfd = (int)args[1];
        pid_t owner;

        /* `file` is oldfd's file*: generic_fd_exec already looked it up via
        * arg_is_fd=0x01 (and if oldfd was invalid, lookup returned NULL and we
        * never reached this case -> caller gets the unhandled/EBADF path). */
        if (newfd < 0 || newfd >= THREEI_VFD_MAX) {
            ret = -EBADF;
            goto out;
        }

        if (syscall_nr == __NR_dup3) {
            unsigned int flags = (unsigned int)args[2];

            /* dup3: only O_CLOEXEC is allowed, and oldfd==newfd is EINVAL.
             * (The vfd table does not track per-fd CLOEXEC, so O_CLOEXEC is
             * accepted but not stored -  TODO.) */
            if (flags & ~O_CLOEXEC) {
                ret = -EINVAL;
                goto out;
            }
            if (oldfd == newfd) {
                ret = newfd;
                goto out;
            }
        } else {
            /* dup2: if oldfd == newfd, it's a no-op returning newfd (oldfd is
             * already known valid since we have `file`). */
            if (oldfd == newfd) {
                ret = newfd;
                goto out;
            }
        }

        spin_lock(&fdtable->lock);
        owner = fdtable->owner_grate[oldfd];
        spin_unlock(&fdtable->lock);

        ret = threei_vfd_install_at(fdtable, newfd, file, owner);
        goto out;
    }
#endif
    default:
        /* fd syscall we don't generically implement: give up cleanly */
        *handled = false;
        ret = 0;
        goto out;
    }

    /* OUT buffers (read/pread): copy kbuf -> cage AFTER the op */
    if (ret > 0 && desc->buf.dir == THREEI_BUF_OUT && kbuf) {
        size_t n = (size_t)ret;

        if (n > len) {
            n = len;
        }
        if (copy_to_user((void __user *)args[desc->buf.ptr_arg], kbuf,
                         n)) {
            ret = -EFAULT;
            goto out;
        }
    }

out:
    if (kbuf) {
        kvfree(kbuf);
    }

    return ret;
}

/*
 * Generalized gate handling for THREEI_ARG_IS_FD_MAP syscalls (mmap
 * and any address-space syscall that consumes an fd). current is the
 * cage here.
 *
 * desc->map_fd names which argument holds the vfd (lowest set bit).
 * We look it up in the cage's vfd table, install the real file into
 * the cage's own table, and rewrite that arg to the new real cage fd.
 */
void threei_gate_map_fd(const struct threei_fd_desc *desc,
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
