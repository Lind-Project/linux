#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/threei.h>

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
