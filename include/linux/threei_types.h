#define THREEI_CTX_CACHE_MAX 4
#define THREEI_CTX_CACHE_FULL GENMASK(THREEI_CTX_CACHE_MAX - 1, 0)

struct threei_grate_ctx;

struct threei_ctx_cache {
	pid_t grateid[THREEI_CTX_CACHE_MAX];
	struct threei_grate_ctx *ctx[THREEI_CTX_CACHE_MAX];
	unsigned long valid;
	unsigned int next;
} ____cacheline_aligned; // lands in kmalloc-64

struct threei_ctx_borrow {
	const struct cred *cage_cred;
	struct mm_struct *cage_mm;
	struct files_struct *cage_files;
	struct fs_struct *cage_fs;
	struct nsproxy *cage_nsproxy;

	const struct cred *old_cred;
	struct mm_struct *old_mm;
	struct files_struct *old_files;
	struct fs_struct *old_fs;
	struct nsproxy *old_nsproxy;

	struct task_struct *id_cage;
};
