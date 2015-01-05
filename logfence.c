#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <syslog.h>
#include <stdbool.h>
#include <sys/queue.h>
#include <limits.h>

#define FUSE_USE_VERSION (26)
#include <fuse.h>

#define USAGE "Usage: %s DIR\n"

struct wrlock {
	struct stat stbuf;
	pid_t pid;
	int fd;
	LIST_ENTRY(wrlock) peers;
};

struct lf_ctx {
	char path[PATH_MAX];
	LIST_HEAD(wrlock_list, wrlock) wrlocks;
	pthread_mutex_t mutex;
	int fd;
};

static void *lf_init(struct fuse_conn_info *conn)
{
	openlog(PROG, 0, LOG_DAEMON);
	return NULL;
}

static void lf_destroy(void *private_data)
{
	const struct lf_ctx *lf_ctx = (const struct lf_ctx *) private_data;
	struct wrlock *wrlock;

	LIST_FOREACH(wrlock, &lf_ctx->wrlocks, peers)
		free(wrlock);

	closelog();
}

static struct lf_ctx *get_lf_ctx(void)
{
	struct fuse_context *ctx;

	ctx = fuse_get_context();
	if (NULL == ctx)
		return NULL;

	return (struct lf_ctx *) ctx->private_data;
}

static int lf_access(const char *name, int mask)
{
	const struct lf_ctx *lf_ctx;

	lf_ctx = get_lf_ctx();
	if (NULL == lf_ctx)
		return -ENOMEM;

	if (-1 == faccessat(lf_ctx->fd, &name[1], mask, AT_SYMLINK_NOFOLLOW))
		return -errno;

	return 0;
}

static int stat_internal(const char *name,
                         struct stat *stbuf,
                         const bool follow)
{
	const struct lf_ctx *lf_ctx;
	int flags;

	lf_ctx = get_lf_ctx();
	if (NULL == lf_ctx)
		return -ENOMEM;

	if (true == follow)
		flags = AT_EMPTY_PATH;
	else
		flags = AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;
	if (-1 == fstatat(lf_ctx->fd, &name[1], stbuf, flags))
		return -errno;

	return 0;
}
static int lf_stat(const char *name, struct stat *stbuf)
{
	return stat_internal(name, stbuf, false);
}

static bool is_locked(const struct lf_ctx *lf_ctx,
                      const char *name,
                      const struct stat *stbuf,
                      const pid_t pid)
{
	const struct wrlock *wrlock;

	LIST_FOREACH(wrlock, &lf_ctx->wrlocks, peers) {
		if (pid == wrlock->pid)
			continue;

		if ((wrlock->stbuf.st_ino == stbuf->st_ino) &&
		    (wrlock->stbuf.st_dev == stbuf->st_dev))
			return true;
	}

	return false;
}

static int add_lock(const char *name,
                    const struct fuse_context *ctx,
                    const int fd)
{
	struct lf_ctx *lf_ctx = (struct lf_ctx *) ctx->private_data;
	struct wrlock *wrlock;
	int ret = -ENOMEM;

	wrlock = (struct wrlock *) malloc(sizeof(struct wrlock));
	if (NULL == wrlock)
		goto end;

	ret = stat_internal(name, &wrlock->stbuf, true);
	if (0 != ret)
		goto free_wrlock;

	if (true == is_locked(lf_ctx, name, &wrlock->stbuf, ctx->pid)) {
		syslog(LOG_ALERT,
		       "denied writing to %s%s from %ld\n",
		       lf_ctx->path,
		       name,
		       (long) ctx->pid);
		ret = -EBUSY;
		goto free_wrlock;
	}

	syslog(LOG_INFO, "locking %s%s\n", lf_ctx->path, name);

	wrlock->pid = ctx->pid;
	wrlock->fd = fd;
	LIST_INSERT_HEAD(&lf_ctx->wrlocks, wrlock, peers);

	ret = 0;
	goto end;

free_wrlock:
	free(wrlock);

end:
	return ret;
}

static int open_internal(const char *name, const int flags, const mode_t mode)
{
	struct fuse_context *ctx;
	struct lf_ctx *lf_ctx;
	int fd;
	int ret = -ENOMEM;
	bool check;

	ctx = fuse_get_context();
	if (NULL == ctx)
		goto end;

	lf_ctx = (struct lf_ctx *) ctx->private_data;
	if (-1 == pthread_mutex_lock(&lf_ctx->mutex))
		goto end;

	if (0 == (O_WRONLY & flags))
		check = false;
	else
		check = true;

	fd = openat(lf_ctx->fd, &name[1], flags, mode);
	if (-1 == fd) {
		ret = -errno;
		goto unlock;
	}

	if (true == check) {
		ret = add_lock(name, ctx, fd);
		if (0 != ret) {
			(void) close(fd);
			goto unlock;
		}
	}

	ret = fd;

unlock:
	(void) pthread_mutex_unlock(&lf_ctx->mutex);

end:
	return ret;
}

static void remove_lock(const struct lf_ctx *lf_ctx,
                        const char *name,
                        const int fd)
{
	struct wrlock *wrlock;

	LIST_FOREACH(wrlock, &lf_ctx->wrlocks, peers) {
		if (fd != wrlock->fd)
			continue;

		syslog(LOG_INFO, "unlocking %s%s\n", lf_ctx->path, name);
		LIST_REMOVE(wrlock, peers);
		free(wrlock);
		break;
	}
}

static int close_internal(const char *name, const int fd)
{
	struct lf_ctx *lf_ctx;
	int ret = -ENOMEM;

	lf_ctx = get_lf_ctx();
	if (NULL == lf_ctx)
		goto end;

	if (-1 == pthread_mutex_lock(&lf_ctx->mutex))
		goto end;

	remove_lock(lf_ctx, name, fd);

	if (-1 == close(fd)) {
		ret = -errno;
		goto unlock;
	}

	ret = 0;

unlock:
	(void) pthread_mutex_unlock(&lf_ctx->mutex);

end:
	return ret;
}

static int lf_create(const char *name,
                     mode_t mode,
                     struct fuse_file_info *fi)
{
	struct fuse_context *ctx;
	const struct lf_ctx *lf_ctx;
	int tmp;
	int fd;

	ctx = fuse_get_context();
	if (NULL == ctx)
		return -ENOMEM;

	fd = open_internal(name, O_CREAT | fi->flags, mode);
	if (0 > fd)
		return fd;

	lf_ctx = (const struct lf_ctx *) ctx->private_data;
	if (-1 == fchownat(lf_ctx->fd,
	                   &name[1],
	                   ctx->uid,
	                   ctx->gid,
	                   AT_SYMLINK_NOFOLLOW)) {
		tmp = errno;
		(void) close_internal(name, fd);
		(void) unlinkat(lf_ctx->fd, &name[1], 0);
		return -tmp;
	}

	fi->fh = (uint64_t) fd;
	return 0;
}

static int lf_truncate(const char *name, off_t size)
{
	int fd;
	int ret;

	fd = open_internal(name, O_WRONLY, 0);
	if (0 > fd)
		return fd;

	if (-1 == ftruncate(fd, size))
		ret = -errno;
	else
		ret = 0;

	(void) close_internal(name, fd);

	return ret;
}

static int lf_open(const char *name, struct fuse_file_info *fi)
{
	int fd;

	fd = open_internal(name, fi->flags, 0);
	if (0 > fd)
		return fd;

	fi->fh = (uint64_t) fd;
	return 0;
}

static int lf_close(const char *name, struct fuse_file_info *fi)
{
	int fd = (int) fi->fh;
	int ret;

	if (-1 == fd)
		return -EBADF;

	ret = close_internal(name, fd);
	if (0 == ret)
		fi->fh = (uint64_t) -1;

	return ret;
}

static int lf_read(const char *path,
                   char *buf,
                   size_t size,
                   off_t off,
                   struct fuse_file_info *fi)
{
	ssize_t ret;
	int fd = (int) fi->fh;

	if (-1 == fd)
		return -EBADF;

	ret = pread(fd, buf, size, off);
	if (-1 == ret)
		return -errno;

	return (int) ret;
}

static int lf_write(const char *path,
                    const char *buf,
                    size_t size,
                    off_t off,
                    struct fuse_file_info *fi)
{
	ssize_t ret;
	int fd = (int) fi->fh;

	if (-1 == fd)
		return -EBADF;

	ret = pwrite(fd, buf, size, off);
	if (-1 == ret)
		return -errno;

	return (int) ret;
}

static int lf_opendir(const char *name, struct fuse_file_info *fi)
{
	const struct lf_ctx *lf_ctx;
	DIR *dir;
	const char *rname;
	int fd;
	int tmp;

	lf_ctx = get_lf_ctx();
	if (NULL == lf_ctx)
		return -ENOMEM;

	if (0 == strcmp("/", name))
		rname = ".";
	else
		rname = &name[1];

	fd = openat(lf_ctx->fd, rname, O_DIRECTORY | (3 & fi->flags), 0);
	if (-1 == fd)
		return -errno;

	dir = fdopendir(fd);
	if (NULL == dir) {
		tmp = errno;
		(void) close(fd);
		return -tmp;
	}

	fi->fh = (uint64_t) (uintptr_t) dir;

	return 0;
}

static int lf_readdir(const char *path,
                      void *buf,
                      fuse_fill_dir_t filler,
                      off_t offset,
                      struct fuse_file_info *fi)
{
	struct stat stbuf;
	struct dirent ent;
	struct dirent *entp;
	DIR *dir = (DIR *) (uintptr_t) fi->fh;

	if (NULL == dir)
		return -EBADF;

	if (0 != readdir_r(dir, &ent, &entp))
		return -errno;
	if (NULL == entp)
		return 0;

	if (-1 == fstatat(dirfd(dir), entp->d_name, &stbuf, AT_SYMLINK_NOFOLLOW))
		return -errno;

	if (1 == filler(buf, entp->d_name, &stbuf, 1 + offset))
		return -ENOMEM;

	return 0;
}

static int lf_closedir(const char *name, struct fuse_file_info *fi)
{
	DIR *dir = (DIR *) (uintptr_t) fi->fh;

	if (NULL == dir)
		return -EBADF;

	if (-1 == closedir(dir))
		return -errno;

	return 0;
}

static struct fuse_operations lf_oper = {
	.init		= lf_init,
	.destroy	= lf_destroy,

	.access		= lf_access,
	.getattr	= lf_stat,

	.create		= lf_create,
	.truncate	= lf_truncate,
	.open		= lf_open,
	.release	= lf_close,

	.read		= lf_read,
	.write		= lf_write,

	.opendir	= lf_opendir,
	.readdir	= lf_readdir,
	.releasedir	= lf_closedir,
};

int main(int argc, char *argv[])
{
	char *fuse_argv[] = {argv[0], "-ononempty", argv[1],  NULL};
	struct lf_ctx ctx;
	int ret = EXIT_FAILURE;

	if (1 == argc) {
		(void) fprintf(stderr, USAGE, argv[0]);
		goto end;
	}

	if (NULL == realpath(argv[1], ctx.path))
		goto end;

	if (0 != pthread_mutex_init(&ctx.mutex, NULL))
		goto end;

	ctx.fd = open(argv[1], O_DIRECTORY | O_RDONLY);
	if (-1 == ctx.fd)
		goto destroy_mutex;

	LIST_INIT(&ctx.wrlocks);
	ret = fuse_main((sizeof(fuse_argv) / sizeof(fuse_argv[0])) - 1,
	                fuse_argv,
	                &lf_oper,
	                (void *) &ctx);

	(void) close(ctx.fd);

destroy_mutex:
	(void) pthread_mutex_destroy(&ctx.mutex);

end:
	return ret;
}
