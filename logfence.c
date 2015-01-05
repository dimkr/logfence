/*
 * Copyright (c) 2015 Dima Krasner
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

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

/* the command-line usage message */
#define USAGE "Usage: %s DIR\n"

/* a file writing lock process owning it */
struct wrlock {
	struct stat stbuf; /* the file metadata - we use the combination of device
	                      and inode to identify files precisely */
	pid_t pid;
	int fd;
	LIST_ENTRY(wrlock) peers;
};

enum lf_fd_types {
	LF_REG = 0,
	LF_DIR = 1
};

/* a regular file handle */
struct lf_reg_fd {
	enum lf_fd_types type; /* must be the first member - see struct lf_dir_fd */
	int fd;
	struct wrlock *lock; /* the lock associated with the file - we cache it here
	                        to avoid lookup when the file is closed */
};

/* a directory handle */
struct lf_dir_fd {
	enum lf_fd_types type;
	DIR *fh;
};

/* the global file system state */
struct lf_ctx {
	char path[PATH_MAX]; /* the mount point path */
	LIST_HEAD(wrlock_list, wrlock) wrlocks; /* the list of locked files */
	pthread_mutex_t mutex;
	int fd; /* a file descriptor of the mount point - we need it for *at()
	         * system calls */
};

static struct lf_ctx *get_ctx(struct fuse_context **ctx)
{
	struct fuse_context *tmp;

	if (NULL == ctx) {
		tmp = fuse_get_context();
		if (NULL != tmp)
			return (struct lf_ctx *) tmp->private_data;
	}
	else {
		*ctx = fuse_get_context();
		if (NULL != *ctx)
			return (struct lf_ctx *) (*ctx)->private_data;
	}

	return NULL;
}

static void *lf_init(struct fuse_conn_info *conn)
{
	openlog(PROG, 0, LOG_DAEMON);

	return (void *) get_ctx(NULL);
}

static void lf_destroy(void *private_data)
{
	const struct lf_ctx *lf_ctx = (const struct lf_ctx *) private_data;
	struct wrlock *wrlock;

	LIST_FOREACH(wrlock, &lf_ctx->wrlocks, peers)
		free(wrlock);

	closelog();
}

static int lf_access(const char *name, int mask)
{
	const struct lf_ctx *lf_ctx;

	lf_ctx = get_ctx(NULL);
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

	lf_ctx = get_ctx(NULL);
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
		/* ignore locks owned by the calling process */
		if (pid == wrlock->pid)
			continue;

		if ((wrlock->stbuf.st_ino == stbuf->st_ino) &&
		    (wrlock->stbuf.st_dev == stbuf->st_dev))
			return true;
	}

	return false;
}

/* returns the "name" of a process - similar to get_task_comm() */
static const char *get_name(const pid_t pid, char *buf, const size_t len)
{
	char path[PATH_MAX];
	const char *pos = NULL;
	char *term;
	ssize_t res;
	int out;
	int fd;

	out = snprintf(path, sizeof(path), "/proc/%ld/stat", (long) pid);
	if ((0 >= out) || (sizeof(path) <= out))
		goto end;

	fd = open(path, O_RDONLY);
	if (-1 == fd)
		goto end;

	res = read(fd, (void *) buf, len - 1);
	if (0 >= res)
		goto close_stat;
	buf[res] = '\0';

	/* locate and separate the process name - it's enclosed in parentheses */
	pos = strchr(buf, '(');
	if (NULL == pos)
		goto close_stat;
	++pos;

	term = strchr(pos, ')');
	if (NULL == term) {
		pos = NULL;
		goto close_stat;
	}
	term[0] = '\0';

close_stat:
	(void) close(fd);

end:
	return pos;
}

static int add_lock(const char *name,
                    const struct fuse_context *ctx,
                    struct lf_ctx *lf_ctx,
                    struct lf_reg_fd *lf_fd)
{
	char buf[NAME_MAX];
	const char *comm;
	struct wrlock *wrlock;
	int ret = -ENOMEM;

	wrlock = (struct wrlock *) malloc(sizeof(struct wrlock));
	if (NULL == wrlock)
		goto end;

	/* stat() the file, so we can compare its inode and device in is_locked() */
	ret = stat_internal(name, &wrlock->stbuf, true);
	if (0 != ret)
		goto free_wrlock;

	if (true == is_locked(lf_ctx, name, &wrlock->stbuf, ctx->pid)) {
		comm = get_name(ctx->pid, buf, sizeof(buf));
		if (NULL == comm) {
			syslog(LOG_ALERT,
			       "denied open of %s%s from %ld\n",
			       lf_ctx->path,
			       name,
			       (long) ctx->pid);
		}
		else {
			syslog(LOG_ALERT,
			       "denied open of %s%s from %ld (%s)\n",
			       lf_ctx->path,
			       name,
			       (long) ctx->pid,
			       comm);
		}
		ret = -EBUSY;
		goto free_wrlock;
	}

	syslog(LOG_INFO, "locking %s%s\n", lf_ctx->path, name);

	wrlock->pid = ctx->pid;
	lf_fd->lock = wrlock;
	LIST_INSERT_HEAD(&lf_ctx->wrlocks, wrlock, peers);

	ret = 0;
	goto end;

free_wrlock:
	free(wrlock);

end:
	return ret;
}

static int open_internal(const char *name,
                         const int flags,
                         const mode_t mode,
                         struct lf_reg_fd **lf_fd)
{
	struct fuse_context *ctx;
	struct lf_ctx *lf_ctx;
	int ret = -ENOMEM;
	bool check;

	lf_ctx = get_ctx(&ctx);
	if (NULL == lf_ctx)
		goto end;

	if (-1 == pthread_mutex_lock(&lf_ctx->mutex))
		goto end;

	/* do not check whether files opened without writing permissions are
	 * locked, for better efficiency */
	if (0 == (O_WRONLY & flags))
		check = false;
	else
		check = true;

	*lf_fd = (struct lf_reg_fd *) malloc(sizeof(struct lf_reg_fd));
	if (NULL == *lf_fd) {
		ret = -ENOMEM;
		goto unlock;
	}

	(*lf_fd)->fd = openat(lf_ctx->fd, &name[1], flags, mode);
	if (-1 == (*lf_fd)->fd) {
		ret = -errno;
		goto free_lock;
	}

	if (false == check)
		(*lf_fd)->lock = NULL;
	else {
		ret = add_lock(name, ctx, lf_ctx, *lf_fd);
		if (0 != ret) {
			(void) close((*lf_fd)->fd);
			goto free_lock;
		}
	}

	ret = 0;
	goto unlock;

free_lock:
	free(*lf_fd);

unlock:
	(void) pthread_mutex_unlock(&lf_ctx->mutex);

end:
	return ret;
}

/* must be called while lf_ctx->mutex is locked */
static void remove_lock(const struct lf_ctx *lf_ctx,
                        const char *name,
                        struct lf_reg_fd *lf_fd)
{
	if (NULL != lf_fd->lock) {
		syslog(LOG_INFO, "unlocking %s%s\n", lf_ctx->path, name);
		LIST_REMOVE(lf_fd->lock, peers);
		free(lf_fd->lock);
	}
}

static int close_internal(const char *name,
                          struct lf_reg_fd *lf_fd,
                          const bool delete)
{
	struct lf_ctx *lf_ctx;
	int ret = -ENOMEM;
	int fd;

	lf_ctx = get_ctx(NULL);
	if (NULL == lf_ctx)
		goto end;

	if (-1 == pthread_mutex_lock(&lf_ctx->mutex))
		goto end;

	fd = lf_fd->fd;
	remove_lock(lf_ctx, name, lf_fd);

	if (-1 == close(fd)) {
		/* keep the file descriptor but unset the lock pointer, to prevent
		 * attempts to free it again */
		lf_fd->lock = NULL;
		ret = -errno;
		goto unlock;
	}

	/* we do this here to avoid races - we want lf_ctx->mutex locked, to prevent
	 * deletion immediately after another process acquires the write lock */
	if (true == delete)
		(void) unlinkat(lf_ctx->fd, &name[1], 0);

	free(lf_fd);

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
	struct lf_reg_fd *lf_fd;
	int tmp;
	int ret;

	lf_ctx = get_ctx(&ctx);
	if (NULL == lf_ctx)
		return -ENOMEM;

	/* creat() does not have a *at() equivalent, so we have to use the
	 * combination openat(), O_CREAT and fchownat() */
	ret = open_internal(name, O_CREAT | fi->flags, mode, &lf_fd);
	if (0 != ret)
		return ret;

	if (-1 == fchownat(lf_ctx->fd,
	                   &name[1],
	                   ctx->uid,
	                   ctx->gid,
	                   AT_SYMLINK_NOFOLLOW)) {
		tmp = errno;
		(void) close_internal(name, lf_fd, false);
		return -tmp;
	}

	fi->fh = (uint64_t) (uintptr_t) lf_fd;
	return 0;
}

static int lf_truncate(const char *name, off_t size)
{
	struct lf_reg_fd *lf_fd;
	int ret;

	/* pass O_WRONLY, to respect locks - we do not allow truncation of locked
	 * files */
	ret = open_internal(name, O_WRONLY, 0, &lf_fd);
	if (0 != ret)
		return ret;

	if (-1 == ftruncate(lf_fd->fd, size))
		ret = -errno;
	else
		ret = 0;

	(void) close_internal(name, lf_fd, false);

	return ret;
}

static int lf_open(const char *name, struct fuse_file_info *fi)
{
	struct lf_reg_fd *lf_fd;
	int ret;

	ret = open_internal(name, fi->flags, 0, &lf_fd);
	if (0 != ret)
		return ret;

	lf_fd->type = LF_REG;
	fi->fh = (uint64_t) (uintptr_t) lf_fd;

	return 0;
}

static int lf_close(const char *name, struct fuse_file_info *fi)
{
	struct lf_reg_fd *lf_fd = (struct lf_reg_fd *) (void *) (uintptr_t) fi->fh;
	int ret;

	if (NULL == lf_fd)
		return -EBADF;
	if (LF_REG != lf_fd->type)
		return -EBADF;

	ret = close_internal(name, lf_fd, false);
	if (0 == ret)
		fi->fh = (uint64_t) (uintptr_t) NULL;

	return ret;
}

static int lf_unlink(const char *path)
{
	char buf[NAME_MAX];
	struct stat stbuf;
	const char *comm;
	struct fuse_context *ctx;
	const struct lf_ctx *lf_ctx;
	int ret;

	lf_ctx = get_ctx(&ctx);
	if (NULL == lf_ctx)
		return -ENOMEM;

	ret = lf_stat(path, &stbuf);
	if (0 != ret)
		return ret;

	/* do not allow deletion of locked files */
	if (false == is_locked(lf_ctx, path, &stbuf, ctx->pid)) {
		if (-1 == unlinkat(lf_ctx->fd, &path[1], 0))
			return -errno;
		return 0;
	}

	comm = get_name(ctx->pid, buf, sizeof(buf));
	if (NULL == comm) {
		syslog(LOG_ALERT,
		       "denied unlink of %s%s from %ld\n",
		       lf_ctx->path,
		       path,
		       (long) ctx->pid);
	}
	else {
		syslog(LOG_ALERT,
		       "denied unlink of %s%s from %ld (%s)\n",
		       lf_ctx->path,
		       path,
		       (long) ctx->pid,
		       comm);
	}

	return -EBUSY;
}

static int lf_read(const char *path,
                   char *buf,
                   size_t size,
                   off_t off,
                   struct fuse_file_info *fi)
{
	ssize_t ret;
	struct lf_reg_fd *lf_fd = (struct lf_reg_fd *) (void *) (uintptr_t) fi->fh;

	if (NULL == lf_fd)
		return -EBADF;
	if (LF_REG != lf_fd->type)
		return -EBADF;

	ret = pread(lf_fd->fd, buf, size, off);
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
	struct lf_reg_fd *lf_fd = (struct lf_reg_fd *) (void *) (uintptr_t) fi->fh;

	if (NULL == lf_fd)
		return -EBADF;
	if (LF_REG != lf_fd->type)
		return -EBADF;

	ret = pwrite(lf_fd->fd, buf, size, off);
	if (-1 == ret)
		return -errno;

	return (int) ret;
}

static int lf_mkdir(const char *path, mode_t mode)
{
	const struct lf_ctx *lf_ctx;

	lf_ctx = get_ctx(NULL);
	if (NULL == lf_ctx)
		return -ENOMEM;

	if (-1 == mkdirat(lf_ctx->fd, &path[1], mode))
		return -errno;

	return 0;
}

static int lf_opendir(const char *name, struct fuse_file_info *fi)
{
	const struct lf_ctx *lf_ctx;
	struct lf_dir_fd *lf_fd;
	const char *rname;
	int fd;
	int ret = -ENOMEM;

	lf_ctx = get_ctx(NULL);
	if (NULL == lf_ctx)
		goto end;

	lf_fd = (struct lf_dir_fd *) malloc(sizeof(struct lf_dir_fd));
	if (NULL == lf_fd)
		goto end;

	if (0 == strcmp("/", name))
		rname = ".";
	else
		rname = &name[1];
	fd = openat(lf_ctx->fd, rname, O_DIRECTORY | (3 & fi->flags), 0);
	if (-1 == fd) {
		ret = -errno;
		goto free_fd;
	}

	lf_fd->fh = fdopendir(fd);
	if (NULL == lf_fd->fh) {
		ret = -errno;
		(void) close(fd);
		goto free_fd;
	}

	lf_fd->type = LF_DIR;
	fi->fh = (uint64_t) (uintptr_t) lf_fd;
	ret = 0;
	goto end;

free_fd:
	free(lf_fd);

end:
	return ret;
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
	struct lf_dir_fd *lf_fd = (struct lf_dir_fd *) (void *) (uintptr_t) fi->fh;

	if (NULL == lf_fd)
		return -EBADF;
	if (LF_DIR != lf_fd->type)
		return -EBADF;

	if (0 != readdir_r(lf_fd->fh, &ent, &entp))
		return -errno;
	if (NULL == entp)
		return 0;

	if (-1 == fstatat(dirfd(lf_fd->fh),
	                  entp->d_name,
	                  &stbuf,
	                  AT_SYMLINK_NOFOLLOW))
		return -errno;

	if (1 == filler(buf, entp->d_name, &stbuf, 1 + offset))
		return -ENOMEM;

	return 0;
}

static int lf_closedir(const char *name, struct fuse_file_info *fi)
{
	struct lf_dir_fd *lf_fd = (struct lf_dir_fd *) (void *) (uintptr_t) fi->fh;

	if (NULL == lf_fd)
		return -EBADF;
	if (LF_DIR != lf_fd->type)
		return -EBADF;

	if (-1 == closedir(lf_fd->fh))
		return -errno;

	free(lf_fd);
	fi->fh = (uint64_t) (uintptr_t) NULL;

	return 0;
}

static int lf_rmdir(const char *path)
{
	const struct lf_ctx *lf_ctx;

	lf_ctx = get_ctx(NULL);
	if (NULL == lf_ctx)
		return -ENOMEM;

	if (-1 == unlinkat(lf_ctx->fd, &path[1], AT_REMOVEDIR))
		return -errno;

	return 0;
}

static int lf_symlink(const char *oldpath, const char *newpath)
{
	const struct lf_ctx *lf_ctx;

	lf_ctx = get_ctx(NULL);
	if (NULL == lf_ctx)
		return -ENOMEM;

	if (-1 == symlinkat(oldpath, lf_ctx->fd, &newpath[1]))
		return -errno;

	return 0;
}

static int lf_readlink(const char *path, char *buf, size_t len)
{
	const struct lf_ctx *lf_ctx;

	lf_ctx = get_ctx(NULL);
	if (NULL == lf_ctx)
		return -ENOMEM;

	len = readlinkat(lf_ctx->fd, &path[1], buf, len - 1);
	if (-1 == len)
		return -errno;
	buf[len] = '\0';

	return 0;
}

static int lf_chmod(const char *path, mode_t mode)
{
	const struct lf_ctx *lf_ctx;

	lf_ctx = get_ctx(NULL);
	if (NULL == lf_ctx)
		return -ENOMEM;

	if (-1 == fchmodat(lf_ctx->fd, &path[1], mode, AT_SYMLINK_NOFOLLOW))
		return -errno;

	return 0;
}

static int lf_chown(const char *path, uid_t uid, gid_t gid)
{
	const struct lf_ctx *lf_ctx;

	lf_ctx = get_ctx(NULL);
	if (NULL == lf_ctx)
		return -ENOMEM;

	if (-1 == fchownat(lf_ctx->fd,
	                   &path[1],
	                   uid,
	                   gid,
	                   AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW))
		return -errno;

	return 0;
}

static int lf_utimens(const char *path, const struct timespec tv[2])
{
	char buf[NAME_MAX];
	struct stat stbuf;
	const char *comm;
	struct fuse_context *ctx;
	const struct lf_ctx *lf_ctx;
	int ret;

	lf_ctx = get_ctx(&ctx);
	if (NULL == lf_ctx)
		return -ENOMEM;

	ret = lf_stat(path, &stbuf);
	if (0 != ret)
		return ret;

	/* do not allow utimens() on locked files, since this may be an attempt to
	 * buy time while cleaning up evidence during a breach (i.e if the
	 * modification time of the syslog hasn't changed, one might assume nothing
	 * happened until it's too late) */
	if (false == is_locked(lf_ctx, path, &stbuf, ctx->pid)) {
		if (-1 == utimensat(lf_ctx->fd,
		                   &path[1],
		                   tv,
		                   AT_SYMLINK_NOFOLLOW))
			return -errno;
		return 0;
	}

	comm = get_name(ctx->pid, buf, sizeof(buf));
	if (NULL == comm) {
		syslog(LOG_ALERT,
		       "denied touch of %s%s from %ld\n",
		       lf_ctx->path,
		       path,
		       (long) ctx->pid);
	}
	else {
		syslog(LOG_ALERT,
		       "denied touch of %s%s from %ld (%s)\n",
		       lf_ctx->path,
		       path,
		       (long) ctx->pid,
		       comm);
	}

	return -EBUSY;
}

static struct fuse_operations lf_oper = {
	.init		= lf_init,
	.destroy	= lf_destroy,

	.access		= lf_access,
	.getattr	= lf_stat,

	.chmod		= lf_chmod,
	.chown		= lf_chown,
	.utimens	= lf_utimens,

	.create		= lf_create,
	.truncate	= lf_truncate,
	.open		= lf_open,
	.release	= lf_close,
	.unlink		= lf_unlink,

	.read		= lf_read,
	.write		= lf_write,

	.symlink	= lf_symlink,
	.readlink	= lf_readlink,

	.mkdir		= lf_mkdir,
	.opendir	= lf_opendir,
	.readdir	= lf_readdir,
	.releasedir	= lf_closedir,
	.rmdir		= lf_rmdir
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

	/* get the canonicalized path of the mount point, for prettier logging */
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
