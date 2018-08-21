/* brz_utils.c -- file utilities

   Copyright (C) 2013-2018 Michal Roszkowski

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.  */

#include <sys/types.h>
#include <sys/stat.h>
#include <fts.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include "brz_utils.h"

#define BRZ_EXTENSION ".brz"
#define BRZ_HAS_EXTENSION(p)	((strlen(p) > strlen(BRZ_EXTENSION)) &&	\
				(!strcasecmp(BRZ_EXTENSION,		\
				(p) + (strlen(p) - strlen(BRZ_EXTENSION)))))

static unsigned char skip_buf[PIPE_BUF];

static int _brz_pathcat(char *dst, const char *dir, const char *name);
static int _brz_remove_ftsent(FTS *fts, FTSENT *f, void *arg);
static int _brz_fts_compar(const FTSENT **f1, const FTSENT **f2);
static int _fts_tree_walk(char *const *pathv, int options,
			  int (*func)(FTS *, FTSENT *, void *), void *arg);

int brz_openat(const char *dir, const char *name, int oflag, ...)
{
	char path[PATH_MAX];

	if (_brz_pathcat(path, dir, name))
		return -1;

	if (oflag & O_CREAT) {
		va_list ap;
		mode_t mode;

		va_start(ap, oflag);
		mode = va_arg(ap, unsigned int);
		va_end(ap);

		return open(path, oflag, mode);
	}

	return open(path, oflag);
}

int brz_unlinkat(const char *dir, const char *name)
{
	char path[PATH_MAX];

	if (_brz_pathcat(path, dir, name))
		return -1;

	return unlink(path);
}

int brz_mkdir_p(const char *path, mode_t mode)
{
	int rval;

	if (!path)
		return -1;

	while ((rval = mkdir(path, mode)) == -1) {
		if (errno != ENOENT)
			break;

		char *p = strdup(path);
		rval = brz_mkdir_p(brz_dirname(p), mode);
		free(p);
	}
	return rval;
}

int brz_rmdir_p(const char *path)
{
	int rval;
	char *p = strdup(path);

	if (p == NULL)
		return -1;

	do
		rval = rmdir(p);
	while (rval == 0 && brz_dirname(p) != NULL && !IS_ROOT(p));

	free(p);
	return -(rval == -1 && errno != ENOTEMPTY);
}

int brz_remove_r(char *const path)
{
	char *const pathv[] = {path, NULL};

	return _fts_tree_walk(pathv, FTS_PHYSICAL, _brz_remove_ftsent, NULL);
}

char *brz_dirname(char *path)
{
	char *p = strrchr(path, '/');

	if (p == NULL)
		return NULL;

	while (p > path + 1 && p[-1] == '/')
		p--;

	p[p == path] = '\0';

	return path;
}

char *brz_basename(const char *path)
{
	const char *p;

	return (char *)(((p = strrchr(path, '/')) == NULL)? path : p + 1);
}

char *brz_basename_s(char *path)
{
	const char *p = brz_basename(path);

	if (p != path)
		memmove(path, p, strlen(p));

	if (BRZ_HAS_EXTENSION(path))
		*(strrchr(path, '.')) = '\0';

	return path;
}

int brz_realpath(char *path)
{
	char *p, *clpse, *dir;
	int n = 0, n_dotdot = 0;

	p = brz_basename(path);
	clpse = (*p == '\0')? p : NULL;
	dir = p + strlen(p);

	while (p >= path) {
		if (IS_DOT(p) || *p == '/') {
			clpse = p;
		} else if (IS_DOTDOT(p)) {
			clpse = p;
			n_dotdot++;
		} else if (n_dotdot) {
			clpse = p;
			n_dotdot--;
		}

		if (clpse != p || p == path) {
			if (clpse) {
				if (dir == NULL || *dir == '\0') {
					if (clpse > path)
						clpse--;
					*clpse = '\0';
				} else {
					memmove(clpse, dir, n + 1);
				}
				n += clpse - p;
				clpse = NULL;
			} else {
				n += dir - p;
			}
			dir = p;
		}

		while (--p > path && p[-1] != '/');
	}

	return n;
}

int brz_skip(FILE *stream, size_t len)
{
	int n;

	if (fseek(stream, len, SEEK_CUR) == 0)
		return 0;

	for (n = sizeof(skip_buf); len > 0; len -= n) {
		n = (n < len)? n : len;
		if (!fread(skip_buf, n, 1, stream))
			return -1;
	}
	return 0;
}

int is_brz_file(FTSENT *f)
{
	return (f->fts_info == FTS_F &&
		(f->fts_level == FTS_ROOTLEVEL ||
		(f->fts_namelen > strlen(BRZ_EXTENSION) &&
		 !strcasecmp(BRZ_EXTENSION, f->fts_name +
			      (f->fts_namelen - strlen(BRZ_EXTENSION))))));
}

int fts_tree_walk(char *const *pathv,
		  int (*func)(FTS *, FTSENT *, void *), void *arg)
{
	return _fts_tree_walk(pathv, FTS_LOGICAL, func, arg);
}

static int _fts_tree_walk(char *const *pathv, int options,
			  int (*func)(FTS *, FTSENT *, void *), void *arg)
{
	FTS *fts;
	FTSENT *f;
	int fval, rval = 0;
	int err = 0;

	if (!(fts = fts_open(pathv, options, _brz_fts_compar)))
		return -1;

	while ((f = fts_read(fts)) != NULL)
		switch (f->fts_info) {
		case FTS_DNR:
		case FTS_ERR:
		case FTS_NS:
			err = f->fts_errno;
			rval = -1;
			break;
		default:
			if  ((fval = func(fts, f, arg)) != 0) {
				err = errno;
				rval = fval;
			}
		}

	fts_close(fts);
	errno = err;
	return rval;
}

static int _brz_fts_compar(const FTSENT **f1, const FTSENT **f2)
{
	return strcasecmp((*f1)->fts_name, (*f2)->fts_name);
}

static int _brz_remove_ftsent(FTS *fts, FTSENT *f, void *arg)
{
	switch (f->fts_info) {
	case FTS_D:
		return 0;
	case FTS_DP:
		return rmdir(f->fts_accpath);
	default:
		return unlink(f->fts_accpath);
	}
}

static int _brz_pathcat(char *dst, const char *dir, const char *name)
{
	size_t namelen, dirlen = 0;

	if (dir && (dirlen = strlen(dir)) > 0) {
		if (dirlen + 1 >= PATH_MAX) {
			errno = ENAMETOOLONG;
			return -1;
		}
		memcpy(dst, dir, dirlen);

		if (dst[dirlen - 1] != '/')
			dst[dirlen++] = '/';
	}

	if ((namelen = strlen(name) + 1) > PATH_MAX - dirlen) {
		errno = ENAMETOOLONG;
		return -1;
	}

	memcpy(dst + dirlen, name, namelen);
	return 0;
}

