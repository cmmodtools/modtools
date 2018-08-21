/* brz_utils.h -- file utilities

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

#ifndef _BRZ_UTILS_H_
#define _BRZ_UTILS_H_

#include <sys/stat.h>
#include <fts.h>
#include <fcntl.h>
#include <stdio.h>

#define FTS_DIRLEN(f)	((f)->fts_pathlen - (f)->fts_namelen    \
			/* omit trailing '/' */                 \
			- ((f)->fts_namelen > 0 &&              \
			   (f)->fts_pathlen - (f)->fts_namelen > 1))

#define IS_DOT(s)	((s)[0] == '.' && ((s)[1] == '/' || (s)[1] == '\0'))
#define IS_DOTDOT(s)	((s)[0] == '.' && (s)[1] == '.' && ((s)[2] == '/' || \
							    (s)[2] == '\0'))
#define IS_ROOT(s)	((s)[0] == '/' && (s)[1] == '\0')

int brz_openat(const char *dir, const char *name, int oflag, ...);
int brz_unlinkat(const char *dir, const char *name);
int brz_mkdir_p(const char *path, mode_t mode);
int brz_rmdir_p(const char *path);
int brz_remove_r(char *const path);
char *brz_dirname(char *path);
char *brz_basename(const char *path);
char *brz_basename_s(char *path);
int brz_realpath(char *path);
int brz_skip(FILE *stream, size_t len);
int is_brz_file(FTSENT *p);
int fts_tree_walk(char * const *pathv,
                  int (*func)(FTS *, FTSENT *, void *), void *arg);

#endif /* _BRZ_UTILS_H_ */
