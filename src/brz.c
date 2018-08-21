/* brz.c -- manipulate CMx2 BRZ resource files

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

#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include "brz_utils.h"
#include "brz.h"

#ifndef EFTYPE
#define EFTYPE EINVAL
#endif

#define BRZ_OPEN_READ (O_RDONLY)
#define BRZ_OPEN_CREAT (O_RDWR|O_CREAT|O_EXCL)

#define BRZ_FILE_MODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)
#define BRZ_DIR_MODE (S_IRWXU|S_IRWXG|S_IRWXO)

#define BRZ_MAGIC 0x00000000

typedef uint16_t brz_strlen_t;
typedef uint32_t brz_uint_t;
typedef  int32_t brz_int_t;
typedef  int32_t brz_off_t;

#define BRZ_SIZEOF_STR(s)	(sizeof(brz_str_t) + (s)->len)
#define BRZ_SIZEOF_HEADER(h) 	(sizeof(brz_header_t) +			\
				 sizeof(brz_file_t) * (h)->header.nfiles)

#define BRZ_LEN(h)		((h)->file[(h)->header.nfiles].offset)
#define BRZ_FILE_LEN(h, n)	(((h)->file[(n) + 1].offset) -		\
				 ((h)->file[n].offset))

#define BRZ_FILE_HDR_LEN(f)	(sizeof((f)->offset) +			\
				 sizeof((f)->name_len) + (f)->name_len +\
				 sizeof((f)->dir_len) +	(f)->dir_len)

#define BRZ_FILE_OFFSET(f)	(*(brz_off_t *)(f))
#define BRZ_FILE_NAME(f)	(*(brz_str_t *)(&BRZ_FILE_OFFSET(f) + 1))
#define BRZ_FILE_DIR(f)		(*(brz_str_t *)((void *)&BRZ_FILE_NAME(f) + \
				 BRZ_SIZEOF_STR(&BRZ_FILE_NAME(f))))

#define BRZ_FILE_INIT(f)	do {					\
					(f)->name_len = (f)->dir_len = 0; \
					(f)->_path = NULL;		\
				} while (0)

typedef struct __attribute__((packed)) {
	brz_uint_t magic;
	brz_uint_t nfiles;
} brz_hdr_t;

typedef struct {
	brz_off_t offset;
	brz_strlen_t name_len;
	char *name;
	brz_strlen_t dir_len;
	char *dir;
	char *_path;
} brz_file_t;

typedef struct {
	brz_hdr_t header;
	brz_file_t file[1];
} brz_header_t;

typedef struct __attribute__((packed)) {
	brz_strlen_t len;
	char str[];
} brz_str_t;

static int brz_explode_ftsent(FTS *fts, FTSENT *f, void *arg);
static int brz_add_ftsent(FTS *fts, FTSENT *f, void *arg);
static int brz_fprint_ftsent(FTS *fts, FTSENT *f, void *arg);
static int brz_explode_file(FILE *brz,
			    filterfn_t *filterfn,
			    filter_init_t *filter_init,
			    filter_fini_t *filter_fini,
			    void *arg);
static int brz_fprint_file(FILE *brz, FILE *stream);
static brz_header_t *brz_read_header(FILE *brz);
static size_t brz_write_header(brz_header_t *brz, FILE *stream);
static void brz_free_header(brz_header_t *brz);
static inline void brz_free_header_file(brz_file_t *file);
static size_t brz_header_len(brz_header_t *brz);
static int brz_header_lens2offs(brz_header_t *brz);
static brz_uint_t brz_header_filter(brz_header_t *brz,
				    filterfn_t *filterfn,
				    void *filter_args);
static void _brz_replace_ch(char *s, int old_ch, int new_ch);
static void _brz_path_dos2unix(char *path);
static void _brz_path_unix2dos(char *path);

struct explode_args {
	int ed;			/* explode directory */
	int wd;			/* working directory */
	filterfn_t *filterfn;
	filter_init_t *filter_init; /* constructor */
	filter_fini_t *filter_fini; /* destructor */
	void *filter_args;
};

int brz_explode(char *const *pathv,
		const char *explode_dir,
		filterfn_t *filterfn,
		filter_init_t *filter_init,
		filter_fini_t *filter_fini,
		void *filter_args)
{
	struct explode_args args;
	int c, err = 0, rval = 0;

	if (brz_mkdir_p(explode_dir, BRZ_DIR_MODE) == -1 &&
	    errno != EEXIST)
		return -1;

	args.ed = open(explode_dir, O_RDONLY);
	args.wd = open(".", O_RDONLY);
	args.filterfn = filterfn;
	args.filter_init = filter_init;
	args.filter_fini = filter_fini;
	args.filter_args = filter_args;

	if (!pathv) {
		if (fchdir(args.ed)) {
			err = errno;
			rval = -1;
		}
		while (!rval && (c = getc(stdin)) != EOF) {
			ungetc(c, stdin);
			rval = brz_explode_file(stdin,
						filterfn,
						filter_init,
						filter_fini,
						filter_args);
			if (rval < 0)
				err = errno;
		}
		if (fchdir(args.wd)) {
			err = errno;
			rval = -1;
		}
	} else {
		if ((rval =
		    fts_tree_walk(pathv, brz_explode_ftsent, &args)) < 0)
			err = errno;
	}

	close(args.ed);
	close(args.wd);

	errno = err;
	return rval;
}

int brz_pack(char *const *pathv,
	     const char *pack_file,
	     filterfn_t *filterfn,
	     filter_init_t *filter_init,
	     filter_fini_t *filter_fini,
	     void *filter_args)
{
	FILE *file;
	void *buf;
	int fd;
	size_t len;
	brz_header_t *p;
	brz_uint_t i;
	int err = 0, rval = 0;

	if (!(p = malloc(sizeof(brz_header_t))))
		return -1;

	p->header.magic = BRZ_MAGIC;
	p->header.nfiles = 0;
	BRZ_FILE_INIT(&p->file[0]);

	if (fts_tree_walk(pathv, brz_add_ftsent, &p) ||
	    (filter_init && filter_init(p->header.nfiles, filter_args))) {
		err = errno;
		rval = -1;
		goto free;
	}

	brz_header_filter(p, filterfn, filter_args);

	if ((rval = brz_header_lens2offs(p)) != 0)
		err = EFBIG;

	if (filter_fini)
		filter_fini(filter_args);

	if (rval != 0) {
		rval = -1;
		goto free;
	}

	if (!p->header.nfiles)
		goto free;

	if (!(file = (pack_file)? fopen(pack_file, "wb") : stdout)) {
		err = errno;
		rval = -1;
		goto free;
	}

	if (!brz_write_header(p, file)) {
		err = errno;
		rval = -1;
		goto fclose;
	}

	for (i = 0; !rval && i < p->header.nfiles; i++) {
		len = BRZ_FILE_LEN(p, i);

		if ((fd = open(p->file[i]._path, BRZ_OPEN_READ)) == -1) {
			err = errno;
			rval = -1;
			continue;
		}

		if ((buf = mmap(0, len, PROT_READ, MAP_SHARED, fd, 0))
			== MAP_FAILED) {
			err = errno;
			rval = -1;
			goto close;
		}

		if (!fwrite(buf, len, 1, file)) {
			err = EIO;
			rval = -1;
		}

		munmap(buf, len);
	close:
		if (close(fd)) {
			err = errno;
			rval = -1;
		}
	}

fclose:
	if (pack_file &&
	    (ftruncate(fileno(file), BRZ_LEN(p)) | (fclose(file) == EOF))) {
		err = errno;
		rval = -1;
	}
free:
	brz_free_header(p);
	if (rval < 0)
		errno = err;
	return rval;
}

int brz_list(char *const *pathv)
{
	int c, rval = 0;

	if (!pathv) {
		while (!rval && (c = getc(stdin)) != EOF) {
			ungetc(c, stdin);
			rval = brz_fprint_file(stdin, stdout);
		}
	} else {
		rval = fts_tree_walk(pathv, brz_fprint_ftsent, stdout);
	}

	return rval;
}

static int brz_explode_ftsent(FTS *fts, FTSENT *f, void *arg)
{
	struct explode_args *args = arg;
	FILE *file;
	int err = 0, rval = 0;

	if (!is_brz_file(f))
		return 0;

	if (!(file = fopen(f->fts_accpath, "rb")))
		return -1;

	if (fchdir(args->ed)) {
		err = errno;
		rval = -1;
		goto close;
	}

	rval = brz_explode_file(file,
				args->filterfn,
				args->filter_init,
				args->filter_fini,
				args->filter_args);
	if (rval < 0)
		err = errno;

	if (fchdir(args->wd)) {
		err = errno;
		rval = -1;
	}
close:
	fclose(file);
	if (rval < 0)
		errno = err;
	return rval;
}

static int brz_add_ftsent(FTS *fts, FTSENT *f, void *arg)
{
	brz_header_t *sp, **brz = arg;
	brz_file_t *new;

	if (f->fts_info == FTS_D) {
		if (f->fts_level > FTS_ROOTLEVEL && f->fts_name[0] == '.') {
			fts_set(fts, f, FTS_SKIP);
			return 0;
		}

		if (f->fts_level > FTS_ROOTLEVEL || (!IS_ROOT(f->fts_name) &&
		    !IS_DOT(f->fts_name) && !IS_DOTDOT(f->fts_name)))
			/* store dir_len in fts_number */
			f->fts_number = f->fts_namelen+f->fts_parent->fts_number
					/* include trailing '/' */
					+ !!f->fts_parent->fts_number;
		return 0;
	}

	if (f->fts_info != FTS_F || f->fts_statp->st_size == 0 ||
	    (f->fts_level > FTS_ROOTLEVEL && f->fts_name[0] == '.'))
		return 0;

	/* check for overflow */
	if (sizeof((*brz)->file->offset < sizeof(f->fts_statp->st_size)) &&
	   (typeof((*brz)->file->offset))f->fts_statp->st_size !=
					 f->fts_statp->st_size) {
		errno = EFBIG;
		return -1;
	}

	(*brz)->header.nfiles++;
	if ((*brz = realloc(sp = *brz, BRZ_SIZEOF_HEADER(*brz))) == NULL) {
		(*brz = sp)->header.nfiles--;
		return -1;
	}

	new = &(*brz)->file[(*brz)->header.nfiles - 1];
	BRZ_FILE_INIT(&(*brz)->file[(*brz)->header.nfiles]);

	if ((new->_path = malloc(f->fts_pathlen + 1)) == NULL) {
		errno = ENOMEM;
		(*brz)->header.nfiles--;
		return -1;
	}

	memcpy(new->_path, f->fts_path, f->fts_pathlen + 1);

	new->offset = (typeof(new->offset))f->fts_statp->st_size;
	new->name_len = f->fts_namelen;
	new->name = new->_path + f->fts_pathlen - new->name_len;
	new->dir_len = f->fts_parent->fts_number;
	new->dir = new->_path + FTS_DIRLEN(f) - new->dir_len;

	return 0;
}

static int brz_fprint_ftsent(FTS *fts, FTSENT *f, void *arg)
{
	FILE *file;
	int rval;

	if (!is_brz_file(f))
		return 0;

	if (!(file = fopen(f->fts_accpath, "rb")))
		return -1;

	rval = brz_fprint_file(file, (FILE *)arg);

	fclose(file);
	return rval;
}

static int brz_explode_file(FILE *brz,
			    filterfn_t *filterfn,
			    filter_init_t *filter_init,
			    filter_fini_t *filter_fini,
			    void *arg)
{
	brz_header_t *p;
	int err = 0, rval = 0;
	brz_uint_t i;
	size_t n;

	if (!(p = brz_read_header(brz)))
		return -1;

	if (filter_init && filter_init(p->header.nfiles, arg)) {
		err = errno;
		rval = -1;
		goto free;
	}

	for (i = n = 0; i < p->header.nfiles; n = ++i) {
		int fd;
		void *buf;
		char *dir;
		size_t file_len = BRZ_FILE_LEN(p, i);

		if (filterfn)
			switch (filterfn(p->file[i].name, &n, arg)) {
			case BRZ_FILTER_MATCH:
				goto skip;
			case BRZ_FILTER_REPLACE:
				unlink(p->file[n]._path);
				if (p->file[n].dir_len > 0) {
					if ((dir = strndup(p->file[n].dir,
							   p->file[n].dir_len)))
					{
						brz_rmdir_p(dir);
						free(dir);
					}
				}
			case BRZ_FILTER_NOMATCH:
			default:
				break;
			}

		while ((fd = open(p->file[i]._path, BRZ_OPEN_CREAT,
				  BRZ_FILE_MODE)) == -1)
			if (errno != ENOENT ||
			    (dir = strndup(p->file[i].dir, p->file[i].dir_len))
				 == NULL ||
			    (rval = brz_mkdir_p(dir, BRZ_DIR_MODE), free(dir),
			     rval == -1)) {
				err = errno;
				rval = -1;
				goto skip;
			}

		if (ftruncate(fd, file_len) ||
		    (buf = mmap(0, file_len, PROT_WRITE, MAP_SHARED, fd, 0))
			== MAP_FAILED) {
			err = errno;
			rval = -1;
			goto close;
		}

		if (!fread(buf, file_len, 1, brz)) {
			err = ferror(brz)? EIO : EFTYPE;
			rval = -1;
		}

		munmap(buf, file_len);
	close:
		if (close(fd)) {
			err = errno;
			rval = -1;
		}

		if (rval < 0) {
	skip:
			brz_skip(brz, file_len);
			rval = 0;
		}
	}

	if (filter_fini)
		filter_fini(arg);
free:
	brz_free_header(p);
	if (err) {
		errno = err;
		return -1;
	}
	return 0;
}

static int brz_fprint_file(FILE *brz, FILE *stream)
{
	brz_uint_t i;
	brz_header_t *p;
	int rval;

	if (!(p = brz_read_header(brz)))
		return -1;

	fputs("\tsize name\n", stream);
	for (i = 0; i < p->header.nfiles; i++) {
		fprintf(stream, "   %9lld ", (long long)BRZ_FILE_LEN(p, i));
		if (p->file[i].dir_len > 0)
			fprintf(stream, "%.*s%c", (int)p->file[i].dir_len,
					p->file[i].dir, '/');
		fprintf(stream, "%.*s\n", (int)p->file[i].name_len,
				p->file[i].name);
	}

	rval = brz_skip(brz, BRZ_LEN(p) - brz_header_len(p));

	brz_free_header(p);
	return rval;
}

static brz_header_t *brz_read_header(FILE *brz)
{
	brz_header_t *p, *sp;
	brz_uint_t i = 0;
	int err;

	if (!(sp = p = malloc(sizeof(brz_header_t))))
		return NULL;

	if (!fread(p, sizeof(brz_hdr_t), 1, brz))
		goto free;

	if (p->header.magic != BRZ_MAGIC) {
		errno = EFTYPE;
		goto free;
	}

	if (!(p = realloc(p, BRZ_SIZEOF_HEADER(p)))) {
		p = sp;
		goto free;
	}

	do {
		BRZ_FILE_INIT(&p->file[i]);

		if (!fread(&p->file[i].offset,
			   sizeof(p->file[i].offset), 1, brz) ||

		    !fread(&p->file[i].name_len,
			   sizeof(p->file[i].name_len), 1, brz) ||
		    p->file[i].name_len > NAME_MAX ||

		    (p->file[i].name_len > 0 &&
		     (!(p->file[i].name = p->file[i]._path =
			malloc(p->file[i].name_len + 1)) ||
		      (p->file[i].name[p->file[i].name_len] = '\0',
		       !fread(p->file[i].name, p->file[i].name_len, 1, brz)) ||
		      p->file[i].name != brz_basename(p->file[i].name))) ||

		    !fread(&p->file[i].dir_len,
			   sizeof(p->file[i].dir_len), 1, brz) ||
		    p->file[i].dir_len >= PATH_MAX - p->file[i].name_len - 1 ||

		    (p->file[i].dir_len > 0 &&
		     (!(p->file[i].dir = realloc(p->file[i]._path,
						 p->file[i].name_len + 1 +
						 p->file[i].dir_len + 1)) ||
		      (p->file[i]._path = p->file[i].dir,
		       p->file[i].name = memmove(p->file[i]._path +
						  p->file[i].dir_len + 1,
						 p->file[i]._path,
						 p->file[i].name_len + 1),
		       p->file[i]._path[p->file[i].dir_len] = '\0',
		       !fread(p->file[i].dir, p->file[i].dir_len, 1, brz)) ||
		      (_brz_path_dos2unix(p->file[i].dir),
		       p->file[i].dir_len != brz_realpath(p->file[i].dir)) ||
		      (p->file[i]._path[p->file[i].dir_len] = '/', 0)))) {
			if (ferror(brz) || feof(brz))
				err = EIO;
			else if ((p->file[i].name_len && !p->file[i].name) ||
				 (p->file[i].dir_len && !p->file[i].dir))
				err = ENOMEM;
			else
				err = EFTYPE;
			p->header.nfiles = i + 1;
			brz_free_header(p);
			goto error;
		}
	} while (i++ < p->header.nfiles);

	return p;
free:
	err = errno;
	free(p);
error:	errno = err;
	return NULL;
}

static size_t brz_write_header(brz_header_t *brz, FILE *stream)
{
	brz_uint_t i = 0;
	void *p, *buf = NULL;
	size_t buf_size = 0;

	if (!fwrite(brz, sizeof(brz_hdr_t), 1, stream))
		return 0;

	do {
		size_t file_hdr_len = BRZ_FILE_HDR_LEN(&brz->file[i]);

		if (buf_size < file_hdr_len &&
		    !(buf = realloc(p = buf, (buf_size = file_hdr_len) + 1))) {
			free(p);
			errno = ENOMEM;
			return 0;
		}

		BRZ_FILE_OFFSET(buf) = brz->file[i].offset;
		BRZ_FILE_NAME(buf).len = brz->file[i].name_len;
		memcpy(BRZ_FILE_NAME(buf).str, brz->file[i].name,
		       brz->file[i].name_len);
		BRZ_FILE_DIR(buf).len = brz->file[i].dir_len;
		memcpy(BRZ_FILE_DIR(buf).str, brz->file[i].dir,
		       brz->file[i].dir_len);

		BRZ_FILE_DIR(buf).str[brz->file[i].dir_len] = '\0';
		_brz_path_unix2dos(BRZ_FILE_DIR(buf).str);

		if (!fwrite(buf, file_hdr_len, 1, stream)) {
			free(buf);
			errno = EIO;
			return 0;
		}
	} while (i++ < brz->header.nfiles);

	free(buf);
	return i;
}

static void brz_free_header(brz_header_t *brz)
{
	brz_uint_t i;

	for (i = 0; i < brz->header.nfiles; i++)
		brz_free_header_file(&brz->file[i]);

	free(brz);
}

static inline void brz_free_header_file(brz_file_t *file)
{
	free(file->_path);
	BRZ_FILE_INIT(file);
}

static size_t brz_header_len(brz_header_t *brz)
{
	size_t len = sizeof(brz->header);
	brz_uint_t i = 0;

	do
		len += BRZ_FILE_HDR_LEN(&brz->file[i]);
	while (i++ < brz->header.nfiles);

	return len;
}

static int brz_header_lens2offs(brz_header_t *brz)
{
	brz_off_t len, offset = brz_header_len(brz);
	brz_uint_t i = 0;

	do {
		len = brz->file[i].offset;
		brz->file[i].offset = offset;
	} while (i++ < brz->header.nfiles &&
		 !__builtin_add_overflow(len, offset, &offset));

	return -(i <= brz->header.nfiles);
}

static brz_uint_t brz_header_filter(brz_header_t *brz,
				    filterfn_t *filterfn,
				    void *filter_args)
{
	brz_uint_t i;
	size_t n;

	if (!filterfn)
		return brz->header.nfiles;

	for (i = n = 0; i < brz->header.nfiles; n = ++i)
		switch (filterfn(brz->file[i].name, &n, filter_args)) {
		case BRZ_FILTER_REPLACE:
		case BRZ_FILTER_MATCH:
			if (n <= i)
				brz_free_header_file(&brz->file[n]);
			break;
		case BRZ_FILTER_NOMATCH:
		default:
			break;
		}

	for (i = 0; i < brz->header.nfiles; i++)
		if (!brz->file[i].name_len) {
			for (n = i + 1;
			     n < brz->header.nfiles && !brz->file[n].name_len;
			     n++);
			memmove(&brz->file[i], &brz->file[n],
				(void *)&brz->file[brz->header.nfiles + 1]
				- (void *)&brz->file[n]);
			brz->header.nfiles -= n - i;
		}

	return brz->header.nfiles;
}

static void _brz_path_dos2unix(char *path)
{
	_brz_replace_ch(path, '\\', '/');
}

static void _brz_path_unix2dos(char *path)
{
	_brz_replace_ch(path, '/', '\\');
}

static void _brz_replace_ch(char *s, int old_ch, int new_ch)
{
	while ((s = strchr(s, old_ch)))
		*s++ = new_ch;
}
