/* brz.c -- manipulate CMx2 BRZ resource files

   Copyright (C) 2013-2020 Michal Roszkowski

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
				 sizeof(brz_file_t) * (h)->prefix.nfiles)

#define BRZ_LEN(h)		((h)->file[(h)->prefix.nfiles].offset)
#define BRZ_FILE_LEN(h, n)	(((h)->file[(n) + 1].offset) -		\
				 ((h)->file[n].offset))

#define BRZ_FILE_HDR_LEN(f)	(sizeof((f)->offset) +			\
				 sizeof((f)->name_len) + (f)->name_len +\
				 sizeof((f)->dir_len) +	(f)->dir_len)

#define BRZ_FILE_OFFSET(f)	(*(brz_off_t *)(f))
#define BRZ_FILE_NAME(f)	(*(brz_str_t *)(&BRZ_FILE_OFFSET(f) + 1))
#define BRZ_FILE_DIR(f)		(*(brz_str_t *)((void *)&BRZ_FILE_NAME(f) + \
				 BRZ_SIZEOF_STR(&BRZ_FILE_NAME(f))))

#define BRZ_FILE_FPRINT(s, f)	fprintf((s), "%.*s%c%.*s",		\
					     (int)(f)->dir_len, (f)->dir, \
					     (f)->dir_len > 0? '/':'\0',\
					     (int)(f)->name_len, (f)->name)

#define BRZ_PREFIX_INIT(p)	do {					\
					(p)->magic = BRZ_MAGIC;		\
					(p)->nfiles = 0;		\
				} while (0)

#define BRZ_FILE_INIT(f)	do {					\
					(f)->name_len = (f)->dir_len = 0; \
					(f)->_path = NULL;		\
				} while (0)

typedef struct __attribute__((packed)) {
	brz_uint_t magic;
	brz_uint_t nfiles;
} brz_prefix_t;

typedef struct {
	brz_off_t offset;
	brz_strlen_t name_len;
	char *name;
	brz_strlen_t dir_len;
	char *dir;
	char *_path;
} brz_file_t;

typedef struct {
	brz_prefix_t prefix;
	brz_file_t file[1];
} brz_header_t;

typedef struct {
	brz_header_t *header;
	union {
		int fd;
		FILE *fp;
	} file;
} brz_t;

typedef struct __attribute__((packed)) {
	brz_strlen_t len;
	char str[];
} brz_str_t;

static int brz_extract_ftsent(FTS *fts, FTSENT *f, void *arg);
static int brz_add_ftsent(FTS *fts, FTSENT *f, void *arg);
static int brz_fprint_ftsent(FTS *fts, FTSENT *f, void *arg);
static int brz_extract_file(FILE *brz, int flags, brz_filter_t *filter);
static int brz_file_fwrite(brz_t *brz, brz_uint_t i, void *arg);
static int brz_fprint_file(FILE *brz, int flags,
			   brz_filter_t *filter, FILE *stream);
static int brz_file_vfprint(brz_t *brz, brz_uint_t i, FILE *stream);
static int brz_file_fprint(brz_t *brz, brz_uint_t i, FILE *stream);
static brz_t *brz_alloc(FILE *stream);
static void brz_free(brz_t *brz);
static brz_header_t *brz_read_header(FILE *brz);
static size_t brz_write_header(brz_header_t *hdr, FILE *stream);
static void brz_free_header(brz_header_t *hdr);
static inline void brz_free_header_file(brz_file_t *file);
static size_t brz_header_len(brz_header_t *hdr);
static int brz_header_lens2offs(brz_header_t *hdr);
static ssize_t brz_header_filter(brz_header_t *hdr, brz_filter_t *filter);
static ssize_t brz_header_walk(brz_t *brz,
			       brz_filter_t *filter,
			       int (*fn)(brz_t *, brz_uint_t, void *),
			       void *fn_arg);
static void _brz_replace_ch(char *s, int old_ch, int new_ch);
static void _brz_path_dos2unix(char *path);
static void _brz_path_unix2dos(char *path);

struct extract_args {
	int flags;
	brz_filter_t *filter;
	int ed;			/* extract directory */
	int wd;			/* working directory */
};

struct print_args {
	int flags;
	brz_filter_t *filter;
	FILE *stream;
};

int brz_extract(char *const *pathv,
		int flags,
		brz_filter_t *filter,
		const char *out_dir)
{
	struct extract_args args;
	int c, err = 0;

	if (brz_mkdir_p(out_dir, BRZ_DIR_MODE) == -1 &&
	    errno != EEXIST)
		return -1;

	args.ed = open(out_dir, O_RDONLY);
	args.wd = open(".", O_RDONLY);

	if (!pathv) {
		if (fchdir(args.ed))
			err = errno;

		while (!err && (c = getc(stdin)) != EOF) {
			ungetc(c, stdin);
			if (brz_extract_file(stdin, flags, filter) < 0)
				err = errno;
		}

		if (fchdir(args.wd))
			err = errno;

	} else {
		args.flags = flags;
		args.filter = filter;

		if (fts_tree_walk(pathv, brz_extract_ftsent, &args) < 0)
			err = errno;
	}

	close(args.ed);
	close(args.wd);

	if (err != 0) {
		errno = err;
		return -1;
	}
	return 0;
}

int brz_pack(char *const *pathv,
	     int flags,
	     brz_filter_t *filter,
	     const char *out_file)
{
	FILE *file, *stream;
	void *buf;
	int fd;
	size_t len;
	brz_header_t *p;
	brz_uint_t i;
	int err = 0;

	if (!(p = malloc(sizeof(brz_header_t))))
		return -1;

	BRZ_PREFIX_INIT(&p->prefix);
	BRZ_FILE_INIT(&p->file[0]);

	if (fts_tree_walk(pathv, brz_add_ftsent, &p) ||
	      brz_header_filter(p, filter) == -1) {
		err = errno;
		goto free;
	}

	if (brz_header_lens2offs(p)) {
		err = EFBIG;
		goto free;
	}

	if (!(file = (out_file)? fopen(out_file, "wb") : stdout)) {
		err = errno;
		goto free;
	}

	if (!brz_write_header(p, file)) {
		err = errno;
		goto fclose;
	}

	for (i = 0, stream = (file == stdout)? stderr : stdout;
	     !err && i < p->prefix.nfiles;
	     i++) {
		len = BRZ_FILE_LEN(p, i);

		if (flags & BRZ_FLAG_VERBOSE) {
			BRZ_FILE_FPRINT(stream, &p->file[i]);
			fputc('\n', stream);
			fflush(stream);
		}

		if ((fd = open(p->file[i]._path, BRZ_OPEN_READ)) == -1) {
			err = errno;
			continue;
		}

		if ((buf = mmap(0, len, PROT_READ, MAP_SHARED, fd, 0))
		      == MAP_FAILED) {
			err = errno;
			goto close;
		}

		if (!fwrite(buf, len, 1, file)) {
			err = EIO;
		}

		munmap(buf, len);
	close:
		if (close(fd)) {
			err = errno;
		}
	}

fclose:
	if (out_file &&
	    (ftruncate(fileno(file), BRZ_LEN(p)) | (fclose(file) == EOF))) {
		err = errno;
	}
free:
	brz_free_header(p);
	if (err != 0) {
		errno = err;
		return -1;
	}
	return 0;
}

int brz_list(char *const *pathv, int flags, brz_filter_t *filter)
{
	int c, rval = 0;

	if (!pathv) {
		while (!rval && (c = getc(stdin)) != EOF) {
			ungetc(c, stdin);
			rval = brz_fprint_file(stdin, flags, filter, stdout);
		}
	} else {
		struct print_args args = {
			.flags = flags,
			.filter = filter,
			.stream = stdout
		};
		rval = fts_tree_walk(pathv, brz_fprint_ftsent, &args);
	}

	return rval;
}

static int brz_extract_ftsent(FTS *fts, FTSENT *f, void *arg)
{
	struct extract_args *args = arg;
	FILE *file;
	int rval, err = 0;

	if (!is_brz_file(f))
		return 0;

	if (!(file = fopen(f->fts_accpath, "rb")))
		return -1;

	if (fchdir(args->ed)) {
		err = errno;
		rval = -1;
		goto close;
	}

	rval = brz_extract_file(file, args->flags, args->filter);

	if (rval < 0)
		err = errno;

	if (fchdir(args->wd)) {
		err = errno;
		rval = -1;
	}
close:
	fclose(file);
	if (err != 0)
		errno = err;
	return rval;
}

static int brz_add_ftsent(FTS *fts, FTSENT *f, void *arg)
{
	brz_header_t *sp, **hdr = arg;
	brz_file_t *file;

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
	if (sizeof((*hdr)->file->offset < sizeof(f->fts_statp->st_size)) &&
	   (typeof((*hdr)->file->offset))f->fts_statp->st_size !=
					 f->fts_statp->st_size) {
		errno = EFBIG;
		return -1;
	}

	(*hdr)->prefix.nfiles++;
	if ((*hdr = realloc(sp = *hdr, BRZ_SIZEOF_HEADER(*hdr))) == NULL) {
		(*hdr = sp)->prefix.nfiles--;
		return -1;
	}

	file = &(*hdr)->file[(*hdr)->prefix.nfiles - 1];
	BRZ_FILE_INIT(&(*hdr)->file[(*hdr)->prefix.nfiles]);

	if ((file->_path = malloc(f->fts_pathlen + 1)) == NULL) {
		errno = ENOMEM;
		(*hdr)->prefix.nfiles--;
		return -1;
	}

	memcpy(file->_path, f->fts_path, f->fts_pathlen + 1);

	file->offset = (typeof(file->offset))f->fts_statp->st_size;
	file->name_len = f->fts_namelen;
	file->name = file->_path + f->fts_pathlen - file->name_len;
	file->dir_len = f->fts_parent->fts_number;
	file->dir = file->_path + FTS_DIRLEN(f) - file->dir_len;

	return 0;
}

static int brz_fprint_ftsent(FTS *fts, FTSENT *f, void *arg)
{
	struct print_args *args = arg;
	FILE *file;
	int rval, err;

	if (!is_brz_file(f))
		return 0;

	if (!(file = fopen(f->fts_accpath, "rb")))
		return -1;

	if ((rval = brz_fprint_file(file, args->flags, args->filter,
				    args->stream)))
		err = errno;

	fclose(file);
	if (rval)
		errno = err;

	return rval;
}

struct file_fwrite_args {
	int flags;
	flt_fn_t *flt_fn;
	void *flt_arg;
};

static int brz_file_fwrite(brz_t *brz, brz_uint_t i, void *arg)
{
	struct file_fwrite_args *args = arg;
	int fd, err = 0, rval = 0;
	void *buf;
	char *dir;
	size_t file_len = BRZ_FILE_LEN(brz->header, i);

	if (args->flt_fn &&
	    args->flt_fn(brz->header->file[i].name, i, args->flt_arg)
	      == BRZ_FLT_MATCH)
		goto skip;

	if (args->flags & BRZ_FLAG_VERBOSE) {
		BRZ_FILE_FPRINT(stdout, &brz->header->file[i]);
		putchar('\n');
		fflush(stdout);
	}

	while ((fd = open(brz->header->file[i]._path, BRZ_OPEN_CREAT,
			  BRZ_FILE_MODE)) == -1)
		if (errno != ENOENT ||
		    (dir = strndup(brz->header->file[i].dir,
				   brz->header->file[i].dir_len)) == NULL ||
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

	if (!fread(buf, file_len, 1, brz->file.fp)) {
		err = ferror(brz->file.fp)? EIO : EFTYPE;
		rval = -1;
	}

	munmap(buf, file_len);
close:
	if (close(fd))
		err = errno;

	if (rval < 0) {
skip:
		brz_skip(brz->file.fp, file_len);
		errno = err;
	}

	return rval;
}

static int brz_extract_file(FILE *stream, int flags, brz_filter_t *filter)
{
	int err, rval;
	brz_t *brz;
	brz_filter_t filter_init;
	struct file_fwrite_args fw_args = { .flags = flags };

	if (!(brz = brz_alloc(stream)))
		return -1;

	if (filter) {
		fw_args.flt_fn = filter->flt_fn;
		fw_args.flt_arg = filter->flt_arg;

		memcpy(&filter_init, filter, sizeof(filter_init));
		filter_init.flt_fn = NULL;
	} else {
		fw_args.flt_fn = NULL;
		fw_args.flt_arg = NULL;

		memset(&filter_init, 0, sizeof(filter_init));
	}

	rval = brz_header_walk(brz, &filter_init, brz_file_fwrite, &fw_args);
	err = errno;

	brz_free(brz);

	if (rval)
		errno = err;
	return rval;
}

static int brz_file_vfprint(brz_t *brz, brz_uint_t i, FILE *stream)
{
	return fprintf(stream, "   %9lld ",
			       (long long)BRZ_FILE_LEN(brz->header, i)) +
	       brz_file_fprint(brz, i, stream);
}

static int brz_file_fprint(brz_t *brz, brz_uint_t i, FILE *stream)
{
	return BRZ_FILE_FPRINT(stream, &brz->header->file[i]) +
	       (fputc('\n', stream) != EOF);
}

static int brz_fprint_file(FILE *file, int flags,
			   brz_filter_t *filter, FILE *stream)
{
	brz_t *brz;
	int rval, err;

	if (!(brz = brz_alloc(file)))
		return -1;

	if ((rval = (flags & BRZ_FLAG_VERBOSE)?
	    brz_header_walk(brz, filter,
			    (int (*)(brz_t *, brz_uint_t, void *))
			    brz_file_vfprint, stream) :
	    brz_header_walk(brz, filter,
			    (int (*)(brz_t *, brz_uint_t, void *))
			    brz_file_fprint, stream)) == -1) {
		err = errno;
		goto free;
	}

	if ((rval = brz_skip(brz->file.fp, BRZ_LEN(brz->header)
					    - brz_header_len(brz->header))))
		err = errno;

free:
	brz_free(brz);
	if (rval)
		errno = err;
	return rval;
}

static brz_t *brz_alloc(FILE *stream)
{
	brz_t *brz;

	if ((brz = malloc(sizeof(*brz))) == NULL)
		return NULL;

	brz->file.fp = stream;

	if ((brz->header = brz_read_header(stream)) == NULL) {
		free(brz);
		return NULL;
	}

	return brz;
}

static brz_header_t *brz_read_header(FILE *brz)
{
	brz_header_t *p, *sp;
	brz_uint_t i = 0;
	int err;

	if (!(p = malloc(sizeof(brz_header_t))))
		return NULL;

	if (!fread(p, sizeof(brz_prefix_t), 1, brz))
		goto free;

	if (p->prefix.magic != BRZ_MAGIC) {
		errno = EFTYPE;
		goto free;
	}

	if (!(p = realloc(sp = p, BRZ_SIZEOF_HEADER(p)))) {
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
						 p->file[i].name_len + 1
						  + p->file[i].dir_len + 1)) ||
		      (p->file[i]._path = p->file[i].dir,
		       p->file[i].name = memmove(p->file[i]._path
						  + p->file[i].dir_len + 1,
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
			p->prefix.nfiles = i + 1;
			brz_free_header(p);
			goto error;
		}
	} while (i++ < p->prefix.nfiles);

	return p;
free:
	err = errno;
	free(p);
error:	errno = err;
	return NULL;
}

static size_t brz_write_header(brz_header_t *hdr, FILE *stream)
{
	brz_uint_t i = 0;
	void *p, *buf = NULL;
	size_t buf_size = 0;

	if (!fwrite(hdr, sizeof(brz_prefix_t), 1, stream))
		return 0;

	do {
		size_t file_hdr_len = BRZ_FILE_HDR_LEN(&hdr->file[i]);

		if (buf_size < file_hdr_len &&
		    !(buf = realloc(p = buf, (buf_size = file_hdr_len) + 1))) {
			free(p);
			errno = ENOMEM;
			return 0;
		}

		BRZ_FILE_OFFSET(buf) = hdr->file[i].offset;
		BRZ_FILE_NAME(buf).len = hdr->file[i].name_len;
		memcpy(BRZ_FILE_NAME(buf).str, hdr->file[i].name,
		       hdr->file[i].name_len);
		BRZ_FILE_DIR(buf).len = hdr->file[i].dir_len;
		memcpy(BRZ_FILE_DIR(buf).str, hdr->file[i].dir,
		       hdr->file[i].dir_len);

		BRZ_FILE_DIR(buf).str[hdr->file[i].dir_len] = '\0';
		_brz_path_unix2dos(BRZ_FILE_DIR(buf).str);

		if (!fwrite(buf, file_hdr_len, 1, stream)) {
			free(buf);
			errno = EIO;
			return 0;
		}
	} while (i++ < hdr->prefix.nfiles);

	free(buf);
	return i;
}

static void brz_free(brz_t *brz)
{
	brz_free_header(brz->header);
	free(brz);
}

static void brz_free_header(brz_header_t *hdr)
{
	brz_uint_t i;

	for (i = 0; i < hdr->prefix.nfiles; i++)
		brz_free_header_file(&hdr->file[i]);

	free(hdr);
}

static inline void brz_free_header_file(brz_file_t *file)
{
	free(file->_path);
	BRZ_FILE_INIT(file);
}

static size_t brz_header_len(brz_header_t *hdr)
{
	size_t len = sizeof(hdr->prefix);
	brz_uint_t i = 0;

	do
		len += BRZ_FILE_HDR_LEN(&hdr->file[i]);
	while (i++ < hdr->prefix.nfiles);

	return len;
}

static int brz_header_lens2offs(brz_header_t *hdr)
{
	brz_off_t len, offset = brz_header_len(hdr);
	brz_uint_t i = 0;

	do {
		len = hdr->file[i].offset;
		hdr->file[i].offset = offset;
	} while (i++ < hdr->prefix.nfiles &&
		 !__builtin_add_overflow(len, offset, &offset));

	return -(i <= hdr->prefix.nfiles);
}

static ssize_t brz_header_filter(brz_header_t *hdr, brz_filter_t *filter)
{
	if (!filter)
		return hdr->prefix.nfiles;

	if (filter->flt_init &&
	    filter->flt_init(hdr->prefix.nfiles, filter->flt_arg))
		return -1;

	if (filter->flt_fn) {
		brz_uint_t i = hdr->prefix.nfiles;
		brz_uint_t j = 0;

		do {
			if (i > 0 &&
			    filter->flt_fn(hdr->file[i-1].name, i-1,
					   filter->flt_arg) == BRZ_FLT_MATCH) {
				if (!j) j = i;
				continue;
			}

			if (j) {
				memmove(&hdr->file[i], &hdr->file[j],
					(hdr->prefix.nfiles - j + 1)
					 * sizeof(brz_file_t));
				hdr->prefix.nfiles -= j - i;
				j = 0;
			}
		} while (i-- > 0);
	}

	if (filter->flt_fini)
		filter->flt_fini(filter->flt_arg);

	return hdr->prefix.nfiles;
}

static ssize_t brz_header_walk(brz_t *brz,
			       brz_filter_t *filter,
			       int (*fn)(brz_t *, brz_uint_t, void *),
			       void *fn_arg)
{
	brz_uint_t i, n;

	if (filter && filter->flt_init &&
	    filter->flt_init(brz->header->prefix.nfiles, filter->flt_arg))
		return -1;

	if (filter && filter->flt_fn) {
		i = brz->header->prefix.nfiles;
		while (i > 0) {
			i--;
			filter->flt_fn(brz->header->file[i].name, i,
				       filter->flt_arg);
		}
	}

	for (i = n = 0; i < brz->header->prefix.nfiles; i++)
		if (!filter || !filter->flt_fn ||
		    filter->flt_fn(brz->header->file[i].name, i,
				   filter->flt_arg) == BRZ_FLT_NOMATCH) {
			fn(brz, i, fn_arg);
			n++;
		}

	if (filter && filter->flt_fini)
		filter->flt_fini(filter->flt_arg);

	return n;
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
