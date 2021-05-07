/* brz.c -- manipulate CMx2 BRZ resource files

   Copyright (C) 2013-2021 Michal Roszkowski

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
#include <sys/param.h>
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

#define BRZ_FILES_MAX		MIN((SIZE_MAX - sizeof(brz_header_t))	\
				 / sizeof(brz_file_t), (brz_uint_t)-1)
#define BRZ_SIZEOF_HEADER(h) 	(sizeof(brz_header_t) +			\
				 sizeof(brz_file_t) * (h)->nfiles)
#define BRZ_SIZEOF_STR(s)	(sizeof(brz_str_t) + (s)->len)

#define BRZ_LEN(h)		((h)->file[(h)->nfiles].offset)
#define BRZ_FILE_LEN(h, n)	(((h)->file[(n) + 1].offset) -		\
				 ((h)->file[n].offset))

#define BRZ_FILE_HDR_LEN(f)	(sizeof((f)->offset) +			\
				 sizeof((f)->name_len) + (f)->name_len +\
				 sizeof((f)->dir_len) +	(f)->dir_len)

#define BRZ_FILE_FPRINT(s, f)	fprintf((s), "%.*s%c%.*s",		\
					     (int)(f)->dir_len, (f)->dir, \
					     (f)->dir_len > 0? '/':'\0',\
					     (int)(f)->name_len, (f)->name)

#define BRZ_INIT(p)		do {					\
					(p)->magic = BRZ_MAGIC;		\
					(p)->nfiles = 0;		\
					BRZ_FILE_INIT(&(p)->file[0]);	\
				} while (0)

#define BRZ_FILE_INIT(f)	do {					\
					(f)->name_len = (f)->dir_len = 0; \
					(f)->_path = NULL;		\
				} while (0)

#define BRZ_DEC(le, he)	do {						\
				uint8_t const *_le = (uint8_t const *)(le); \
				unsigned _i = 0;			\
				(he) = 0;				\
				do					\
					(he) |= _le[_i] << (_i*8);	\
				while (++_i < sizeof(he));		\
				(le) = (typeof(le))&_le[_i];		\
			} while (0)

#define BRZ_ENC(le, he)	do {						\
				uint8_t *_le = (uint8_t *)(le);		\
				unsigned _i = 0;			\
				do					\
					_le[_i] = ((he) >> (_i*8)) & 0xff; \
				while (++_i < sizeof(he));		\
				(le) = (typeof(le))&_le[_i];		\
			} while (0)

typedef struct {
	brz_off_t offset;
	brz_strlen_t name_len;
	char *name;
	brz_strlen_t dir_len;
	char *dir;
	char *_path;
} brz_file_t;

typedef struct {
	brz_uint_t magic;
	brz_uint_t nfiles;
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

static inline brz_uint_t brz_decode_int(void *le);
static inline brz_off_t brz_decode_offset(void *le);
static inline brz_strlen_t brz_decode_strlen(void *le);
static inline void brz_free_header_file(brz_file_t *file);
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
static void *brz_encode_file_hdr(void *dst, brz_file_t *file);
static void brz_free_header(brz_header_t *hdr);
static size_t brz_header_len(brz_header_t *hdr);
static int brz_header_lens2offs(brz_header_t *hdr);
static ssize_t brz_header_filter(brz_header_t *hdr, brz_filter_t *filter);
static ssize_t brz_header_walk(brz_t *brz,
			       brz_filter_t *filter,
			       int (*fn)(brz_t *, brz_uint_t, void *),
			       void *fn_arg);

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

	BRZ_INIT(p);

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
	     !err && i < p->nfiles;
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
	if ((*hdr)->nfiles == BRZ_FILES_MAX ||
	    (sizeof((*hdr)->file->offset < sizeof(f->fts_statp->st_size)) &&
	    (typeof((*hdr)->file->offset))f->fts_statp->st_size !=
					  f->fts_statp->st_size)) {
		errno = EFBIG;
		return -1;
	}

	(*hdr)->nfiles++;
	if ((*hdr = realloc(sp = *hdr, BRZ_SIZEOF_HEADER(*hdr))) == NULL) {
		(*hdr = sp)->nfiles--;
		return -1;
	}

	file = &(*hdr)->file[(*hdr)->nfiles - 1];
	BRZ_FILE_INIT(&(*hdr)->file[(*hdr)->nfiles]);

	if ((file->_path = malloc(f->fts_pathlen + 1)) == NULL) {
		errno = ENOMEM;
		(*hdr)->nfiles--;
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

	if (!fread(&p->magic, sizeof(p->magic), 1, brz) ||
	    !fread(&p->nfiles, sizeof(p->nfiles), 1, brz))
		goto free;

	p->magic = brz_decode_int(&p->magic);
	p->nfiles = brz_decode_int(&p->nfiles);

	if (p->magic != BRZ_MAGIC) {
		errno = EFTYPE;
		goto free;
	}

	if (p->nfiles > BRZ_FILES_MAX) {
		errno = EFBIG;
		goto free;
	}

	if (!(p = realloc(sp = p, BRZ_SIZEOF_HEADER(p)))) {
		p = sp;
		goto free;
	}

	do {
		BRZ_FILE_INIT(&p->file[i]);

		if ((!fread(&p->file[i].offset,
			    sizeof(p->file[i].offset), 1, brz) ||
		     (p->file[i].offset =
			brz_decode_offset(&p->file[i].offset), 0)) ||

		    (!fread(&p->file[i].name_len,
			    sizeof(p->file[i].name_len), 1, brz) ||
		     (p->file[i].name_len =
			brz_decode_strlen(&p->file[i].name_len), 0)) ||
		    p->file[i].name_len > NAME_MAX ||

		    (p->file[i].name_len > 0 &&
		     (!(p->file[i].name = p->file[i]._path =
			malloc(p->file[i].name_len + 1)) ||
		      (p->file[i].name[p->file[i].name_len] = '\0',
		       !fread(p->file[i].name, p->file[i].name_len, 1, brz)) ||
		      p->file[i].name != brz_basename(p->file[i].name))) ||

		    (!fread(&p->file[i].dir_len,
			    sizeof(p->file[i].dir_len), 1, brz) ||
		     (p->file[i].dir_len =
			brz_decode_strlen(&p->file[i].dir_len), 0)) ||
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
		      (brz_path_dos2unix(p->file[i].dir, p->file[i].dir_len),
		       p->file[i].dir_len != brz_realpath(p->file[i].dir)) ||
		      (p->file[i]._path[p->file[i].dir_len] = '/', 0)))) {
			if (ferror(brz) || feof(brz))
				err = EIO;
			else if ((p->file[i].name_len && !p->file[i].name) ||
				 (p->file[i].dir_len && !p->file[i].dir))
				err = ENOMEM;
			else
				err = EFTYPE;
			p->nfiles = i + 1;
			brz_free_header(p);
			goto error;
		}
	} while (i++ < p->nfiles);

	return p;
free:
	err = errno;
	free(p);
error:	errno = err;
	return NULL;
}

static inline brz_uint_t brz_decode_int(void *le)
{
	brz_uint_t he;
	BRZ_DEC(le, he);
	return he;
}

static inline brz_off_t brz_decode_offset(void *le)
{
	brz_off_t he;
	BRZ_DEC(le, he);
	return he;
}

static inline brz_strlen_t brz_decode_strlen(void *le)
{
	brz_strlen_t he;
	BRZ_DEC(le, he);
	return he;
}

static size_t brz_write_header(brz_header_t *hdr, FILE *stream)
{
	brz_uint_t i = 0;
	void *p, *buf;
	size_t buf_size;

	if ((buf = p = malloc(buf_size = sizeof(brz_header_t))) == NULL)
		return 0;

	BRZ_ENC(p, hdr->magic);
	BRZ_ENC(p, hdr->nfiles);

	if (!fwrite(buf, sizeof(hdr->magic) + sizeof(hdr->nfiles), 1, stream)) {
		free(buf);
		errno = EIO;
		return 0;
	}

	do {
		size_t file_hdr_len = BRZ_FILE_HDR_LEN(&hdr->file[i]);

		if (buf_size < file_hdr_len &&
		    !(buf = realloc(p = buf, buf_size = file_hdr_len))) {
			free(p);
			errno = ENOMEM;
			return 0;
		}

		brz_encode_file_hdr(buf, &hdr->file[i]);

		if (!fwrite(buf, file_hdr_len, 1, stream)) {
			free(buf);
			errno = EIO;
			return 0;
		}
	} while (i++ < hdr->nfiles);

	free(buf);
	return i;
}

static void *brz_encode_file_hdr(void *dst, brz_file_t *file)
{
	void *p = dst;

	BRZ_ENC(p, file->offset);
	BRZ_ENC(p, file->name_len);
	p = memcpy(p, file->name, file->name_len) + file->name_len;
	BRZ_ENC(p, file->dir_len);
	memcpy(p, file->dir, file->dir_len);
	brz_path_unix2dos(p, file->dir_len);

	return dst;
}

static void brz_free(brz_t *brz)
{
	brz_free_header(brz->header);
	free(brz);
}

static void brz_free_header(brz_header_t *hdr)
{
	brz_uint_t i;

	for (i = 0; i < hdr->nfiles; i++)
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
	size_t len = sizeof(hdr->magic) + sizeof(hdr->nfiles);
	brz_uint_t i = 0;

	do
		len += BRZ_FILE_HDR_LEN(&hdr->file[i]);
	while (i++ < hdr->nfiles);

	return len;
}

static int brz_header_lens2offs(brz_header_t *hdr)
{
	brz_off_t len, offset = brz_header_len(hdr);
	brz_uint_t i = 0;

	do {
		len = hdr->file[i].offset;
		hdr->file[i].offset = offset;
	} while (i++ < hdr->nfiles &&
		 !__builtin_add_overflow(len, offset, &offset));

	return -(i <= hdr->nfiles);
}

static ssize_t brz_header_filter(brz_header_t *hdr, brz_filter_t *filter)
{
	if (!filter)
		return hdr->nfiles;

	if (filter->flt_init &&
	    filter->flt_init(hdr->nfiles, filter->flt_arg))
		return -1;

	if (filter->flt_fn) {
		brz_uint_t i = hdr->nfiles;
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
					(hdr->nfiles - j + 1)
					 * sizeof(brz_file_t));
				hdr->nfiles -= j - i;
				j = 0;
			}
		} while (i-- > 0);
	}

	if (filter->flt_fini)
		filter->flt_fini(filter->flt_arg);

	return hdr->nfiles;
}

static ssize_t brz_header_walk(brz_t *brz,
			       brz_filter_t *filter,
			       int (*fn)(brz_t *, brz_uint_t, void *),
			       void *fn_arg)
{
	brz_uint_t i, n;

	if (filter && filter->flt_init &&
	    filter->flt_init(brz->header->nfiles, filter->flt_arg))
		return -1;

	if (filter && filter->flt_fn) {
		i = brz->header->nfiles;
		while (i > 0) {
			i--;
			filter->flt_fn(brz->header->file[i].name, i,
				       filter->flt_arg);
		}
	}

	for (i = n = 0; i < brz->header->nfiles; i++)
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
