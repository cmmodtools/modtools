/* brz.h -- manipulate CMx2 BRZ resource files

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

#ifndef _BRZ_H_
#define _BRZ_H_

#include <stdint.h>

#define BRZ_FLAG_VERBOSE	1

#define BRZ_FLT_NOMATCH		0
#define BRZ_FLT_MATCH		1

typedef int (flt_fn_t)(const char *filename, size_t i, void *args);
typedef int (flt_init_t)(size_t n, void *args);
typedef void (flt_fini_t)(void *args);

typedef struct {
	flt_fn_t	*flt_fn;
	flt_init_t	*flt_init;	/* constructor */
	flt_fini_t	*flt_fini;	/* destructor */
	void 		*flt_arg;
} brz_filter_t;

int brz_extract(char *const *pathv,
		int flags,
		brz_filter_t *filter,
		const char *out_dir);

int brz_pack(char *const *pathv,
	     int flags,
	     brz_filter_t *filter,
	     const char *out_file);

int brz_list(char *const *pathv,
	     int flags,
	     brz_filter_t *filter);

#endif /* _BRZ_H_ */
