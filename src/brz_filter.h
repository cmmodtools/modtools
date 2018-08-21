/* brz_filter.h -- filter CMx2 BRZ resource files

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

#ifndef _BRZ_FILTER_H_
#define _BRZ_FILTER_H_

#include <stddef.h>
#include "brz.h"

#define BRZ_FILTER_FLAG_KEEPDUPS	1

typedef struct {
	const char *incl;	/* include pattern */
	const char *excl;	/* exclude pattern */
	unsigned int flags;
} brz_filter_args_t;

int brz_filter(const char *filename, size_t *i, void *arg);
int brz_filter_init(size_t n, void *arg);
void brz_filter_fini(void *arg);

#endif /* _BRZ_FILTER_H_ */

