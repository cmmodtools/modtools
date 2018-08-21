/* brz_filter.c -- filter CMx2 BRZ resource files

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

#include <stdint.h>
#include <string.h>
#include <search.h>
#include <fnmatch.h>
#include "brz_filter.h"

#define FNM_FLAGS	(FNM_CASEFOLD)

int brz_filter(const char *filename, size_t *i, void *arg)
{
	brz_filter_args_t *args = arg;
	ENTRY e, *ep;
	size_t prev;

	if ((args->excl && !fnmatch(args->excl, filename, FNM_FLAGS)) ||
	    (args->incl && fnmatch(args->incl, filename, FNM_FLAGS)))
		return BRZ_FILTER_MATCH;

	if (!(args->flags & BRZ_FILTER_FLAG_KEEPDUPS)) {
		e.key = (char *)filename;
		if ((ep = hsearch(e, FIND))) {
			prev = (typeof(*i))(uintptr_t)ep->data;
			ep->data = (void *)(uintptr_t)*i;
			*i = prev;
			return BRZ_FILTER_REPLACE;
		} else {
			e.key = strdup(filename);
			e.data = (void *)(uintptr_t)*i;
			hsearch(e, ENTER);
		}
	}

	return BRZ_FILTER_NOMATCH;
}


int brz_filter_init(size_t n, void *arg)
{
	brz_filter_args_t *args = arg;

	if (!(args->flags & BRZ_FILTER_FLAG_KEEPDUPS))
		return !hcreate(n);

	return 0;
}

void brz_filter_fini(void *arg)
{
	brz_filter_args_t *args = arg;

	if (!(args->flags & BRZ_FILTER_FLAG_KEEPDUPS))
		hdestroy();
}

