/* brz.h -- manipulate CMx2 BRZ resource files

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

#ifndef _BRZ_H_
#define _BRZ_H_

#include <stdint.h>

#define BRZ_FILTER_REPLACE      -1
#define BRZ_FILTER_NOMATCH      0
#define BRZ_FILTER_MATCH        1

typedef int (filterfn_t)(const char *filename, size_t *i, void *args);
typedef int (filter_init_t)(size_t n, void *args);
typedef void (filter_fini_t)(void *args);

int brz_explode(char *const *pathv,
		const char *explode_dir,
		filterfn_t *filterfn,
		filter_init_t *filter_init,
		filter_fini_t *filter_fini,
		void *filter_args);

int brz_pack(char *const *pathv,
	     const char *pack_file,
	     filterfn_t *filterfn,
	     filter_init_t *filter_init,
	     filter_fini_t *filter_fini,
	     void *filter_args);

int brz_list(char *const *pathv);

#endif /* _BRZ_H_ */
