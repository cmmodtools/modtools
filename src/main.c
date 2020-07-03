/* main.c -- rezexplode and rezpack CMx2 BRZ resource files

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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include "brz_filter.h"
#include "brz_utils.h"
#include "brz.h"

#define REZ_STDIO_FILE	"-"
#define REZ_WORKING_DIR "--in progress--"
#define REZ_DEFAULT_SRC_DIR "input/"
#define REZ_DEFAULT_DST_DIR "exploded"
#define REZ_DEFAULT_DST_FILE "packed.brz"

#define REZ_COMMANDS "xpl"

#define IS_STDIO(s) (strcmp((s), REZ_STDIO_FILE) == 0)

#define VERSION "1.3.1 Copyright (C) 2013-2020 by Michal Roszkowski"

static const char *progname;
static char *cwd, *working;

static void version(void);
static void usage(void);
static void cleanup(int signo);
static int rez_dirlen(const char *path);
static char *rez_strlcat(const char *s1, const char *s2, size_t n);

struct commands {
	const char *const name;
	int (*const fn)(char *const *, int, brz_filter_t *, char const *);
	const char *const dfl_out;
};

static const struct commands do_it[] = {
	{"rezexplode", brz_extract, REZ_DEFAULT_DST_DIR},
	{"rezpack", brz_pack, REZ_DEFAULT_DST_FILE},
	{"rezlist", (void *)brz_list, NULL},
	{NULL, NULL, NULL}
};

enum command { REZ_EXPLODE, REZ_PACK, REZ_LIST, REZ_NONE, REZ_INVALID };

int main(int argc, char **argv)
{
	int ch, rval, flags = 0;
	enum command cmd;
	char **inputv, *output;
	struct sigaction cleanup_sa;
	brz_filter_args_t args;
	brz_filter_t filter = {
			.flt_fn   = brz_filter,
			.flt_init = brz_filter_init,
			.flt_fini = brz_filter_fini,
			.flt_arg  = &args
	};

	progname = brz_basename(argv[0]);

	cmd = REZ_NONE;
	output = NULL;
	memset(&args, 0, sizeof(args));

	while ((ch = getopt(argc, argv, REZ_COMMANDS "di:e:ho:vV")) != -1) {
		switch(ch) {
		case 'd':
			args.flags |= BRZ_FILTER_FLAG_KEEPDUPS;
			break;
		case 'i':
			args.incl = optarg;
			break;
		case 'e':
			args.excl = optarg;
			break;
		case 'h':
			usage();
			return 0;
		case 'o':
			output = optarg;
			break;
		case 'v':
			flags |= BRZ_FLAG_VERBOSE;
			break;
		case 'V':
			version();
			return 0;
		case 'l':
			cmd = (cmd != REZ_NONE)? REZ_INVALID : REZ_LIST;
			break;
		case 'p':
			cmd = (cmd != REZ_NONE)? REZ_INVALID : REZ_PACK;
			break;
		case 'x':
			cmd = (cmd != REZ_NONE)? REZ_INVALID : REZ_EXPLODE;
			break;
		default:
			usage();
			return -1;
		}
	}

	if (cmd == REZ_INVALID) {
		fprintf(stderr,
			"%s: You cannot specify more than one of the '-%s'"
			" options\n", progname, REZ_COMMANDS);
		usage();
		return -1;
	}

	if (cmd == REZ_NONE) {
		for (cmd = 0; do_it[cmd].name != NULL; cmd++)
			if (strcmp(progname, do_it[cmd].name) == 0) {
				goto cmd_ok;
			}
		fprintf(stderr, "%s: "
			"You must specify one of the '-%s' options\n",
			progname, REZ_COMMANDS);
		usage();
		return -1;
	}
cmd_ok:

	if (!output) {
		if (optind < argc) {
			if (do_it[cmd].dfl_out)
				output = strdup(do_it[cmd].dfl_out);
			inputv = (IS_STDIO(argv[optind]))? NULL : &argv[optind];
		} else {
			if (do_it[cmd].dfl_out)
				output = rez_strlcat(argv[0],
						     do_it[cmd].dfl_out,
						     rez_dirlen(argv[0]));
			inputv = calloc(sizeof(char *), 2);
			inputv[0] = rez_strlcat(argv[0], REZ_DEFAULT_SRC_DIR,
						rez_dirlen(argv[0]));
		}
	} else {
		/* if output path contains a trailing '/' append default name */
		if (strlen(output) > 0 && output[strlen(output) - 1] == '/')
			output = strcat(realloc(strdup(output),
						strlen(output) +
						strlen(do_it[cmd].dfl_out) + 1),
					do_it[cmd].dfl_out);
		else
			output = working = IS_STDIO(output)? NULL :
							     strdup(output);

		if (optind < argc) {
			inputv = (IS_STDIO(argv[optind]))? NULL : &argv[optind];
		} else {
			inputv = calloc(sizeof(char *), 2);
			inputv[0] = strdup(REZ_DEFAULT_SRC_DIR);
		}
	}

	if (cmd == REZ_EXPLODE && !output) {
		fprintf(stderr,
			"%s: Cannot extract to standard output\n", progname);
		return -1;
	}

	if (cmd == REZ_PACK && !inputv) {
		fprintf(stderr,
			"%s: Cannot pack from standard input\n", progname);
		return -1;
	}

	if (cmd == REZ_LIST) {
		args.flags |= BRZ_FILTER_FLAG_KEEPDUPS;
		if (output) {
			fprintf(stderr,
				"%s: Cannot specify -o parameter\n", progname);
			return -1;
		}
	}

	if (output != working) {
		if ((working = rez_strlcat(output,
					   REZ_WORKING_DIR,
					   rez_dirlen(output))) == NULL) {
			perror("rez_strlcat");
			return -1;
		}
		if ((cwd = getcwd(NULL, 0)) == NULL) {
			perror("getcwd");
			return -1;
		}
		if (brz_remove_r(working) == -1 && errno != ENOENT) {
			perror("brz_remove_r");
			return -1;
		}

		cleanup_sa.sa_handler = cleanup;
		sigemptyset(&cleanup_sa.sa_mask);
		sigaddset(&cleanup_sa.sa_mask, SIGHUP);
		sigaddset(&cleanup_sa.sa_mask, SIGINT);
		sigaddset(&cleanup_sa.sa_mask, SIGTERM);
		cleanup_sa.sa_flags = 0;

		sigaction(SIGHUP, &cleanup_sa, NULL);
		sigaction(SIGINT, &cleanup_sa, NULL);
		sigaction(SIGTERM, &cleanup_sa, NULL);
	}

	argc -= optind;
	argv += optind;

	rval = do_it[cmd].fn(inputv, flags, &filter, working);

	if (rval < 0) {
		perror(NULL);
	}

	if (output != working) {
		while (rename(working, output) == -1 &&
		       (errno == ENOTEMPTY || errno == ENOTDIR))
			if (brz_remove_r(output) == -1)
				break;
		free(working);
	}

	if (!argc) {
		free(inputv[0]);
		free(inputv);
	}

	free(output);
	free(cwd);

	return rval;
}

static void version(void)
{
	printf("%s %s\n", progname, VERSION);
}

static void usage(void)
{
	fprintf(stderr, "Usage: %s [options] [file] ...\n", progname);
	fputs(
		"\t-x\t\textract file(s)\n"
		"\t-p\t\tpack file(s)\n"
		"\t-l\t\tlist contents of file(s)\n"
		"\t-d\t\tinclude duplicate filenames\n"
		"\t-i <pattern>\tfilename include pattern\n"
		"\t-e <pattern>\tfilename exclude pattern\n"
		"\t-h\t\tshow usage\n"
		"\t-o <file>\toutput file or directory\n"
		"\t-v\t\tverbose output\n"
		"\t-V\t\tshow version\n"
		, stderr);
}

static void cleanup(int signo)
{
	if (working != NULL && (cwd == NULL || chdir(cwd) == 0))
		brz_remove_r(working);

	exit(0);
}

static int rez_dirlen(const char *path)
{
	return brz_basename(path) - path;
}

static char *rez_strlcat(const char *s1, const char *s2, size_t n)
{
	char *s;

	if ((s = malloc(n + strlen(s2) + 1)) == NULL)
		return NULL;

	strncpy(s, s1, n);
	s[n] = '\0';
	return strcat(s, s2);
}
