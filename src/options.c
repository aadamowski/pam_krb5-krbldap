/*
 * Copyright 2003,2004 Red Hat, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of the
 * GNU Lesser General Public License, in which case the provisions of the
 * LGPL are required INSTEAD OF the above restrictions.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN
 * NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "../config.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif

#include <krb5.h>
#ifdef USE_KRB4
#include KRB4_DES_H
#include KRB4_KRB_H
#ifdef KRB4_KRB_ERR_H
#include KRB4_KRB_ERR_H
#endif
#endif

#include "items.h"
#include "log.h"
#include "options.h"
#include "userinfo.h"
#include "v5.h"
#include "xstr.h"

#ident "$Id$"

static int
option_b(pam_handle_t *pamh, int argc, PAM_KRB5_MAYBE_CONST char **argv,
	 krb5_context ctx, const char *realm, const char *s)
{
	int i;

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], s) == 0) {
			return 1;
		}
		if ((strncmp(argv[i], "no", 2) == 0) &&
		    (strcmp(argv[i] + 2, s) == 0)) {
			return 0;
		}
		if ((strncmp(argv[i], "not", 3) == 0) &&
		    (strcmp(argv[i] + 3, s) == 0)) {
			return 0;
		}
		if ((strncmp(argv[i], "no_", 3) == 0) &&
		    (strcmp(argv[i] + 3, s) == 0)) {
			return 0;
		}
		if ((strncmp(argv[i], "not_", 4) == 0) &&
		    (strcmp(argv[i] + 4, s) == 0)) {
			return 0;
		}
	}

	v5_appdefault_boolean(ctx, realm, s, -1, &i);

	return i;
}
static char *
option_s(pam_handle_t *pamh, int argc, PAM_KRB5_MAYBE_CONST char **argv,
	 krb5_context ctx, const char *realm, const char *s,
	 const char *default_value)
{
	int i;
	char *o;

	for (i = 0; i < argc; i++) {
		if ((strncmp(argv[i], s, strlen(s)) == 0) &&
		    (argv[i][strlen(s)] == '=')) {
		    	return xstrdup(argv[i] + strlen(s) + 1);
		}
	}

	v5_appdefault_string(ctx, realm, s, default_value, &o);

	return o;
}
static void
free_s(char *s)
{
	xstrfree(s);
}
static int
option_i(pam_handle_t *pamh, int argc, PAM_KRB5_MAYBE_CONST char **argv,
	 krb5_context ctx, const char *realm, const char *s)
{
	char *tmp, *p;
	long i;

	tmp = option_s(pamh, argc, argv, ctx, realm, s, "");

	i = strtol(tmp, &p, 10);
	if ((p == NULL) || (p == tmp) || (*p != '\0')) {
		i = -1;
	}
	free_s(tmp);

	return i;
}
static char **
option_l(pam_handle_t *pamh, int argc, PAM_KRB5_MAYBE_CONST char **argv,
	 krb5_context ctx, const char *realm, const char *s)
{
	int i;
	char *o, *p, *q, **list;

	o = option_s(pamh, argc, argv, ctx, realm, s, "");
	list = malloc((strlen(o) + 1) * sizeof(char*));
	if (list == NULL) {
		return NULL;
	}
	memset(list, 0, (strlen(o) + 1) * sizeof(char*));

	i = 0;
	p = q = o;
	do {
		while ((*p != '\0') && isspace(*p)) {
			p++;
		}
		q = p;
		while ((*q != '\0') && !isspace(*q)) {
			q++;
		}
		if (p != q) {
			list[i++] = xstrndup(p, q - p);
		}
		p = q;
	} while (*p != '\0');

	free_s(o);

	return list;
}
static void
free_l(char **l)
{
	int i;
	if (l != NULL) {
		for (i = 0; l[i] != NULL; i++) {
			free_s(l[i]);
			l[i] = NULL;
		}
		free(l);
	}
}

struct _pam_krb5_options *
_pam_krb5_options_init(pam_handle_t *pamh, int argc,
		       PAM_KRB5_MAYBE_CONST char **argv,
		       krb5_context ctx)
{
	struct _pam_krb5_options *options;
	int try_first_pass, use_first_pass, i;
	char *default_realm, **list;
	char *service;
	struct stat stroot, stafs;

	options = malloc(sizeof(struct _pam_krb5_options));
	if (options == NULL) {
		return NULL;
	}
	memset(options, 0, sizeof(struct _pam_krb5_options));

	service = NULL;
	_pam_krb5_get_item_text(pamh, PAM_SERVICE, &service);

	for (i = 0; i < argc; i++) {
		if (strncmp(argv[i], "realm=", 6) == 0) {
			if (options->realm != NULL) {
				xstrfree(options->realm);
			}
			options->realm = xstrdup(argv[i] + 6);
		}
	}
	if (krb5_get_default_realm(ctx, &default_realm) == 0) {
		if (options->debug) {
			debug("default/local realm '%s'", default_realm);
		}
		if (options->realm == NULL) {
			options->realm = xstrdup(default_realm);
		}
		v5_free_default_realm(ctx, default_realm);
	}
	if (options->realm == NULL) {
		options->realm = xstrdup(DEFAULT_REALM);
	}
	if (strlen(options->realm) > 0) {
		krb5_set_default_realm(ctx, options->realm);
		if (options->debug) {
			debug("configured realm '%s'", options->realm);
		}
	}

	/* parsing debugging */
	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "debug_parser") == 0) {
			char *s, **l;
			i = option_b(pamh, argc, argv, ctx, options->realm,
				     "boolean_parameter_1");
			debug("boolean_parameter_1 = %d", i);
			i = option_b(pamh, argc, argv, ctx, options->realm,
				     "boolean_parameter_2");
			debug("boolean_parameter_2 = %d", i);
			i = option_b(pamh, argc, argv, ctx, options->realm,
				     "boolean_parameter_3");
			debug("boolean_parameter_3 = %d", i);
			s = option_s(pamh, argc, argv,
				     ctx, options->realm, "string_parameter_1",
				     "default_string_value");
			debug("string_parameter_1 = '%s'", s ? s : "(null)");
			free_s(s);
			s = option_s(pamh, argc, argv,
				     ctx, options->realm, "string_parameter_2",
				     "default_string_value");
			debug("string_parameter_2 = '%s'", s ? s : "(null)");
			free_s(s);
			s = option_s(pamh, argc, argv,
				     ctx, options->realm, "string_parameter_3",
				     "default_string_value");
			debug("string_parameter_3 = '%s'", s ? s : "(null)");
			free_s(s);
			l = option_l(pamh, argc, argv,
				     ctx, options->realm, "list_parameter_1");
			for (i = 0; (l != NULL) && (l[i] != NULL); i++) {
				debug("list_parameter_1[%d] = '%s'", i, l[i]);
			}
			free_l(l);
			break;
		}
	}
	
	/* private option */
	options->debug = option_b(pamh, argc, argv,
				  ctx, options->realm, "debug");
	if (options->debug) {
		debug("configured realm '%s'", options->realm);
	}

	/* library options */
	options->addressless = option_b(pamh, argc, argv,
					ctx, options->realm, "addressless");
	options->forwardable = option_b(pamh, argc, argv,
					ctx, options->realm, "forwardable");
	options->proxiable = option_b(pamh, argc, argv,
				      ctx, options->realm, "proxiable");
	options->renewable = option_b(pamh, argc, argv,
				      ctx, options->realm, "renewable");
	if (options->debug) {
		debug("flags:%s%s%s%s%s%s%s%s",
		      options->addressless == 1 ? " addressless" : "",
		      options->addressless == 0 ? " not addressless" : "",
		      options->forwardable == 1 ? " forwardable" : "",
		      options->forwardable == 0 ? " not forwardable" : "",
		      options->proxiable == 1 ? " proxiable" : "",
		      options->proxiable == 0 ? " not proxiable" : "",
		      options->renewable == 1 ? " renewable" : "",
		      options->renewable == 0 ? " not renewable" : "");
	}

	/* private option */
	options->ignore_afs = option_b(pamh, argc, argv,
				       ctx, options->realm, "ignore_afs");
	if (options->ignore_afs == -1) {
		options->ignore_afs = 0;
	}
	if (options->debug && (options->ignore_afs == 1)) {
		debug("flag: ignore_afs");
	}
	if (options->debug && (options->ignore_afs == 0)) {
		debug("flag: no ignore_afs");
	}

	/* private option */
	options->tokens = option_b(pamh, argc, argv,
				   ctx, options->realm, "tokens");
	if (options->tokens == -1) {
		options->tokens = 0;
	}
	if (options->debug && options->tokens) {
		debug("flag: tokens");
	}

	/* private option */
	options->user_check = option_b(pamh, argc, argv,
				       ctx, options->realm, "user_check");
	if (options->user_check == -1) {
		options->user_check = 1;
	}
	if (options->debug && options->user_check) {
		debug("flag: user_check");
	}

	/* private option */
	options->use_authtok = option_b(pamh, argc, argv,
					ctx, options->realm, "use_authtok");
	if (options->use_authtok == -1) {
		options->use_authtok = 0;
	}
	if (options->debug && options->use_authtok) {
		debug("flag: use_authtok");
	}

	/* private option */
	options->v4 = option_b(pamh, argc, argv,
			       ctx, options->realm, "krb4_convert");
	if (options->v4 == -1) {
		/* default is to have this behavior disabled... */
		options->v4 = 0;
	}
	if (options->debug && (options->v4 == 1)) {
		debug("flag: krb4_convert");
	}
	if (options->debug && (options->v4 == 0)) {
		debug("flag: no krb4_convert");
	}

	/* private option */
	options->use_first_pass = 1;
	options->use_second_pass = 1;
	use_first_pass = option_b(pamh, argc, argv,
				  ctx, options->realm, "use_first_pass");
	if (use_first_pass == 1) {
		options->use_first_pass = 1;
		options->use_second_pass = 0;
	}
	try_first_pass = option_b(pamh, argc, argv,
				  ctx, options->realm, "try_first_pass");
	if (try_first_pass == 1) {
		options->use_first_pass = 1;
		options->use_second_pass = 1;
	}

	/* private option */
	options->use_shmem = option_b(pamh, argc, argv,
				      ctx, options->realm, "use_shmem");
	if (options->use_shmem != 1) {
		options->use_shmem = 0;
		if (service != NULL) {
			list = option_l(pamh, argc, argv, ctx, options->realm,
					"use_shmem");
			for (i = 0; (list != NULL) && (list[i] != NULL); i++) {
				if (strcmp(list[i], service) == 0) {
					options->use_shmem = 1;
					break;
				}
			}
			free_l(list);
		}
	}
	if (options->debug && (options->use_shmem == 1)) {
		debug("flag: use_shmem");
	}
	if (options->debug && (options->use_shmem == 0)) {
		debug("flag: no use_shmem");
	}

	/* private option */
	options->validate = option_b(pamh, argc, argv,
				     ctx, options->realm, "validate");
	if (options->debug && (options->validate == 1)) {
		debug("flag: validate");
	}

	options->warn = option_b(pamh, argc, argv,
				 ctx, options->realm, "warn");
	if (options->warn == -1) {
		options->warn = 1;
	}
	if (options->debug && (options->warn == 1)) {
		debug("flag: warn");
	}

	/* private option */
	options->ticket_lifetime = option_i(pamh, argc, argv,
					    ctx, options->realm,
					    "ticket_lifetime");
	if (options->ticket_lifetime < 0) {
		options->ticket_lifetime = 0;
	}
	if (options->debug) {
		debug("ticket lifetime: %d", options->ticket_lifetime);
	}

	/* library option */
	options->renew_lifetime = option_i(pamh, argc, argv,
					   ctx, options->realm,
					   "renew_lifetime");
	if (options->renew_lifetime < 0) {
		options->renew_lifetime = 0;
	}
	if (options->renew_lifetime > 0) {
		options->renewable = 1;
	}
	if (options->debug) {
		debug("renewable lifetime: %d", options->renew_lifetime);
	}

	/* private option */
	options->minimum_uid = option_i(pamh, argc, argv,
					ctx, options->realm, "minimum_uid");
	if (options->debug && (options->minimum_uid != -1)) {
		debug("minimum uid: %d", options->minimum_uid);
	}

	/* private options */
	options->banner = option_s(pamh, argc, argv,
				   ctx, options->realm, "banner",
				   "Kerberos 5");
	if (options->debug && options->banner) {
		debug("banner: %s", options->banner);
	}
	options->ccache_dir = option_s(pamh, argc, argv,
				       ctx, options->realm, "ccache_dir",
				       DEFAULT_CCACHE_DIR);
	if (strlen(options->ccache_dir) == 0) {
		xstrfree(options->ccache_dir);
		options->ccache_dir = xstrdup(DEFAULT_CCACHE_DIR);
	}
	if (options->debug && options->ccache_dir) {
		debug("ccache dir: %s", options->ccache_dir);
	}

	options->keytab = option_s(pamh, argc, argv,
				   ctx, options->realm, "keytab",
				   "/etc/krb5.keytab");
	if (strlen(options->keytab) == 0) {
		xstrfree(options->keytab);
		options->keytab = xstrdup("/etc/krb5.keytab");
	}
	if (options->debug && options->keytab) {
		debug("keytab: %s", options->keytab);
	}

	options->hosts = option_l(pamh, argc, argv,
				  ctx, options->realm, "hosts");
	if (options->hosts) {
		int i;
		for (i = 0; options->hosts[i] != NULL; i++) {
			if (options->debug) {
				debug("host: %s", options->hosts[i]);
			}
			options->addressless = 0;
		}
	}

	/* If /afs is on a different device from /, this suggests that AFS is
	 * running.  Set up to get tokens for the local cell and attempt to
	 * get that cell's name if we're not ignoring AFS altogether. */
	if (!options->ignore_afs) {
		if (stat("/", &stroot) == 0) {
			if (stat("/afs", &stafs) == 0) {
				if (stroot.st_dev != stafs.st_dev) {
					options->v4_for_afs = 1;
				}
			}
		}
		options->afs_cells = option_l(pamh, argc, argv,
					      ctx, options->realm, "afs_cells");
		if ((options->afs_cells != NULL) &&
		    (options->afs_cells[0] != NULL)) {
			options->v4_for_afs = 1;
		}
		if (options->debug && options->afs_cells) {
			int i;
			for (i = 0; options->afs_cells[i] != NULL; i++) {
				debug("afs cell: %s", options->afs_cells[i]);
			}
		}
	}

	list = option_l(pamh, argc, argv, ctx, options->realm, "mappings");
	for (i = 0; (list != NULL) && (list[i] != NULL); i++) {
		/* nothing */
	}
	if ((i == 0) || ((i % 2) != 0)) {
		options->n_mappings = 0;
		options->mappings = NULL;
	} else {
		options->n_mappings = i / 2;
		options->mappings = malloc(sizeof(struct name_mapping) *
					   options->n_mappings);
		if (options->mappings == NULL) {
			options->n_mappings = 0;
		}
		for (i = 0; i < options->n_mappings; i++) {
			options->mappings[i].pattern = strdup(list[i * 2]);
			options->mappings[i].replacement =
				strdup(list[i * 2 + 1]);
			if (options->debug) {
				debug("mapping: \"%s\" to \"%s\"",
				      options->mappings[i].pattern,
				      options->mappings[i].replacement);
			}
		}
	}
	free_l(list);

	return options;
}
void
_pam_krb5_options_free(pam_handle_t *pamh, krb5_context ctx,
		       struct _pam_krb5_options *options)
{
	free_s(options->banner);
	options->banner = NULL;
	free_s(options->ccache_dir);
	options->ccache_dir = NULL;
	free_s(options->keytab);
	options->keytab = NULL;
	free_s(options->realm);
	options->realm = NULL;
	free_l(options->hosts);
	options->hosts = NULL;
	free_l(options->afs_cells);
	options->afs_cells = NULL;
	free(options);
};
