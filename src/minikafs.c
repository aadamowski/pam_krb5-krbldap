/*
 * Copyright 2004,2005 Red Hat, Inc.
 * Copyright 2004 Kungliga Tekniska Högskolan
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

 /*
  * A miniature afslog implementation.  Requires a running krb524 server or a
  * v4-capable KDC, or cells served by OpenAFS 1.2.8 or later in combination
  * with MIT Kerberos 1.2.6 or later.
  */

#include "../config.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

#include "log.h"
#include "minikafs.h"
#include "v5.h"
#include "xstr.h"

#ident "$Id$"

#ifndef KRB_TICKET_GRANTING_TICKET
#define KRB_TICKET_GRANTING_TICKET "krbtgt"
#endif

#define OPENAFS_AFS_IOCTL_FILE  "/proc/fs/openafs/afs_ioctl"
#define ARLA_AFS_IOCTL_FILE     "/proc/fs/nnpfs/afs_ioctl"
#define VIOC_SYSCALL            _IOW('C', 1, void *)

/* A structure specifying parameters to the VIOC_SYSCALL ioctl.  An array would
 * do as well, but this makes the order of items clearer. */
struct minikafs_procdata {
	long param4;
	long param3;
	long param2;
	long param1;
	long function;
};

/* Global(!) containing the path to the file/device/whatever in /proc which we
 * can use to get the effect of the AFS syscall.  If we ever need to be
 * thread-safe, we'll have to lock around accesses to this. */
static const char *minikafs_procpath = NULL;

/* A structure specifying input/output buffers to minikafs_syscall() or
 * minikafs_pioctl(). */
struct minikafs_ioblock {
	char *in, *out;
	u_int16_t insize, outsize;
};

/* The portion of a token which includes our own key and other bookkeeping
 * stuff.  Along with a magic blob used by rxkad, the guts of tokens. */
struct minikafs_plain_token {
	u_int32_t kvno;
	char key[8];
	u_int32_t uid;
	u_int32_t start, end; /* must be odd (?) */
};

/* Functions called through minikafs_syscall().  Might not port to your system. */
enum minikafs_subsys {
	minikafs_subsys_pioctl = 20,
	minikafs_subsys_setpag = 21,
};

/* Subfunctions called through minikafs_pioctl().  Might not port to your system. */
#define PIOCTL_FN(id) ((unsigned int) _IOW('V', (id), struct minikafs_ioblock))
enum minikafs_pioctl_fn {
	minikafs_pioctl_bogus = PIOCTL_FN(0),
	minikafs_pioctl_settoken = PIOCTL_FN(3),
	minikafs_pioctl_flush = PIOCTL_FN(6),
	minikafs_pioctl_gettoken = PIOCTL_FN(8),
	minikafs_pioctl_unlog = PIOCTL_FN(9),
	minikafs_pioctl_whereis = PIOCTL_FN(14),
	minikafs_pioctl_getcelloffile = PIOCTL_FN(30),
};

/* Call AFS using an ioctl. Might not port to your system. */
static int
minikafs_ioctlcall(long function, long arg1, long arg2, long arg3, long arg4)
{
	int fd, ret, saved_errno;
	struct minikafs_procdata data;
	fd = open(minikafs_procpath, O_RDWR);
	if (fd == -1) {
		errno = EINVAL;
		return -1;
	}
	data.function = function;
	data.param1 = arg1;
	data.param2 = arg2;
	data.param3 = arg3;
	data.param4 = arg4;
	ret = ioctl(fd, VIOC_SYSCALL, &data);
	saved_errno = errno;
	close(fd);
	errno = saved_errno;
	return ret;
}

/* Call the AFS syscall. Might not port to your system. */
static int
minikafs_syscall(long function, long arg1, long arg2, long arg3, long arg4)
{
	return syscall(__NR_afs_syscall, function, arg1, arg2, arg3, arg4);
}

/* Call into AFS, somehow. */
static int
minikafs_call(long function, long arg1, long arg2, long arg3, long arg4)
{
	if (minikafs_procpath != NULL) {
		return minikafs_ioctlcall(function, arg1, arg2, arg3, arg4);
	}
	return minikafs_syscall(function, arg1, arg2, arg3, arg4);
}

/* Make an AFS pioctl. Might not port to your system. */
static int
minikafs_pioctl(char *file, enum minikafs_pioctl_fn subfunction,
		struct minikafs_ioblock *iob)
{
	return minikafs_call(minikafs_subsys_pioctl, (long) file,
			     subfunction, (long) iob, 0);
}

/* Determine in which cell a given file resides.  Returns 0 on success. */
int
minikafs_cell_of_file(const char *file, char *cell, size_t length)
{
	struct minikafs_ioblock iob;
	char *wfile;
	int i;

	wfile = xstrdup(file ? file : "/afs");

	memset(&iob, 0, sizeof(iob));
	iob.in = wfile;
	iob.insize = strlen(wfile) + 1;
	iob.out = cell;
	iob.outsize = length;

	i = minikafs_pioctl(wfile, minikafs_pioctl_getcelloffile, &iob);

	xstrfree(wfile);
	return i;
}

/* Determine if AFS is running. Unlike most other functions, return 0 on
 * FAILURE. */
int
minikafs_has_afs(void)
{
	char cell[PATH_MAX];
	int fd, i, ret;
	struct sigaction news, olds;

	fd = open(OPENAFS_AFS_IOCTL_FILE, O_RDWR);
	if (fd != -1) {
		minikafs_procpath = OPENAFS_AFS_IOCTL_FILE;
		close(fd);
		return 1;
	}
	if (fd == -1) {
		fd = open(ARLA_AFS_IOCTL_FILE, O_RDWR);
		if (fd != -1) {
			minikafs_procpath = ARLA_AFS_IOCTL_FILE;
			close(fd);
			return 1;
		}
	}

	memset(&news, 0, sizeof(news));
	news.sa_handler = SIG_IGN;
	i = sigaction(SIGSYS, &news, &olds);
	if (i != 0) {
		return 0;
	}

	ret = 0;
	i = minikafs_cell_of_file(NULL, cell, sizeof(cell));
	if ((i == 0) || ((i == -1) && (errno != ENOSYS))) {
		ret = 1;
	}

	sigaction(SIGSYS, &olds, NULL);

	return ret;
}

/* Determine in which realm a cell exists.  We do this by obtaining the address
 * of the fileserver which holds /afs/cellname (assuming that the root.cell
 * volume from the cell is mounted there), converting the address to a host
 * name, and then asking libkrb5 to tell us to which realm the host belongs. */
static int
minikafs_realm_of_cell_with_ctx(krb5_context ctx,
				struct _pam_krb5_options *options,
				const char *cell,
				char *realm, size_t length)
{
	struct minikafs_ioblock iob;
	struct sockaddr_in sin;
	in_addr_t *address;
	krb5_context use_ctx;
	char *path, host[NI_MAXHOST], **realms;
	int i, n_addresses, ret;

	if (cell) {
		path = malloc(strlen(cell) + 6);
	} else {
		path = malloc(5);
	}
	if (path == NULL) {
		return -1;
	}
	if (cell) {
		sprintf(path, "/afs/%s", cell);
	} else {
		sprintf(path, "/afs");
	}

	n_addresses = 2;
	do {
		/* allocate the output buffer for the address [list] */
		address = malloc(n_addresses * sizeof(address[0]));
		if (address == NULL) {
			ret = -1;
			break;
		}
		memset(&iob, 0, sizeof(iob));
		iob.in = path;
		iob.insize = strlen(path) + 1;
		iob.out = (char*) &address[0];
		iob.outsize = n_addresses * sizeof(address[0]);
		ret = minikafs_pioctl(path, minikafs_pioctl_whereis, &iob);
		/* if we failed, free the address [list], and if the error was
		 * E2BIG, increase the size we'll use next time, up to a
		 * hard-coded limit */
		if (ret != 0) {
			free(address);
			address = NULL;
			if (errno == E2BIG) {
				if (n_addresses > 256) {
					break;
				}
				n_addresses++;
			}
		}
	} while ((ret != 0) && (errno == E2BIG));

	if (ret != 0) {
		if (options->debug > 1) {
			debug("got error %d (%s) determining file server for "
			      "\"%s\"", errno, error_message(errno), path);
		}
		free(path);
		return ret;
	}
	free(path);

	sin.sin_family = AF_INET;
	if (options->debug > 1) {
		for (i = 0; i < n_addresses; i++) {
			debug("file server for \"/afs/%s\" is %u.%u.%u.%u",
			      cell,
			      (address[i] >>  0) & 0xff,
			      (address[i] >>  8) & 0xff,
			      (address[i] >> 16) & 0xff,
			      (address[i] >> 24) & 0xff);
		}
	}

	if (ctx == NULL) {
		if (krb5_init_context(&use_ctx) != 0) {
			free(address);
			return -1;
		}
	} else {
		use_ctx = ctx;
	}

	for (i = 0; i < n_addresses; i++) {
		memcpy(&sin.sin_addr, &address[i], sizeof(address[i]));
		if (getnameinfo((const struct sockaddr*) &sin, sizeof(sin),
				host, sizeof(host), NULL, 0,
				NI_NAMEREQD) == 0) {
			if (krb5_get_host_realm(use_ctx, host, &realms) == 0) {
				strncpy(realm, realms[0], length - 1);
				realm[length - 1] = '\0';
				krb5_free_host_realm(use_ctx, realms);
				if (options->debug > 1) {
					debug("%s is in realm %s", host, realm);
				}
				i = 0;
				break;
			}
		} else {
			if (options->debug > 1) {
				debug("error %d(%s) determining realm for %s",
				      i, error_message(i), host);
			}
		}
	}

	if (use_ctx != ctx) {
		krb5_free_context(use_ctx);
	}

	free(address);

	return i;
}

int
minikafs_realm_of_cell(struct _pam_krb5_options *options,
		       const char *cell, char *realm, size_t length)
{
	return minikafs_realm_of_cell_with_ctx(NULL, options, cell,
					       realm, length);
}

/* Create a new PAG. */
int
minikafs_setpag(void)
{
	return minikafs_call(minikafs_subsys_setpag, 0, 0, 0, 0);
}

#ifdef USE_KRB4
/* Stuff the ticket and key from a v4 credentials structure into the kernel. */
static int
minikafs_4settoken(const char *cell, uid_t uid, u_int32_t start, u_int32_t end,
		   CREDENTIALS *creds)
{
	char buffer[4 + creds->ticket_st.length +
		    4 + sizeof(struct minikafs_plain_token) +
		    4 + strlen(cell) + 1];
	struct minikafs_plain_token plain_token;
	struct minikafs_ioblock iob;
	u_int32_t size;

	/* their key, encrypted with our key */
	size = creds->ticket_st.length;
	memcpy(buffer, &size, 4);
	memcpy(buffer + 4, &creds->ticket_st.dat, size);

	/* our key, plus housekeeping */
	plain_token.kvno = creds->kvno;
	memcpy(&plain_token.key, creds->session, 8);
	plain_token.uid = uid;
	plain_token.start = start;
	plain_token.end = end;
	if (((end - start) % 1) == 0) {
		plain_token.end--;
	}

	size = sizeof(plain_token);
	memcpy(buffer + 4 + creds->ticket_st.length, &size, 4);
	memcpy(buffer + 4 + creds->ticket_st.length + 4, &plain_token, size);

	/* the name of the cell */
	size = 0;
	memcpy(buffer + 4 + creds->ticket_st.length + 4 +
	       sizeof(plain_token), &size, 4);
	strcpy(buffer + 4 + creds->ticket_st.length + 4 +
	       sizeof(plain_token) + 4, cell);

	/* the regular stuff */
	memset(&iob, 0, sizeof(iob));
	iob.in = buffer;
	iob.insize = 4 + creds->ticket_st.length +
		     4 + sizeof(struct minikafs_plain_token) +
		     4 + strlen(cell) + 1;
	iob.out = NULL;
	iob.outsize = 0;

	return minikafs_pioctl(NULL, minikafs_pioctl_settoken, &iob);
}
#endif

/* Stuff the ticket and key from a v5 credentials structure into the kernel.
 * While this may succeed and return 0, the cache manager may discard the token
 * without clearing it, so we can't depend on this working in any
 * programmatically verifiable way. Grrrr! */
static int
minikafs_5settoken(const char *cell, krb5_creds *creds, uid_t uid)
{
	char buffer[4 + creds->ticket.length +
		    4 + sizeof(struct minikafs_plain_token) +
		    4 + strlen(cell) + 1];
	struct minikafs_plain_token plain_token;
	struct minikafs_ioblock iob;
	u_int32_t size;

	if (v5_creds_key_length(creds) != 8) {
		return -1;
	}

	/* their key, encrypted with our key */
	size = creds->ticket.length;
	memcpy(buffer, &size, 4);
	memcpy(buffer + 4, creds->ticket.data, size);

	/* our key, plus housekeeping */
	plain_token.kvno = 0x100; /* magic number, signals OpenAFS 1.2.8 and
				     later that the ticket is a v5 ticket */
	memcpy(&plain_token.key, v5_creds_key_contents(creds),
	       v5_creds_key_length(creds));
	plain_token.uid = uid;
	plain_token.start = creds->times.starttime;
	plain_token.end = creds->times.endtime;
	if (((creds->times.endtime - creds->times.starttime) % 1) == 0) {
		plain_token.end--;
	}

	size = sizeof(plain_token);
	memcpy(buffer + 4 + creds->ticket.length, &size, 4);
	memcpy(buffer + 4 + creds->ticket.length + 4, &plain_token, size);

	/* the name of the cell */
	size = 0;
	memcpy(buffer + 4 + creds->ticket.length + 4 +
	       sizeof(plain_token), &size, 4);
	strcpy(buffer + 4 + creds->ticket.length + 4 +
	       sizeof(plain_token) + 4, cell);

	/* the regular stuff */
	memset(&iob, 0, sizeof(iob));
	iob.in = buffer;
	iob.insize = 4 + creds->ticket.length +
		     4 + sizeof(struct minikafs_plain_token) +
		     4 + strlen(cell) + 1;
	iob.out = NULL;
	iob.outsize = 0;

	return minikafs_pioctl(NULL, minikafs_pioctl_settoken, &iob);
}

/* Clear our tokens. */
int
minikafs_unlog(void)
{
	return minikafs_pioctl(NULL, minikafs_pioctl_unlog, NULL);
}

#ifdef USE_KRB4
/* Try to convert the v5 credentials to v4 credentials using the krb524 service
 * and then attempt to stuff the resulting v4 credentials into the kernel. */
static int
minikafs_5convert_and_log(krb5_context ctx, struct _pam_krb5_options *options,
			  const char *cell, krb5_creds *creds, uid_t uid)
{
	CREDENTIALS v4creds;
	int i, ret;
	memset(&v4creds, 0, sizeof(v4creds));
	i = -1;
#if defined(HAVE_KRB5_524_CONVERT_CREDS)
	i = krb5_524_convert_creds(ctx, creds, &v4creds);
#else
#if defined(HAVE_KRB524_CONVERT_CREDS_KDC)
	i = krb524_convert_creds_kdc(ctx, creds, &v4creds);
#endif
#endif
	if (i != 0) {
		if (options->debug) {
			debug("got error %d (%s) converting v5 creds to v4 for"
			      " \"%s\"", i, error_message(i), cell);
		}
		return i;
	}
	if (v4creds.kvno == (0x100 - 0x2b)) {
		/* Probably a v5 enc_part blob, per the rxkad 2b proposal.  Do
		 * nothing. */;
	}
	ret = minikafs_4settoken(cell, uid,
				 creds->times.starttime, creds->times.endtime,
				 &v4creds);
	return ret;
}
#else
static int
minikafs_5convert_and_log(krb5_context ctx, struct _pam_krb5_options *options,
			  const char *cell, krb5_creds *creds, uid_t uid)
{
	return -1;
}
#endif

/* Try to set a token for the given cell using creds for the named principal. */
static int
minikafs_5log_with_principal(krb5_context ctx,
			     struct _pam_krb5_options *options,
			     krb5_ccache ccache,
			     const char *cell, const char *principal,
			     uid_t uid, int try_v5_2b)
{
	krb5_principal server, client;
	krb5_creds mcreds, creds, *new_creds;
	int etypes[] = {
		ENCTYPE_DES_CBC_CRC,
		ENCTYPE_DES_CBC_MD4,
		ENCTYPE_DES_CBC_MD5,
	};
	unsigned int i;

	memset(&client, 0, sizeof(client));
	memset(&server, 0, sizeof(server));

	if (krb5_cc_get_principal(ctx, ccache, &client) != 0) {
		return -1;
	}
	if (krb5_parse_name(ctx, principal, &server) != 0) {
		krb5_free_principal(ctx, client);
		return -1;
	}

	/* Check if we already have a suitable credential. */
	for (i = 0; i < sizeof(etypes) / sizeof(etypes[0]); i++) {
		memset(&mcreds, 0, sizeof(mcreds));
		memset(&creds, 0, sizeof(creds));
		mcreds.client = client;
		mcreds.server = server;
		v5_creds_set_etype(ctx, &mcreds, etypes[i]);
		if (krb5_cc_retrieve_cred(ctx, ccache, v5_cc_retrieve_match(),
					  &mcreds, &creds) == 0) {
			if (try_v5_2b &&
			    (minikafs_5settoken(cell, &creds, uid) == 0)) {
				krb5_free_cred_contents(ctx, &creds);
				krb5_free_principal(ctx, client);
				krb5_free_principal(ctx, server);
				return 0;
			}
			if (minikafs_5convert_and_log(ctx, options, cell,
						      &creds, uid) == 0) {
				krb5_free_cred_contents(ctx, &creds);
				krb5_free_principal(ctx, client);
				krb5_free_principal(ctx, server);
				return 0;
			}
			krb5_free_cred_contents(ctx, &creds);
		}
	}

	/* Try to obtain a suitable credential. */
	for (i = 0; i < sizeof(etypes) / sizeof(etypes[0]); i++) {
		memset(&mcreds, 0, sizeof(mcreds));
		mcreds.client = client;
		mcreds.server = server;
		v5_creds_set_etype(ctx, &mcreds, etypes[i]);
		new_creds = NULL;
		if (krb5_get_credentials(ctx, 0, ccache,
					 &mcreds, &new_creds) == 0) {
			if (try_v5_2b &&
			    (minikafs_5settoken(cell, new_creds, uid) == 0)) {
				krb5_free_creds(ctx, new_creds);
				krb5_free_principal(ctx, client);
				krb5_free_principal(ctx, server);
				return 0;
			}
			if (minikafs_5convert_and_log(ctx, options, cell,
						      new_creds, uid) == 0) {
				krb5_free_creds(ctx, new_creds);
				krb5_free_principal(ctx, client);
				krb5_free_principal(ctx, server);
				return 0;
			}
			krb5_free_creds(ctx, new_creds);
		}
	}

	krb5_free_principal(ctx, client);
	krb5_free_principal(ctx, server);

	return -1;
}

/* Try to obtain tokens for the named cell using the default ccache and
 * configuration settings. */
static int
minikafs_5log(krb5_context context, krb5_ccache ccache,
	      struct _pam_krb5_options *options,
	      const char *cell, const char *hint_principal,
	      uid_t uid, int try_v5_2b)
{
	krb5_context ctx;
	krb5_ccache use_ccache;
	int ret;
	unsigned int i;
	char *principal, *defaultrealm, realm[PATH_MAX];
	size_t principal_size;
	const char *base[] = {"afs", "afsx"};

	if (context == NULL) {
		if (krb5_init_context(&ctx) != 0) {
			return -1;
		}
	} else {
		ctx = context;
	}

	defaultrealm = NULL;
	if (krb5_get_default_realm(ctx, &defaultrealm) != 0) {
		defaultrealm = NULL;
	}

	if (options->debug > 1) {
		debug("attempting to determine realm for \"%s\"", cell);
	}
	if (minikafs_realm_of_cell_with_ctx(ctx, options, cell,
					    realm, sizeof(realm)) != 0) {
		strncpy(realm, cell, sizeof(realm));
		realm[sizeof(realm) - 1] = '\0';
	} else {
		strcpy(realm, "");
	}

	principal_size = strlen("/@") + 1;
	for (i = 0; (ret != 0) && (i < sizeof(base) / sizeof(base[0])); i++) {
		principal_size += strlen(base[i]);
	}
	principal_size += strlen(cell);
	principal_size += strlen(realm);
	if (defaultrealm != NULL) {
		principal_size += strlen(defaultrealm);
	}
	principal = malloc(principal_size);
	if (principal == NULL) {
		if (defaultrealm != NULL) {
			v5_free_default_realm(ctx, defaultrealm);
		}
		return -1;
	}

	memset(&use_ccache, 0, sizeof(use_ccache));
	if (ccache != NULL) {
		use_ccache = ccache;
	} else {
		if (krb5_cc_default(ctx, &use_ccache) != 0) {
			if (ctx != context) {
				krb5_free_context(ctx);
			}
			return -1;
		}
	}

	ret = -1;

	/* If we were given a principal name, try it. */
	if ((hint_principal != NULL) && (strlen(hint_principal) > 0)) {
		debug("attempting to obtain tokens for \"%s\" (\"%s\")",
		      cell, hint_principal);
		ret = minikafs_5log_with_principal(ctx, options, use_ccache,
						   cell, hint_principal, uid,
						   try_v5_2b);
	}
	for (i = 0; (ret != 0) && (i < sizeof(base) / sizeof(base[0])); i++) {
		/* Try the cell instance in the cell's realm. */
		snprintf(principal, principal_size, "%s/%s@%s",
			 base[i], cell, realm);
		if (options->debug) {
			debug("attempting to obtain tokens for \"%s\" (\"%s\")",
			      cell, principal);
		}
		ret = minikafs_5log_with_principal(ctx, options, use_ccache,
						   cell, principal, uid,
						   try_v5_2b);
		if (ret == 0) {
			break;
		}
		/* If the realm name and cell name are similar, try the NULL
		   instance. */
		if (strcasecmp(realm, cell) == 0) {
			snprintf(principal, principal_size, "%s@%s",
				 base[i], realm);
			if (options->debug) {
				debug("attempting to obtain tokens for \"%s\" "
				      "(\"%s\")", cell, principal);
			}
			ret = minikafs_5log_with_principal(ctx, options,
							   use_ccache,
							   cell, principal, uid,
							   try_v5_2b);
		}
		if (ret == 0) {
			break;
		}
		/* Repeat the last two attempts, but using the default realm. */
		if ((defaultrealm != NULL) &&
		    (strcmp(defaultrealm, realm) != 0)) {
			/* Try the cell instance in the default realm. */
			snprintf(principal, principal_size, "%s/%s@%s",
				 base[i], cell, defaultrealm);
			if (options->debug) {
				debug("attempting to obtain tokens for \"%s\" "
				      "(\"%s\")", cell, principal);
			}
			ret = minikafs_5log_with_principal(ctx, options,
							   use_ccache,
							   cell, principal, uid,
							   try_v5_2b);
			if (ret == 0) {
				break;
			}
			/* If the default realm name and cell name are similar,
			 * try the NULL instance. */
			if (strcasecmp(defaultrealm, cell) == 0) {
				snprintf(principal, principal_size, "%s@%s",
					 base[i], defaultrealm);
				if (options->debug) {
					debug("attempting to obtain tokens for "
					      "\"%s\" (\"%s\")",
					      cell, principal);
				}
				ret = minikafs_5log_with_principal(ctx, options,
								   use_ccache,
								   cell,
								   principal,
								   uid,
								   try_v5_2b);
			}
			if (ret == 0) {
				break;
			}
		}
	}

	if (use_ccache != ccache) {
		krb5_cc_close(ctx, use_ccache);
	}
	if (defaultrealm != NULL) {
		v5_free_default_realm(ctx, defaultrealm);
	}
	if (ctx != context) {
		krb5_free_context(ctx);
	}
	free(principal);

	return ret;
}

#ifdef USE_KRB4
/* Try to set a token for the given cell using creds for the named principal. */
static int
minikafs_4log_with_principal(struct _pam_krb5_options *options,
			     const char *cell,
			     char *service, char *instance, char *realm,
			     uid_t uid)
{
	CREDENTIALS creds;
	u_int32_t endtime;
	int lifetime, ret;
	char lrealm[PATH_MAX];

	memset(&creds, 0, sizeof(creds));
	lifetime = 255;
	/* Get the lifetime from our TGT. */
	if (krb_get_tf_realm(tkt_string(), lrealm) == 0) {
		if (krb_get_cred(KRB_TICKET_GRANTING_TICKET, lrealm, lrealm,
				 &creds) == 0) {
			lifetime = creds.lifetime;
		}
	}
	/* Read the credential from the ticket file. */
	if (krb_get_cred(service, instance, realm, &creds) != 0) {
		if ((ret = get_ad_tkt(service, instance, realm,
				      lifetime)) != 0) {
			if (options->debug) {
				debug("got error %d (%s) obtaining v4 creds for"
				      " \"%s\"", ret, error_message(ret), cell);
			}
			return -1;
		}
		if (krb_get_cred(service, instance, realm, &creds) != 0) {
			return -1;
		}
	}
#ifdef HAVE_KRB_LIFE_TO_TIME
	/* Convert the ticket lifetime of the v4 credentials into Unixy
	 * lifetime, which is the X coordinate along a curve where Y is the
	 * actual length.  Again, this is magic. */

	endtime = krb_life_to_time(creds.issue_date, creds.lifetime);
#else
	/* No life-to-time function means we have to treat this as if we were
	 * measuring life units in 5-minute increments.  Is this ever right for
	 * AFS? */
	endtime = creds.issue_date + (creds.lifetime * (5 * 60));
#endif
	ret = minikafs_4settoken(cell, uid, creds.issue_date, endtime, &creds);
	return ret;
}

/* Try to obtain tokens for the named cell using the default ticket file and
 * configuration settings. */
static int
minikafs_4log(krb5_context context, struct _pam_krb5_options *options,
	      const char *cell, const char *hint_principal, uid_t uid)
{
	int ret;
	unsigned int i;
	char localrealm[PATH_MAX], realm[PATH_MAX];
	char service[PATH_MAX], instance[PATH_MAX];
	char *base[] = {"afs", "afsx"}, *wcell;
	krb5_principal principal;

	/* If we were given a principal name, try it. */
	if ((hint_principal != NULL) && (strlen(hint_principal) > 0)) {
		principal = NULL;
		if (krb5_parse_name(context, hint_principal, &principal) != 0) {
			principal = NULL;
		}
		if ((principal == NULL) ||
		    (krb5_524_conv_principal(context, principal,
					     service, instance, realm) != 0)) {
			memset(service, '\0', sizeof(service));
		}
		ret = -1;
		if (strlen(service) > 0) {
			if (options->debug) {
				debug("attempting to obtain tokens for \"%s\" "
				      "(\"%s\"(v5)->\"%s%s%s@%s\"(v4))",
				      cell, hint_principal,
				      service,
				      (strlen(service) > 0) ? "." : "",
				      instance,
				      realm);
			}
			ret = minikafs_4log_with_principal(options, cell,
							   service, instance,
							   realm,
							   uid);
		}
		if (principal != NULL) {
			krb5_free_principal(context, principal);
		}
		if (ret == 0) {
			return 0;
		}
	}

	if (krb_get_lrealm(localrealm, 1) != 0) {
		return -1;
	}
	if (minikafs_realm_of_cell_with_ctx(context, options, cell,
					    realm, sizeof(realm)) != 0) {
		strncpy(realm, cell, sizeof(realm));
		realm[sizeof(realm) - 1] = '\0';
	}
	wcell = xstrdup(cell);
	if (wcell == NULL) {
		return -1;
	}

	ret = -1;
	for (i = 0; i < sizeof(base) / sizeof(base[0]); i++) {
		/* Try the cell instance in its own realm. */
		if (options->debug) {
			debug("attempting to obtain tokens for \"%s\" "
			      "(\"%s%s%s@%s\")", cell, base[i],
			      (strlen(wcell) > 0) ? "." : "",
			      wcell, realm);
		}
		ret = minikafs_4log_with_principal(options, cell,
						   base[i], wcell, realm, uid);
		if (ret == 0) {
			break;
		}
		/* If the realm name and cell name are similar, try the NULL
		   instance. */
		if (strcasecmp(realm, cell) == 0) {
			if (options->debug) {
				debug("attempting to obtain tokens for \"%s\" "
				      "(\"%s@%s\")", cell, base[i], realm);
			}
			ret = minikafs_4log_with_principal(options, cell,
							   base[i], "", realm,
							   uid);
		}
		if (ret == 0) {
			break;
		}
		/* Repeat with the local realm. */
		if (strcmp(realm, localrealm) != 0) {
			/* Try the cell instance in its own realm. */
			if (options->debug) {
				debug("attempting to obtain tokens for \"%s\" "
				      "(\"%s%s%s@%s\")", cell, base[i],
				      (strlen(wcell) > 0) ? "." : "",
				      wcell, localrealm);
			}
			ret = minikafs_4log_with_principal(options, cell,
							   base[i], wcell,
							   localrealm, uid);
			if (ret == 0) {
				break;
			}
			/* If the realm name and cell name are similar, try the
			 * NULL instance. */
			if (strcasecmp(localrealm, cell) == 0) {
				if (options->debug) {
					debug("attempting to obtain tokens for "
					      "\"%s\" (\"%s@%s\")",
					      cell, base[i], localrealm);
				}
				ret = minikafs_4log_with_principal(options,
								   cell,
								   base[i], "",
								   localrealm,
								   uid);
			}
			if (ret == 0) {
				break;
			}
		}
	}

	xstrfree(wcell);

	return ret;
}
#endif

/* Try to get tokens for the named cell using every available mechanism. */
int
minikafs_log(krb5_context ctx, krb5_ccache ccache,
	     struct _pam_krb5_options *options,
	     const char *cell, const char *hint_principal,
	     uid_t uid, int try_v5_2b_first)
{
	int i;
	i = minikafs_5log(ctx, ccache, options, cell, hint_principal,
			  uid, try_v5_2b_first);
	if (i != 0) {
		if (options->debug) {
			debug("v5 afslog (2b=%d) failed to \"%s\"",
			      try_v5_2b_first, cell);
		}
	}
#ifdef USE_KRB4
	if (i != 0) {
		if (options->debug) {
			debug("trying with v4 ticket");
		}
		i = minikafs_4log(ctx, options, cell, hint_principal, uid);
		if (i != 0) {
			if (options->debug) {
				debug("v4 afslog failed to \"%s\"", cell);
			}
		}
	}
#endif
	if ((i != 0) && (!try_v5_2b_first)) {
		if (options->debug) {
			debug("retrying v5 with 2b=1");
		}
		i = minikafs_5log(ctx, ccache, options, cell, hint_principal,
				  uid, 1);
		if (i != 0) {
			if (options->debug) {
				debug("v5 afslog (2b=1) failed to \"%s\"",
				      cell);
			}
		}
	}
	if (i == 0) {
		if (options->debug) {
			debug("got tokens for cell \"%s\"", cell);
		}
	}
	return i;
}
