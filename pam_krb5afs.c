/*******************************************************************************
 A module for Linux-PAM to do Kerberos 5 authentication, convert the
 Kerberos 5 ticket to a Kerberos 4 ticket, and use it to grab AFS
 tokens for specified cells if possible.

 Copyright 2000-2002 Red Hat, Inc.
 Portions Copyright 1999 Nalin Dahyabhai.
 
 This is free software; you can redistribute it and/or modify it
 under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful, but
 WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 ******************************************************************************/

#ident "$Id$"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif
#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

/******************************************************************************/

#ifdef HAVE_COM_ERR_H
#include <com_err.h>
#endif

#ifdef HAVE_KRB5_H
#include <krb5.h>
#endif

#ifdef HEIMDAL
#define KRB5KDC_ERR_KEY_EXP KRB5KDC_ERR_KEY_EXPIRED
#endif

#ifdef HAVE_KERBEROSIV_KRB_H
#include <kerberosIV/krb.h>
#else
#ifdef HAVE_KRB_H
#include <krb.h>
#endif
#endif

#if defined(AFS) && defined(HAVE_KRBAFS_H)
#include <krbafs.h>
#define MODULE_NAME "pam_krb5afs"
#else
#define MODULE_NAME "pam_krb5"
#endif

#ifndef KRB5_SUCCESS
#define KRB5_SUCCESS 0
#endif

#define MODULE_STASH_NAME MODULE_NAME "_cred_stash"
#define MODULE_RET_NAME MODULE_NAME "_ret_stash"

#define PAM_SM_AUTH
#define PAM_SM_ACCT_MGMT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif

#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif

#ifndef PAM_AUTHTOK_RECOVERY_ERR
#ifdef PAM_AUTHTOK_RECOVER_ERR
#define PAM_AUTHTOK_RECOVERY_ERR PAM_AUTHTOK_RECOVER_ERR
#endif
#endif

#ifndef PAM_EXTERN
#define PAM_EXTERN extern
#endif

#define APPDEFAULT_APP		"pam"
#define DEFAULT_BANNER		"Kerberos 5"
#define DEFAULT_CCACHE_DIR	"/tmp"
#define DEFAULT_KEYTAB		"/etc/krb5.keytab"
#define DEFAULT_LIFE		36000
#define DEFAULT_SERVICE		"host"

#ifndef TRUE
#define FALSE 0
#define TRUE !FALSE
#endif

#define RC_OK ((krc == KRB5_SUCCESS) && (prc == PAM_SUCCESS))

#ifdef HAVE_LIBKRB524
extern int krb524_convert_creds_kdc(krb5_context, krb5_creds *, CREDENTIALS *);
#endif

#ifndef PASSWORD_CHANGING_SERVICE
#define PASSWORD_CHANGING_SERVICE "kadmin/changepw"
#endif

/* Variables internal to libkrb5 which allow tweaking of network timeouts. */
extern int krb5_max_skdc_timeout;
extern int krb5_skdc_timeout_shift;
extern int krb5_skdc_timeout_1;

/******************************************************************************/

/* Authentication. */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
				   const char **argv);

/* Credential management. */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
			      const char **argv);

/* Account management. */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
				const char **argv);

/* Session management. */
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
				   const char **argv);
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
				    const char **argv);
    
/* Password-setting. */
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc,
				const char **argv);

/******************************************************************************/

#define DEBUG if ((config == NULL) || (config->debug)) dEBUG

/* User credentials which we ask libpam to hang onto for us. */
struct stash {
	uid_t uid;
	gid_t gid;
	char v5_path[PATH_MAX];
	char v4_path[PATH_MAX];
	int have_v5_creds;
	krb5_creds v5_creds;
#ifdef HAVE_LIBKRB4
	int have_v4_creds;
	CREDENTIALS v4_creds;
#endif
};

/* Module-specific configuration data. */
struct config {
	int debug;
	int get_tokens;
	int try_first_pass;
	int try_second_pass;
	int use_authtok;
	int krb4_convert;
	int setcred;
	int user_check;
	int validate;
	krb5_get_init_creds_opt creds_opt;
	int ticket_lifetime;
	int renew_lifetime;
	int warn_period;
	int minimum_uid;
	int retain_token;			/* retain token after session closed */
	char *banner;
	char **cell_list;
	char *realm;
	char *required_tgs;
	char *ccache_dir;
	char *keytab;
};

/* Logging functions for logging messages of various types. */
static void
dEBUG(const char *x,...) {
	char buf[LINE_MAX];
	va_list a;
	va_start(a,x);
	vsnprintf(buf, sizeof(buf), x, a);
	va_end(a);
	syslog(LOG_DEBUG, MODULE_NAME ": %s", buf);
}
static void
NOTICE(const char *x,...) {
	char buf[LINE_MAX];
	va_list a;
	va_start(a,x);
	vsnprintf(buf, sizeof(buf), x, a);
	va_end(a);
	syslog(LOG_NOTICE, MODULE_NAME ": %s", buf);
}
static void
INFO(const char *x,...) {
	char buf[LINE_MAX];
	va_list a;
	va_start(a,x);
	vsnprintf(buf, sizeof(buf), x, a);
	va_end(a);
	syslog(LOG_INFO, MODULE_NAME ": %s", buf);
}
static void
WARN(const char *x,...) {
	char buf[LINE_MAX];
	va_list a;
	va_start(a,x);
	vsnprintf(buf, sizeof(buf), x, a);
	va_end(a);
	syslog(LOG_WARNING, MODULE_NAME ": %s", buf);
}
static void
CRIT(const char *x,...) {
	char buf[LINE_MAX];
	va_list a;
	va_start(a,x);
	vsnprintf(buf, sizeof(buf), x, a);
	va_end(a);
	syslog(LOG_CRIT, MODULE_NAME ": %s", buf);
}

#include "krb5conf.l.c"

/* Count the number of whitespace-separated words in the passed-in string. */
static int
num_words(const char *s)
{
	int i, ret = 0;
	for (i = 0; s && (s[i] != '\0'); i++) {
		/* If we're about to transit from word to (whitespace or nul),
		 * then count the word. */
		if (!isspace(s[i]) &&
		    (isspace(s[i + 1]) || (s[i + 1] == '\0'))) {
			ret++;
		}
	}
	return ret;
}

/* Return the address of the start of the nth whitespace-separated word in the
 * passed-in string, or an empty string if there is no such word. */
static const char *
nth_word(const char *s, int w)
{
	int i = 0, l = FALSE;
	for (i = 0; (s[i] != '\0') && (w > 0); i++) {
		/* If the current character is part of a word and the next
		 * character isn't, then we have less words to skip over. */
		if (l && !isspace(s[i + 1])) {
			w--;
		}
		l = isspace(s[i]);
		if (w == 0) {
			break;
		}
	}
	/* If we aren't still looking, return the location where we were when
	 * we stopped. */
	if (w == 0) {
		return &s[i];
	} else {
		return "";
	}
}

/* Make a copy of the passed-in string, stopping at the nul-terminator or at the
 * first piece of whitespace we find. */
static char *
word_copy(const char *s)
{
	int start = 0, end = 0;
	char *ret = NULL;
	/* Find the point in the string where we should start. */
	while ((s[start] != '\0') && isspace(s[start])) {
		start++;
	}
	/* Find the point in the string where we should end. */
	end = start;
	while ((s[end] != '\0') && !isspace(s[end])) {
		end++;
	}
	/* Allocate storage for the new string, and copy it into the area. */
	ret = malloc(end - start + 1);
	if (ret != NULL) {
		memcpy(ret, &s[start], end - start);
		ret[end - start] = '\0';
	}
	return ret;
}

/* Return the length of a string if it's below max_len, otherwise return
 * -1.  This function returns non-negative results whenever str can fit
 * into a buffer with room for max_len bytes of data. */
static int
xstrnlen(const char *str, int max_len)
{
	int i;
	for (i = 0; i < max_len; i++) {
		if (str[i] == '\0') {
			return i;
		}
	}
	return -1;
}

/* Determine if a word is an affirmative or a negative. */
static int
truefalse(const char *t)
{
	if ((strcasecmp(t, "on") == 0) ||
	    (strcasecmp(t, "true") == 0) ||
	    (strcasecmp(t, "yes") == 0)) {
		return TRUE;
	}
	if ((strcasecmp(t, "off") == 0) ||
	    (strcasecmp(t, "false") == 0) ||
	    (strcasecmp(t, "no") == 0)) {
		return FALSE;
	}
	return -1;
}

/* Convert a few Kerberos error codes and convert to PAM equivalents. */
static int
convert_kerror(int error)
{
	int prc;
	switch (error) {
		case KRB5_SUCCESS:
		case KRB5KDC_ERR_NONE:
			prc = PAM_SUCCESS;
			break;
		case KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN:
			prc = PAM_USER_UNKNOWN;
			break;
		case KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN:
		case KRB5_REALM_UNKNOWN:
		case KRB5_SERVICE_UNKNOWN:
			prc = PAM_SYSTEM_ERR;
			break;
		case KRB5KRB_AP_ERR_BAD_INTEGRITY:
			prc = PAM_PERM_DENIED;
			break;
		case KRB5KDC_ERR_KEY_EXP:
			prc = PAM_NEW_AUTHTOK_REQD;
			break;
		case KRB5KDC_ERR_NAME_EXP:
			prc = PAM_AUTHTOK_EXPIRED; /* Is this right?  The
						    * principal has expired. */
			break;
		default:
			prc = PAM_AUTH_ERR;
			break;
	}
	return prc;
}

/* Attempt to open a possibly-pre-existing file in such a way that we can
 * write to it safely, and truncate it to have zero length. */
static int
safe_create(struct config *config, const char *filename)
{
	struct stat ost, nst;
	int fd = -1, rc = -1, preexisting;

	/* Try to read characteristics of the file. */
	rc = lstat(filename, &ost);
	preexisting = (rc == 0);

	/* If the file exists and is normal, or doesn't exist, then we should
	 * try to open it. */
	if (((rc == 0) && S_ISREG(ost.st_mode)) ||
	    ((rc == -1) && (errno != ENOENT))) {
		errno = 0;
		fd = open(filename, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
	} else {
		return -1;
	}
	if (fd == -1) {
		NOTICE("error opening `%s': %s", filename, strerror(errno));
		return -1;
	}

	/* Get information about the file now that we have a descriptor. */
	rc = fstat(fd, &nst);
	if (rc == -1) {
		NOTICE("error getting information about `%s': %s", filename,
		       strerror(errno));
		close(fd);
		return -1;
	}

	/* If the file existed before we opened it, make sure that the
	 * descriptor points to the same device/inode we looked at before. */
	if (preexisting) {
		if ((ost.st_dev != nst.st_dev) || (ost.st_ino != nst.st_ino)) {
			NOTICE("sanity test failed for `%s': %s", filename,
			       strerror(errno));
			close(fd);
			return -1;
		}
	}

	/* Make sure the new file is not.... funny. */
	if (!S_ISREG(nst.st_mode)) {
		NOTICE("`%s' is not a regular file", filename);
		close(fd);
		return -1;
	}

	/* Make sure this is the only name the file has. */
	if (nst.st_nlink > 1) {
		NOTICE("`%s' has too many hard links", filename);
		close(fd);
		return -1;
	}

	/* Now it should be safe to zero out the file. */
	ftruncate(fd, 0);

	return fd;
}

/* Yes, this is very messy.  But the kerberos libraries will nuke any temporary
 * file we supply and create a new one, so keeping a file handle around and
 * fchown()ing it later won't work. */
static int
safe_fixup(struct config *config, const char *filename, struct stash *stash)
{
	struct stat ost, nst;
	int rc, fd;

	/* Get information about the file. */
	rc = lstat(filename, &ost);
	if (rc == -1) {
		NOTICE("error getting information about `%s': %s",
		       filename, strerror(errno));
		return PAM_SYSTEM_ERR;
	}

	/* Try to open the file.  If it doesn't exist, fail. */
	fd = open(filename, O_RDWR);
	if (fd == -1) {
		NOTICE("error opening `%s': %s", filename, strerror(errno));
		return PAM_SYSTEM_ERR;
	}

	/* Get information about the file the descriptor points to. */
	rc = fstat(fd, &nst);
	if (rc == -1) {
		NOTICE("error getting information about `%s': %s",
		       filename, strerror(errno));
		close(fd);
		return PAM_SYSTEM_ERR;
	}

	/* The device/inode pairs should match up.  If they don't, it's quite
	 * possible that someone is messing with us. */
	if ((ost.st_dev != nst.st_dev) ||
	    (ost.st_ino != nst.st_ino)) {
		NOTICE("sanity test failed for `%s': %s",
		       filename, strerror(errno));
		close(fd);
		return PAM_SYSTEM_ERR;
	}

	/* The file had better be a regular file with only one name, too. */
	if (!S_ISREG(nst.st_mode)) {
		NOTICE("`%s' is not a regular file", filename);
		close(fd);
		return PAM_SYSTEM_ERR;
	}
	if (nst.st_nlink > 1) {
		NOTICE("`%s' has too many hard links", filename);
		close(fd);
		return PAM_SYSTEM_ERR;
	}

	/* Actually change the ownership of the file.  This is allowed to fail
	 * if the current euid is not the superuser. */
	DEBUG("setting ownership on `%s' to %d/%d", filename,
	      stash->uid, stash->gid);
	rc = fchown(fd, stash->uid, stash->gid);
	if ((rc == -1) && (geteuid() == 0)) {
		CRIT("`%s' setting owner of ccache", strerror(errno));
		close(fd);
		return PAM_SYSTEM_ERR;
	}

	/* Set the permissions of the file (which we assume to be a ccache)
	 * so that only the owner can read or write to it. */
	DEBUG("setting permissions on `%s' to %04o", filename,
	      S_IRUSR | S_IWUSR);
	rc = fchmod(fd, S_IRUSR | S_IWUSR);
	if (rc == -1) {
		CRIT("`%s' setting mode of ticket file", strerror(errno));
		close(fd);
		return PAM_SYSTEM_ERR;
	}

	close(fd);

	return PAM_SUCCESS;
}

/* Read a value from the configuration file, using a path setup similar
 * to the MIT Kerberos internal profile functions. */
static void
appdefault_string(krb5_context context, const char *option,
		  int argc, const char **argv,
		  const char *default_value, char **ret_value)
{
	int found = FALSE, i;
	const char *tmp;
	char buf[LINE_MAX];
	size_t buflen;

	/* Read the value for the configuration option. */
	tmp = xkrb5_conf_read(option);
	if (tmp) {
		*ret_value = strdup(tmp);
		found = TRUE;
	}

	/* Let the argv array override the value. */
	snprintf(buf, sizeof(buf), "%s=", option);
	buflen = strlen(buf);
	for (i = 0; i < argc; i++) {
		if (strncmp(argv[i], buf, buflen) == 0) {
			/* If we already found a value (either here, or
			 * earlier in argv), remove it. */
			if (*ret_value != NULL) {
				free(*ret_value);
			}
			/* Use the value from argv[i]. */
			*ret_value = strdup(argv[i] + buflen);
			found = TRUE;
		}
	}

#ifdef HAVE_KRB5_APPDEFAULT_STRING
	/* If we haven't found it yet, use the libkrb5 functions for reading
	 * from the [appdefaults] section of the file. */
	if (!found) {
		krb5_appdefault_string(context, APPDEFAULT_APP, NULL, option,
				       default_value, ret_value);
		found = TRUE;
	}
#endif

	/* If we haven't found it, use the default value. */
	if (!found) {
		*ret_value = default_value ? strdup(default_value) : NULL;
	}
}

static void
appdefault_boolean(krb5_context context, const char *option,
		   int argc, const char **argv,
		   int default_value, int *ret_value)
{
	int found = FALSE, i;
	const char *tmp;
	char buf[LINE_MAX];
	size_t buflen;

	/* See if there's a value in the configuration file which looks
	 * like some kind of boolean. */
	tmp = xkrb5_conf_read(option);
	if (tmp) {
		if (truefalse(tmp) != -1) {
			*ret_value = truefalse(tmp);
			found = TRUE;
		}
	}

	/* Next, scan the argument array for "option=yes|no|true|false..." */
	snprintf(buf, sizeof(buf), "%s=", option);
	buflen = strlen(buf);

	for (i = 0; i < argc; i++) {
		/* Check for a match. */
		if (strncmp(argv[i], buf, buflen) == 0) {
			/* Only process it if it's a valid value. */
			if (truefalse(argv[i] + buflen) != -1) {
				*ret_value = truefalse(argv[i] + buflen);
				found = TRUE;
			}
		}
		/* Check for a match with "no_" prefixed, which negates it. */
		if (strncmp(argv[i], "no_", 3) == 0) {
			if (strcmp(argv[i] + 3, option) == 0) {
				*ret_value = FALSE;
				found = TRUE;
			}
		}
		/* Check for a match with "not" prefixed, which negates it. */
		if (strncmp(argv[i], "not", 3) == 0) {
			if (strcmp(argv[i] + 3, option) == 0) {
				*ret_value = FALSE;
				found = TRUE;
			}
		}
		/* Check for a match with "not_" prefixed, which negates it. */
		if (strncmp(argv[i], "not_", 4) == 0) {
			if (strcmp(argv[i] + 4, option) == 0) {
				*ret_value = FALSE;
				found = TRUE;
			}
		}
	}

#ifdef HAVE_KRB5_APPDEFAULT_BOOLEAN
	/* Try the profile [appdefault] section. */
	if (!found) {
		krb5_appdefault_boolean(context, APPDEFAULT_APP, NULL,
				        option, default_value, ret_value);
		found = TRUE;
	}
#endif
	/* Last resort, return the default. */
	if (!found) {
		*ret_value = default_value;
	}
}

static void
appdefault_integer(krb5_context context, const char *option,
		   int argc, const char **argv,
		   int default_value, int *ret_value)
{
	int found = FALSE, i, ival;
	char *p;
	const char *tmp;
	char buf[LINE_MAX];
	size_t buflen;

	/* Read the value from the configuration file. */
	tmp = xkrb5_conf_read(option);
	if (tmp) {
		*ret_value = atoi(tmp);
		found = TRUE;
	}

	/* Allow the argument list to override this value. */
	snprintf(buf, sizeof(buf), "%s=", option);
	buflen = strlen(buf);
	for (i = 0; i < argc; i++) {
		if (strncmp(argv[i], buf, buflen) == 0) {
			ival = strtol(argv[i] + buflen, &p, 0);
			if ((p == NULL) || (*p == '\0')) {
				*ret_value = ival;
			}
		}
	}

	/* If we didn't find anything, search the [appdefault] section. */
#ifdef HAVE_KRB5_APPDEFAULT_STRING
	if (!found) {
		krb5_appdefault_string(context, APPDEFAULT_APP, NULL,
				       option, "", (char**)&tmp);
		if (strlen(tmp) != 0) {
			ival = strtol(tmp, &p, 0);
			if (*p == '\0') {
				*ret_value = ival;
			}
			found = TRUE;
		}
	}
#endif
	/* Last resort, return the default. */
	if (!found) {
		*ret_value = default_value;
	}
}


static struct config *
get_config(krb5_context context, int argc, const char **argv)
{
	int i, j;
	struct config *ret = NULL, *config = NULL;
	char *foo, *hosts;
#ifdef AFS
	char *cells;
#endif
	krb5_address **addresses = NULL;
	krb5_address **hostlist;
	char tgsname[LINE_MAX] = DEFAULT_SERVICE "/";

	/* Read in the configuration file. */
	xkrb5_conf_parse_file();

	/* Defaults: try everything (try_first_pass, no debugging). */
	ret = malloc(sizeof(struct config));
	if (ret == NULL) {
		return NULL;
	}
	config = ret;
	memset(ret, 0, sizeof(struct config));
	krb5_get_init_creds_opt_init(&ret->creds_opt);
	ret->try_first_pass = 1;
	ret->try_second_pass = 1;

	/* Whether or not to debug via syslog. */
	appdefault_boolean(context, "debug", argc, argv,
			   ret->debug, &ret->debug);
	DEBUG("get_config() called");
			    
	/* Whether or not to retain the KRB token after session closed. */
	appdefault_boolean(context, "retain_after_close", argc, argv,
			   ret->retain_token, &ret->retain_token);

	/* The default realm we assume users are in unless told otherwise. */
	krb5_get_default_realm(context, &ret->realm);
	appdefault_string(context, "realm", argc, argv,
			  ret->realm, &ret->realm);
	krb5_set_default_realm(context, ret->realm);

	/* Whether to get an addressless ticket, or to get a ticket containing
	 * addresses of other hosts in addition to those of local interfaces. */
	appdefault_boolean(context, "addressless", argc, argv, FALSE, &i);
	if (i == TRUE) {
		DEBUG("Creating an addressless ticket");
		addresses = NULL;
	} else {
		/* Additional hosts credentials should be good for. */
		DEBUG("Creating a ticket with addresses");
		appdefault_string(context, "hosts", argc, argv, "", &hosts);

		/* Get the addresses of local interfaces, and count them. */
		krb5_os_localaddr(context, &hostlist);
		for (j = 0; hostlist[j] != NULL; j++) ;

		/* Allocate enough space for all of the local addresses, plus
		 * the number of hosts explicitly named, and one more for the
		 * NULL-terminator. */
		addresses = malloc(sizeof(krb5_address) *
				   (num_words(hosts) + 1 + j));
		if (addresses == NULL) {
			free(ret);
			return NULL;
		}

		/* Set the address list. */
		memset(addresses, 0, sizeof(krb5_address) *
		       (num_words(hosts) + 1 + j));
		for (j = 0; hostlist[j] != NULL; j++) {
			addresses[j] = hostlist[j];
		}
		for (i = 0; i < num_words(hosts); i++) {
			foo = word_copy(nth_word(hosts, i));
			if (foo == NULL) {
				free(ret);
				return NULL;
			}
			krb5_os_hostaddr(context, foo, &hostlist);
			DEBUG("also getting ticket for host `%s'", foo);
			addresses[i + j] = hostlist[0];
		}
	}
	krb5_get_init_creds_opt_set_address_list(&ret->creds_opt, addresses);

#ifdef AFS
	/* Cells to get tokens for. */
	appdefault_string(context, "afs_cells", argc, argv, "", &cells);
	DEBUG("will afslog to cells `%s'", cells);
	ret->cell_list = malloc(sizeof(char*) * (num_words(cells) + 1));
	if (ret->cell_list == NULL) {
		free(ret);
		return NULL;
	}
	memset(ret->cell_list, 0, sizeof(char*) * (num_words(cells) + 1));
	for (i = 0; i < num_words(cells); i++) {
		ret->cell_list[i] = word_copy(nth_word(cells, i));
		if (ret->cell_list[i] == NULL) {
			free(ret);
			return NULL;
		}
		DEBUG("will afslog to cell `%s'", ret->cell_list[i]);
		if (ret->krb4_convert != TRUE) {
			ret->krb4_convert = TRUE;
			DEBUG("krb4_convert forced on");
		}
	}
	ret->get_tokens = TRUE;
#endif

	/* What to say we are when changing passwords. */
	appdefault_string(context, "banner", argc, argv,
			  DEFAULT_BANNER, &ret->banner);
	DEBUG("password-changing banner set to `%s'", ret->banner);

	/* Which directory to put ticket files in. */
	appdefault_string(context, "ccache_dir", argc, argv,
			  DEFAULT_CCACHE_DIR, &ret->ccache_dir);
	DEBUG("ccache directory set to `%s'", ret->ccache_dir);

	/* Forwardable? */
	appdefault_boolean(context, "forwardable", argc, argv, TRUE, &i);
	if (i) {
		DEBUG("making tickets forwardable");
		krb5_get_init_creds_opt_set_forwardable(&ret->creds_opt, TRUE);
	} else {
		DEBUG("making tickets non-forwardable");
		krb5_get_init_creds_opt_set_forwardable(&ret->creds_opt, FALSE);
	}

	/* Support for changing timeouts. This plays with some internal library
	 * stuff which will apparently "go away soon".  When it does, it'll
	 * hopefully be replaced with the right way to do this. This sets the
	 * initial timeout when attempting to contact the KDC. */
	appdefault_integer(context, "initial_timeout", argc, argv,
			   krb5_skdc_timeout_1, &krb5_skdc_timeout_1);
	DEBUG("setting initial timeout to %d", krb5_skdc_timeout_1);

	/* Path to the keytab file. */
	appdefault_string(context, "keytab", argc, argv,
			  DEFAULT_KEYTAB, &ret->keytab);
	DEBUG("keytab file name set to `%s'", ret->keytab);

	/* Whether to get krb4 tickets using either krb524_convert_creds() or
	 * a v4 TGT request. */
	appdefault_boolean(context, "krb4_convert", argc, argv,
			   FALSE, &ret->krb4_convert);
	DEBUG("krb4_convert %s", ret->krb4_convert ? "true" : "false");

	/* Support for changing timeouts. This plays with some internal library
	 * stuff which will apparently "go away soon".  When it does, it'll
	 * hopefully be replaced with the right way to do this. This sets the
	 * maximum timeout when attempting to contact the KDC. */
	appdefault_integer(context, "max_timeout", argc, argv,
			   krb5_max_skdc_timeout, &krb5_max_skdc_timeout);
	DEBUG("setting maximum timeout to %d", krb5_max_skdc_timeout);

	/* Minimum user UID we care about. */
	appdefault_integer(context, "minimum_uid", argc, argv,
			   0, &ret->minimum_uid);
	DEBUG("will only attempt to authenticate users when UID >= %d",
	      ret->minimum_uid);

	/* Proxiable? */
	appdefault_boolean(context, "proxiable", argc, argv, TRUE, &i);
	if (i) {
		DEBUG("making tickets proxiable");
		krb5_get_init_creds_opt_set_proxiable(&ret->creds_opt, TRUE);
	} else {
		DEBUG("making tickets non-proxiable");
		krb5_get_init_creds_opt_set_proxiable(&ret->creds_opt, FALSE);
	}

	/* Renewable lifetime. */
	appdefault_integer(context, "renew_lifetime", argc, argv,
			   DEFAULT_LIFE, &ret->renew_lifetime);
	DEBUG("setting renewable lifetime to %d", ret->renew_lifetime);
	krb5_get_init_creds_opt_set_renew_life(&ret->creds_opt,
					       ret->renew_lifetime);

	/* Get the name of a service ticket the user must be able to obtain and
	 * a keytab with the key for the service in it, which we can use to
	 * decrypt the credential to make sure the KDC's response wasn't
	 * spoofed.  This is an undocumented way to do it, but it's what people
	 * do if they need to validate the TGT. */
	if (gethostname(tgsname + strlen(tgsname),
		       sizeof(tgsname) - strlen(tgsname) - 1) == -1) {
		memset(&tgsname, 0, sizeof(tgsname));
	}
	appdefault_string(context, "required_tgs", argc, argv,
			  tgsname, &ret->required_tgs);
	DEBUG("required_tgs set to `%s'", ret->required_tgs);

	/* Ticket lifetime. */
	appdefault_integer(context, "ticket_lifetime", argc, argv,
		           DEFAULT_LIFE, &ret->ticket_lifetime);
	DEBUG("setting ticket lifetime to %d", ret->ticket_lifetime);
	krb5_get_init_creds_opt_set_tkt_life(&ret->creds_opt,
					     ret->ticket_lifetime);

	/* Support for changing timeouts. This plays with some internal library
	 * stuff which will apparently "go away soon".  When it does, it'll
	 * hopefully be replaced with the right way to do this. This sets the
	 * timeout_shift value used when attempting to contact a KDC. */
	appdefault_integer(context, "timeout_shift", argc, argv,
			   krb5_skdc_timeout_shift, &krb5_skdc_timeout_shift);
	DEBUG("setting timeout shift to %d", krb5_skdc_timeout_shift);

	/* Rely exclusively on PAM_AUTHTOK for password-changing. */
	appdefault_boolean(context, "use_authtok", argc, argv,
			   FALSE, &ret->use_authtok);
	DEBUG("use_authtok %s", ret->use_authtok ? "true" : "false");

	/* Don't check that the user exists, and don't do ccache
	   permission munging. */
	appdefault_boolean(context, "user_check", argc, argv,
			   TRUE, &ret->user_check);
	DEBUG("user_check %s", ret->user_check ? "true" : "false");

	/* Whether to validate TGTs or not. */
	appdefault_boolean(context, "validate", argc, argv,
			   FALSE, &ret->validate);
	DEBUG("validate %s", ret->validate ? "true" : "false");

	/* Warning period before the user's password expires. */
	appdefault_integer(context, "warn_period", argc, argv, 604800, &i);
	ret->warn_period = i;
	DEBUG("warn_period %d", ret->warn_period);

	/* Parse the rest of the arguments which don't fit the above
	 * scheme very well. */
	for (i = 0; i < argc; i++) {
		/* Required argument that we don't use but need to recognize.*/
		if (strcmp(argv[i], "no_warn") == 0) {
			continue;
		}
		/* Try the first password. */
		if (strcmp(argv[i], "try_first_pass") == 0) {
			ret->try_first_pass = 1;
			continue;
		}
		/* Only try the first password. */
		if (strcmp(argv[i], "use_first_pass") == 0) {
			ret->try_second_pass = 0;
			continue;
		}
		/* Don't try the password stored in PAM_AUTHTOK. */
		if (strcmp(argv[i], "skip_first_pass") == 0) {
			ret->try_first_pass = 0;
			continue;
		}
		/* Do a setcred() from inside of the auth function. */
		if ((strcmp(argv[i], "get_tokens") == 0) ||
		   (strcmp(argv[i], "tokens") == 0) ||
		   (strcmp(argv[i], "force_cred") == 0)) {
			ret->setcred = 1;
		}
	}

	return ret;
}

/* Free some memory. */
static void
cleanup(pam_handle_t *pamh, void *data, int error_status)
{
	if (data != NULL) {
		free(data);
	}
}
static void
free_stash(pam_handle_t *pamh, void *data, int error_status)
{
	struct stash *stash = (struct stash*) data;
	if (stash != NULL) {
		if (stash->have_v5_creds) {
			krb5_free_cred_contents(NULL, &stash->v5_creds);
		}
		free(stash);
	}
}
static void
free_config(struct config *cfg)
{
	int i;
	if (cfg != NULL) {
		if (cfg->banner) {
			free(cfg->banner);
		}
		for (i = 0;
		     (cfg->cell_list != NULL) && (cfg->cell_list[i] != NULL);
		     i++) {
			free(cfg->cell_list[i]);
		}
		if (cfg->cell_list) {
			free(cfg->cell_list);
		}
		if (cfg->realm) {
			free(cfg->realm);
		}
		if (cfg->required_tgs) {
			free(cfg->required_tgs);
		}
		if (cfg->ccache_dir) {
			free(cfg->ccache_dir);
		}
		if (cfg->keytab) {
			free(cfg->keytab);
		}
		free(cfg);
	}
}

/******************************************************************************/

/* Prompt the user for a single piece of information. */
static int
pam_prompt_for(pam_handle_t *pamh, int msg_style, const char *msg, char **out)
{
	const struct pam_message prompt_message = {msg_style, msg};
	struct pam_response *responses;
	const struct pam_conv *converse = NULL;
	int ret = PAM_SUCCESS;
	const struct pam_message* promptlist[] = {
		&prompt_message,
		NULL
	};

	/* Get the conversation structure passed in by the app. */
	ret = pam_get_item(pamh, PAM_CONV, (const void**) &converse);
	if (ret != PAM_SUCCESS) {
		CRIT("no conversation function supplied");
	}

	/* Now actually prompt the user for that piece of information. */
	if (ret == PAM_SUCCESS) {
		/* Call the conversation function. */
		ret = converse->conv(1, promptlist, &responses,
				     converse->appdata_ptr);
		if (ret == PAM_SUCCESS) {
			if (out) {
				*out = NULL;
				if (responses && responses[0].resp) {
					*out = strdup(responses[0].resp);
					if (*out == NULL) {
						ret = PAM_SYSTEM_ERR;
					}
				}
			}
		} else {
			INFO("%s in conversation function getting info from "
			     "the user", pam_strerror(pamh, ret));
		}
	}

	return ret;
}

/* A wrapper function that wraps PAM prompts into the prompter format
 * that libkrb5 wants to see. */
static int
pam_prompter(krb5_context context, void *data, const char *name,
	     const char *banner, int num_prompts, krb5_prompt prompts[])
{
	int i = 0, len, ret = PAM_SUCCESS;
	char *result = NULL, *prompt = NULL, *tmp = NULL;
	for (i = 0; i < num_prompts; i++) {
		len = strlen(prompts[i].prompt) + strlen(": ") + 1;
		prompt = malloc(len);
		if (prompt == NULL) {
			return PAM_SYSTEM_ERR;
		}
		snprintf(prompt, len, "%s: ", prompts[i].prompt);
		ret = pam_prompt_for(data,
				     prompts[i].hidden ?
				     PAM_PROMPT_ECHO_OFF :
				     PAM_PROMPT_ECHO_ON,
				     prompt,
				     &result);
		if ((ret == PAM_SUCCESS) && (result != NULL)) {
			tmp = strdup(result);
			if (tmp == NULL) {
				ret = PAM_BUF_ERR;
			} else {
				prompts[i].reply->length = strlen(tmp);
				prompts[i].reply->data = tmp;
				if (prompts[i].hidden) {
					pam_set_item(data, PAM_AUTHTOK, tmp);
				}
			}
		} else {
			ret = KRB5_LIBOS_CANTREADPWD;
			break;
		}
	}
	return ret;
}

#ifdef HAVE_VALIDATION
/* Validate the TGT in stash->v5_creds using the keytab and required_tgs set in
 * config.  Return zero only if validation fails, required_tgs is set, and we
 * can read the keytab file. */
static int
validate_tgt(const char *user, krb5_context context, struct config *config,
	     struct stash *stash)
{
	krb5_keytab keytab;
	krb5_keytab_entry entry;
	krb5_principal server;
	krb5_creds st, *tgs;
	krb5_ticket *ticket;
	krb5_error_code ret;
	struct stat buf;

	/* Catch a few non-fatal errors. */
	if ((config->required_tgs == NULL) ||
	   (strlen(config->required_tgs) == 0)) {
		DEBUG("TGT not verified because required_tgs was not set");
		return TRUE;
	}
	if ((stat(config->keytab, &buf) == -1) && (errno == ENOENT)) {
		DEBUG("TGT not verified because keytab file %s doesn't exist",
		      config->keytab);
		return TRUE;
	}

	/* Parse out the service name into a principal. */
	DEBUG("validating TGT");
	ret = krb5_parse_name(context, config->required_tgs, &server);
	if (ret) {
		CRIT("error building service principal for %s: %s",
		     config->required_tgs, error_message(ret));
		return FALSE;
	}

	/* Try to get a service ticket, using the user's credentials,
	 * for authenticating to the service. */
	memset(&st, 0, sizeof(st));
	st.client = stash->v5_creds.client;
	st.server = server;
	ret = krb5_get_cred_via_tkt(context, &stash->v5_creds, 0, NULL,
				    &st, &tgs);
	if (ret) {
		CRIT("error getting credential for %s: %s",
		     config->required_tgs, error_message(ret));
		krb5_free_principal(context, server);
		return FALSE;
	}

	/* Decode the service information from the ticket. */
	ret = krb5_decode_ticket(&tgs->ticket, &ticket);
	if (ret) {
		CRIT("error decoding key information for %s: %s",
		     config->required_tgs, error_message(ret));
		krb5_free_principal(context, server);
		krb5_free_creds(context, tgs);
		return FALSE;
	}

	/* Open the keytab. */
	ret = krb5_kt_resolve(context, config->keytab, &keytab);
	if (ret) {
		DEBUG("error trying to open %s: %s", config->keytab,
		      error_message(ret));
		krb5_free_principal(context, server);
		krb5_free_creds(context, tgs);
		krb5_free_ticket(context, ticket);
		return FALSE;
	}

	/* Read the service's key from the keytab.  Consider lack of permissions
	 * to read the keytab to be a non-fatal error, and return success in the
	 * case where this is the cause of failures reading it. */
	ret = krb5_kt_get_entry(context, keytab, server, ticket->enc_part.kvno,
				ticket->enc_part.enctype, &entry);
	if (ret) {
		if (ret == EACCES) {
			DEBUG("error reading keys from %s: %s",
			      config->keytab, error_message(ret));
		} else {
			CRIT("error reading keys for %s from %s: %s",
			     config->required_tgs, config->keytab,
			     error_message(ret));
		}
		krb5_free_principal(context, server);
		krb5_free_creds(context, tgs);
		krb5_free_ticket(context, ticket);
		krb5_kt_close(context, keytab);
		return (ret == EACCES) ? TRUE : FALSE;
	}

	/* Try to decrypt the encrypted part with the server's key.  If
	 * we do this, and the checksums all match, then the encrypted
	 * part was encrypted with our key, so we know the KDC which
	 * generated it knows our key. */
	ret = krb5_decrypt_tkt_part(context, &entry.key, ticket);
	if (ret) {
		CRIT("verification error: %s", error_message(ret));
	} else {
		INFO("TGT for %s successfully verified", user);
	}

	krb5_free_principal(context, server);
	krb5_free_creds(context, tgs);
	krb5_free_ticket(context, ticket);
	krb5_kt_close(context, keytab);
	krb5_kt_free_entry(context, &entry);

	return (ret == KRB5_SUCCESS) ? TRUE : FALSE;
}
#else
static int
validate_tgt(const char *user, krb5_context context, struct config *config,
	     struct stash *stash)
{
	CRIT("verification error: verification not available because "
	     "krb5_decode_ticket() not available");
	return 0;
}
#endif

#ifdef HAVE___POSIX_GETPWNAM_R
/* Function for determining a user's UID and primary GID.  Solaris version. */
static int
get_pw(const char *user, uid_t *uid, gid_t *gid)
{
	static struct passwd rec;
	struct passwd *pwd = NULL;
	char buf[LINE_MAX];
	memset(&rec, 0, sizeof(rec));
	if (__posix_getpwnam_r(user, &rec, buf, sizeof(buf), &pwd) == 0) {
		if (pwd == &rec) {
			*uid = pwd->pw_uid;
			*gid = pwd->pw_gid;
			return TRUE;
		}
	}
	return FALSE;
}
#elif HAVE_GETPWNAM_R
/* Function for determining a user's UID and primary GID.  glibc and most
 * other systems version. */
static int
get_pw(const char *user, uid_t *uid, gid_t *gid)
{
	static struct passwd rec;
	struct passwd *pwd = NULL;
	static char buf[LINE_MAX];
	memset(&rec, 0, sizeof(rec));
	if (getpwnam_r(user, &rec, buf, sizeof(buf), &pwd) == 0) {
		if (pwd == &rec) {
			*uid = pwd->pw_uid;
			*gid = pwd->pw_gid;
			return TRUE;
		}
	}
	return FALSE;
}
#else
/* Really-old systems version. */
static int
get_pw(const char *user, uid_t *uid, gid_t *gid)
{
	struct passwd *pwd;
	pwd = getpwnam(user);
	if (pwd != NULL) {
		*uid = pwd->pw_uid;
		*gid = pwd->pw_gid;
		return TRUE;
	}
	return FALSE;
}
#endif

/* Big authentication module. */
int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	krb5_context context;
	krb5_principal principal;
	struct config *config = NULL;
	char *user = NULL;
	char *password = NULL;
	char *realm, *tmp;
	int krc = KRB5_SUCCESS, prc = PAM_SUCCESS, *pret = NULL;
	struct stash *stash = NULL;
	char localname[LINE_MAX];

	/* First parse the arguments; if there are problems, bail. */
#ifdef HAVE_INITIALIZE_KRB5_ERROR_TABLE
	initialize_krb5_error_table();
#endif
	krc = krb5_init_secure_context(&context);
	if (krc == KRB5_SUCCESS) {
		krb5_init_ets(context);
	} else {
		CRIT("error initializing Kerberos");
		prc = PAM_SYSTEM_ERR;
	}

	if (RC_OK) {
		if (!(config = get_config(context, argc, argv))) {
			CRIT("error parsing configuration");
			prc = PAM_SYSTEM_ERR;
		}
	}

	DEBUG("pam_sm_authenticate() called (prc = %s)",
	      pam_strerror(pamh, prc));

	/* Initialize Kerberos and grab some memory for the creds structures. */
	if (RC_OK) {
		stash = malloc(sizeof(struct stash));
		if (stash != NULL) {
			memset(stash, 0, sizeof(struct stash));
			krb5_get_default_realm(context, &realm);
			DEBUG("default Kerberos realm is `%s'", realm);
		} else {
			prc = PAM_SYSTEM_ERR;
			CRIT("Kerberos 5 initialize problem/malloc error");
		}
	}

	/* Grab some memory for storing the value to return in a subsequent
	 * setcred() call.  We have no idea what the stack looks like, so
	 * we *have* to help guarantee that the setcred call will work in
	 * exactly the way this authenticate call did. */
	if (RC_OK) {
		pret = malloc(sizeof(prc));
		if (pret != NULL) {
			*pret = PAM_SUCCESS;
		} else {
			prc = PAM_SYSTEM_ERR;
			CRIT("Kerberos 5 initialize problem/malloc error");
		}
	}

	/* Get the user's name, by any means possible. */
	if (RC_OK) {
		const char *rouser = NULL;
		prc = pam_get_user(pamh, &rouser, "login: ");
		if ((prc == PAM_SUCCESS) && (rouser != NULL)) {
			DEBUG("pam_get_user returned `%s'", rouser);
			user = strdup(rouser);
		} else {
			CRIT("couldn't determine user (first guess was `%s'), "
			     "prompting for user name");
			prc = pam_prompt_for(pamh,
					     PAM_PROMPT_ECHO_ON,
					     "login: ",
					     &user);
		}
		if ((prc != PAM_SUCCESS) || (strlen(user) == 0)) {
			CRIT("cannot determine user's login");
			prc = PAM_USER_UNKNOWN;
		}
	}
	DEBUG("user is `%s'", user);

	/* Build the user's principal. */
	if (RC_OK) {
		krc = krb5_parse_name(context, user, &principal);
		if (krc != KRB5_SUCCESS) {
			CRIT("%s building user principal for `%s'",
			     error_message(krc), user);
			prc = PAM_SYSTEM_ERR;
		}
	}

	/* Convert the principal name to a user name and store it as the
	 * PAM_USER. */
	if (RC_OK) {
		memset(&localname, '\0', sizeof(localname));
		if (krb5_aname_to_localname(context, principal,
					   sizeof(localname) - 1,
					   localname) == KRB5_SUCCESS) {
			if (strcmp(user, localname) != 0) {
				user = strdup(localname);
				prc = pam_set_item(pamh, PAM_USER, user);
				if (prc != PAM_SUCCESS) {
					WARN("error setting PAM_USER: %s",
					     pam_strerror(pamh, prc));
					prc = PAM_SUCCESS;
				}
			}
		}
	}

	/* Try to get and save the user's UID. */
	if (RC_OK) {
		if (!config->user_check) {
			stash->uid = getuid();
			stash->gid = getgid();
			DEBUG("using current uid %d, gid %d",
			      stash->uid, stash->gid);
		} else {
			if (get_pw(user, &stash->uid, &stash->gid)) {
				DEBUG("`%s' has uid %d, gid %d",
				      user, stash->uid, stash->gid);
				/* Check if we should care about this user. */
				if (stash->uid < config->minimum_uid) {
					DEBUG("ignoring user; uid is too low");
					prc = PAM_IGNORE;
				}
			} else {
				CRIT("unable to determine uid/gid for user");
				prc = PAM_USER_UNKNOWN;
			}
		}
	}

	/* Retrieve a password that may already have been entered. */
	if (RC_OK && config->try_first_pass) {
		pam_get_item(pamh, PAM_AUTHTOK, (const void**) &password);
	} else {
		password = NULL;
	}

	/* Now try to get a TGT using the password, prompting the user if it
	   fails and we're allowed to prompt for one. */
	if (RC_OK) {
		int authenticated = FALSE;

		DEBUG("attempting to authenticate `%s'", user);

		/* Set up the creds structure. */
		memset(&stash->v5_creds, 0, sizeof(stash->v5_creds));

		/* Who we're representing. */
		stash->v5_creds.client = principal;

		/* If we don't have a password, and we're not configured to
		 * prompt for one, we're done. */
		if ((password == NULL) &&
		   (config->try_first_pass) &&
		   (!config->try_second_pass)) {
			authenticated = TRUE;
			krc = KRB5_LIBOS_CANTREADPWD;
		}

		/* Try the password, if we have one. */
		if (config->try_first_pass && password && !authenticated) {
			krc = krb5_get_init_creds_password(context,
							   &stash->v5_creds,
							   principal,
							   (char*)password,
							   NULL,
							   NULL,
							   0,
							   NULL,
							   &config->creds_opt);
			DEBUG("get_int_tkt returned %s",
			      krc ? error_message(krc) : "Success");
			if (krc == KRB5_SUCCESS) {
				stash->have_v5_creds = TRUE;
			} else
			if (krc == KRB5KDC_ERR_NAME_EXP) {
				if (!(flags & PAM_SILENT)) {
					pam_prompt_for(pamh,
						       PAM_ERROR_MSG,
						       "Account expired.  Please contact your system administrator.",
						       NULL);
				}
			} else
			/* If we're just being told that the key expired, try
			 * to get a password-changing ticket for the purposes
			 * of checking the password. */
			if (krc = KRB5KDC_ERR_KEY_EXP) {
				krc = krb5_get_init_creds_password(context,
								   &stash->v5_creds,
								   principal,
								   (char*)password,
								   NULL,
								   NULL,
								   0,
								   PASSWORD_CHANGING_SERVICE,
								   NULL);
				if (krc == KRB5_SUCCESS) {
					if (!(flags & PAM_SILENT)) {
						pam_prompt_for(pamh,
							       PAM_ERROR_MSG,
							       "Password expired.  You must change it now.",
							       NULL);
					}
				}
			}
			if (krc == KRB5_SUCCESS) {
				authenticated = TRUE;
			}
		}

		/* Use the conversation function to ask the user for a password
		 * to authenticate with. */
		if (config->try_second_pass && !authenticated) {
			password = NULL;
			pam_prompt_for(pamh,
				       PAM_PROMPT_ECHO_OFF,
				       "Password: ",
				       &password);
			if (password) {
				tmp = strdup(password);
				if (tmp) {
					pam_set_item(pamh, PAM_AUTHTOK, tmp);
				}
			}
			krc = krb5_get_init_creds_password(context,
							   &stash->v5_creds,
							   principal,
							   (char*)password,
							   pam_prompter,
							   pamh,
							   0,
							   NULL,
							   &config->creds_opt);
			DEBUG("get_int_tkt returned %s",
			      krc ? error_message(krc) : "Success");
			if (krc == KRB5_SUCCESS) {
				stash->have_v5_creds = TRUE;
			} else
			if (krc == KRB5KDC_ERR_NAME_EXP) {
				if (!(flags & PAM_SILENT)) {
					pam_prompt_for(pamh,
						       PAM_ERROR_MSG,
						       "Your account has expired; please contact your system administrator",
						       NULL);
				}
			} else
			/* If the key expired, attempt to get a password-
			 * changing credential. */
			if (krc = KRB5KDC_ERR_KEY_EXP) {
				krc = krb5_get_init_creds_password(context,
								   &stash->v5_creds,
								   principal,
								   (char*)password,
								   NULL,
								   NULL,
								   0,
								   PASSWORD_CHANGING_SERVICE,
								   NULL);
				if (krc == KRB5_SUCCESS) {
					if (!(flags & PAM_SILENT)) {
						pam_prompt_for(pamh,
							       PAM_ERROR_MSG,
							       "Password expired.  You must change it now.",
							       NULL);
					}
				}
			}
			if (krc == KRB5_SUCCESS) {
				authenticated = TRUE;
			}
		}

		/* Figure out where to go from here. */
		if (krc != KRB5_SUCCESS) {
			CRIT("authenticate error: %s (%d)",
			     error_message(krc), krc);
		}
	}

	/* Verify that the TGT is good (i.e., that the reply wasn't spoofed). */
	if (RC_OK) {
		if (config->validate && stash->have_v5_creds) {
#ifdef HAVE_KRB5_VERIFY_INIT_CREDS
			krc = krb5_verify_init_creds(context,
						     &stash->v5_creds,
						     NULL,
						     NULL,
						     NULL,
						     NULL);
			if (krc != KRB5_SUCCESS) {
				CRIT("TGT verification failed for `%s'");
			}
#else
			if (validate_tgt(user, context, config, stash) == 0) {
				prc = PAM_AUTH_ERR;
			}
#endif
		}
	}

	/* Log something. */
	if (RC_OK) {
		INFO("authentication succeeds for `%s'", user);
	} else {
		INFO("authentication fails for `%s'", user);
	}

	if (RC_OK && stash->have_v5_creds) {
		prc = pam_set_data(pamh, MODULE_STASH_NAME, stash, free_stash);
		if (prc == PAM_SUCCESS) {
			DEBUG("credentials saved for `%s'", user);
		} else {
			DEBUG("error saving credentials for `%s'", user);
		}
	}

#ifdef HAVE_LIBKRB4
	/* Get Kerberos IV credentials if we are supposed to. */
	if (RC_OK && config->krb4_convert && stash->have_v5_creds) {
		const void *goodpass = NULL;
		char v4name[ANAME_SZ], v4inst[INST_SZ], v4realm[REALM_SZ];
		char sname[ANAME_SZ], sinst[INST_SZ];

		/* Get the authtok that succeeded.  We may need it. */
		pam_get_item(pamh, PAM_AUTHTOK, &goodpass);

		memset(v4name, '\0', sizeof(v4name));
		memset(v4inst, '\0', sizeof(v4inst));
		memset(v4realm, '\0', sizeof(v4realm));
		memset(sname, '\0', sizeof(sname));
		memset(sinst, '\0', sizeof(sinst));

		if (krb5_524_conv_principal(context, principal, v4name, v4inst,
					   v4realm) == KSUCCESS) {
			KTEXT_ST ciphertext_st;
			KTEXT ciphertext = &ciphertext_st;
			des_cblock key;
			des_key_schedule key_schedule;
			int k4rc;

			/* Request a TGT for this realm. */
			strncpy(sname, "krbtgt", sizeof(sname) - 1);
			strncpy(sinst, realm, sizeof(sinst) - 1);

			/* Note: the lifetime is measured in multiples of 5m. */
			k4rc = krb_mk_in_tkt_preauth(v4name, v4inst, v4realm,
						     sname, sinst,
						     config->ticket_lifetime
						     / 60 / 5,
						     NULL, 0, ciphertext);
			if (k4rc != KSUCCESS) {
				INFO("couldn't get v4 TGT for %s%s%s@%s (%s), "
				     "continuing", v4name,
				     strlen(v4inst) ? ".": "", v4inst, v4realm,
				     krb_get_err_text(k4rc));
			}
			if (k4rc == KSUCCESS) {
				unsigned char *p = ciphertext->dat;
				int len;

				/* Convert the password to a v4 key. */
				des_string_to_key((char*)goodpass, key);
				des_key_sched(key, key_schedule);

				/* Decrypt the TGT. */
				des_pcbc_encrypt((C_Block*)ciphertext->dat,
						 (C_Block*)ciphertext->dat,
						 ciphertext->length,
						 key_schedule,
						 (C_Block*)key,
						 0);
				memset(key, 0, sizeof(key));
				memset(key_schedule, 0, sizeof(key_schedule));

				/* Decompose the returned data.  Now I know
				 * why Kerberos 5 uses ASN.1 encoding.... */
				memset(&stash->v4_creds, 0,
				       sizeof(stash->v4_creds));

				/* Initial values. */
				strncpy((char*)&stash->v4_creds.pname, v4name,
					sizeof(stash->v4_creds.pname) - 1);
				strncpy((char*)&stash->v4_creds.pinst, v4inst,
					sizeof(stash->v4_creds.pinst) - 1);

				/* Session key. */
				len = ciphertext->length;
				DEBUG("ciphertext length in TGT = %d", len);

				memcpy(&stash->v4_creds.session, p, 8);
				p += 8;
				len -= 8;

				/* Service name. */
				if (xstrnlen(p, len) > 0) {
					strncpy(stash->v4_creds.service, p,
						sizeof(stash->v4_creds.service)
						- 1);
				} else {
					INFO("service name in v4 TGT too long: "
					     "%.8s", p);
				}
				p += (strlen(stash->v4_creds.service) + 1);
				len -= (strlen(stash->v4_creds.service) + 1);

				/* Service instance. */
				if (xstrnlen(p, len) > 0) {
					strncpy(stash->v4_creds.instance, p,
						sizeof(stash->v4_creds.instance)
						- 1);
				}
				p += (strlen(stash->v4_creds.instance) + 1);
				len -= (strlen(stash->v4_creds.instance) + 1);

				/* Service realm. */
				if (xstrnlen(p, len) > 0) {
					strncpy(stash->v4_creds.realm, p,
						sizeof(stash->v4_creds.realm)
						- 1);
				}
				p += (strlen(stash->v4_creds.realm) + 1);
				len -= (strlen(stash->v4_creds.realm) + 1);

				/* Lifetime, kvno, length. */
				if (len >= 3) {
					stash->v4_creds.lifetime = p[0];
					stash->v4_creds.kvno = p[1];
					stash->v4_creds.ticket_st.length = p[2];
				}
				p += 3;
				len -= 3;

				/* Ticket data. */
				if (len >= stash->v4_creds.ticket_st.length) {
					memcpy(stash->v4_creds.ticket_st.dat, p,
					       stash->v4_creds.ticket_st.length);
				}
				p += stash->v4_creds.ticket_st.length;
				len -= stash->v4_creds.ticket_st.length;

				/* Timestamp. */
				if (len >= 4) {
					memcpy(&stash->v4_creds.issue_date,
					       p, 4);
					/* We can't tell if we need to byte-swap
					 * or not, so just make up an issue date
					 * that looks reasonable. */
					stash->v4_creds.issue_date = time(NULL);
				}
				p += 4;
				len -= 4;


				DEBUG("Got v4 TGT for `%s%s%s@%s'",
				      stash->v4_creds.service,
				      strlen(stash->v4_creds.instance) ?
				      "." : "",
				      stash->v4_creds.instance,
				      stash->v4_creds.realm);
				stash->have_v4_creds = TRUE;

				/* Sanity checks. */
				if (len != 0) {
					INFO("Got %d extra bytes in v4 TGT",
					     ciphertext->length - len);
					DEBUG("Extra data = %c%c%c%c%c%c%c%c",
					      p[0], p[1], p[2], p[3],
					      p[4], p[5], p[6], p[7]);
					DEBUG("Extra data = %c%c%c%c%c%c%c%c",
					      p[9], p[10], p[11], p[12],
					      p[13], p[14], p[15], p[16]);
				}
			}
		}
	}
#endif

#ifdef AFS
	/* Get tokens if configured to force it. */
	if (RC_OK && config->setcred && stash->have_v4_creds) {
		prc = pam_sm_setcred(pamh, PAM_ESTABLISH_CRED, argc, argv);
		if (prc == PAM_SUCCESS) {
			prc = pam_sm_setcred(pamh, PAM_DELETE_CRED, argc, argv);
		}
	}
#endif

	/* Recover any Kerberos errors as PAM errors. */
	if (prc == PAM_SUCCESS) {
		prc = convert_kerror(krc);
	}

	/* Save the return code for later use by setcred(). */
	if (RC_OK) {
		*pret = prc;
		prc = pam_set_data(pamh, MODULE_RET_NAME, pret, cleanup);
		if (prc == PAM_SUCCESS) {
			DEBUG("saved return code (%d) for later use", *pret);
		} else {
			INFO("error %d (%s) saving return code (%d)", prc,
			     pam_strerror(pamh, prc), *pret);
		}
		prc = *pret;
	}

	if (!stash->have_v5_creds) {
		free_stash(pamh, stash, PAM_SUCCESS);
	}
	free_config(config);

	/* Done with Kerberos. */
	if (context != NULL) {
		krb5_free_context(context);
	}

	/* Attempt to save the local name associated with the principal
	 * as the PAM_USER item. */
	if (RC_OK) {
		pam_set_item(pamh, PAM_USER, user);
	}

	DEBUG("pam_sm_authenticate returning %d (%s)", prc,
	      prc ? pam_strerror(pamh, prc) : "Success");

	return prc;
}

/******************************************************************************/

/* Create and delete visible credentials as needed. */
int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	krb5_context context;
	struct stash *stash;
	krb5_ccache ccache;
	char v4_path[PATH_MAX];
	char v5_path[PATH_MAX];
	char *user = NULL;
	int krc = KRB5_SUCCESS, prc = PAM_SUCCESS, *pret = NULL;
	struct config *config = NULL;

	/* First parse the arguments; if there are problems, bail. */
#ifdef HAVE_INITIALIZE_KRB5_ERROR_TABLE
	initialize_krb5_error_table();
#endif
	krc = krb5_init_secure_context(&context);
	if (krc == KRB5_SUCCESS) {
		krb5_init_ets(context);
	} else {
		prc = PAM_SYSTEM_ERR;
	}
	if (RC_OK) {
		if (!(config = get_config(context, argc, argv))) {
			prc = PAM_SYSTEM_ERR;
		}
	}
	DEBUG("pam_sm_setcred() called");

	/* Retrieve information about the user. */
	if (RC_OK) {
		const void *rouser = NULL;
		prc = pam_get_item(pamh, PAM_USER, &rouser);
		if (prc != PAM_SUCCESS) {
			CRIT("couldn't determine user");
			prc = PAM_USER_UNKNOWN;
		}
		if (rouser != NULL) {
			user = strdup(rouser);
		}
		if ((user != NULL) && (strlen(user) == 0)) {
			CRIT("cannot determine user's login");
			prc = PAM_USER_UNKNOWN;
		}
	}

	if (RC_OK && (flags & (PAM_ESTABLISH_CRED | PAM_REINITIALIZE_CRED))) {
		int tmpfd = -1;

		/* Retrieve credentials and create a ccache. */
		prc = pam_get_data(pamh, MODULE_STASH_NAME, (void*)&stash);
		if (prc == PAM_SUCCESS) {
			DEBUG("credentials retrieved");

			if (strlen(stash->v5_path) == 0) {
				snprintf(v5_path, sizeof(v5_path),
					 "%s/krb5cc_%d_XXXXXX",
					 config->ccache_dir, stash->uid);
				tmpfd = mkstemp(v5_path);
				if (tmpfd != -1) {
					memset(stash->v5_path, '\0',
					       sizeof(stash->v5_path));
					strncpy(stash->v5_path, v5_path,
						sizeof(stash->v5_path) - 1);
				}
			} else {
				tmpfd = safe_create(config, stash->v5_path);
			}

			if (tmpfd == -1) {
				CRIT("%s opening ccache", strerror(errno));
				prc = PAM_SYSTEM_ERR;
			} else {
				/* Mess with the file's ownership to make
				 * libkrb happy. */
				fchown(tmpfd, getuid(), getgid());
			}
		}
		if (RC_OK) {
			/* Open the ccache via Kerberos. */
			snprintf(v5_path, sizeof(v5_path),
				 "FILE:%s", stash->v5_path);
			krc = krb5_cc_resolve(context, v5_path, &ccache);
			if (krc == KRB5_SUCCESS) {
				krc = krb5_cc_initialize(context, ccache,
							 stash->v5_creds.client);
			}
			if (krc != KRB5_SUCCESS) {
				CRIT("error initializing ccache %s for `%s': %s",
				     v5_path, user, error_message(krc));
			}

			/* Store credentials in the cache. */
			if (krc == KRB5_SUCCESS) {
				krb5_cc_store_cred(context, ccache,
						   &stash->v5_creds);
			}

			/* Close the ccache. */
			krb5_cc_close(context, ccache);
			close(tmpfd);
			tmpfd = -1;

			/* Set the environment variable to point to the cache.*/
			snprintf(v5_path, sizeof(v5_path), "KRB5CCNAME=FILE:%s",
				 stash->v5_path);
			prc = pam_putenv(pamh, v5_path);
			if (prc != PAM_SUCCESS) {
				CRIT("%s setting environment",
				     pam_strerror(pamh, prc));
			}
			if (prc != PAM_SUCCESS) {
				CRIT("%s setting environment",
				     pam_strerror(pamh, prc));
			}
			DEBUG("%s", v5_path);
		} else {
			DEBUG("Kerberos 5 credential retrieval failed for `%s',"
			      " user is probably local", user);
			stash = NULL;
			prc = PAM_CRED_UNAVAIL;
		}

#ifdef HAVE_LIBKRB524
		/* Get Kerberos 4 credentials if we haven't already. */
		if (RC_OK && config->krb4_convert) {
			if (!stash->have_v4_creds) {
				DEBUG("converting credentials for `%s'", user);

				krc = krb524_convert_creds_kdc(context,
							       &stash->v5_creds,
							       &stash->v4_creds);

				DEBUG("krb524_convert_creds returned `%s' for "
				      "`%s'",
				      krc ?
				      error_message(krc) :
				      "Success",
				      user);

				if (krc == KRB5_SUCCESS) {
					INFO("v4 ticket conversion succeeded "
					     "for `%s'", user);
					stash->have_v4_creds = TRUE;
				} else {
					/* This shouldn't happen.  Either
					 * krb524d isn't running on the KDC or
					 * the module is misconfigured, or
					 * something weirder still happened:
					 * we succeeded. */
					CRIT("v4 ticket conversion failed for "
					     "`%s': %d (%s)", user, krc,
					     error_message(krc));
					krc = KRB5_SUCCESS;
				}
			}
		}
#endif
#ifdef HAVE_LIBKRB4
		if (RC_OK && stash->have_v4_creds) {
			if (strlen(stash->v4_path) == 0) {
				/* Create a new ticket file. */
				snprintf(v4_path, sizeof(v4_path),
					 "%s/tkt%d_XXXXXX",
					 config->ccache_dir, stash->uid);
				tmpfd = mkstemp(v4_path);
				if (tmpfd != -1) {
					memset(stash->v4_path, '\0',
					       sizeof(stash->v4_path));
					strncpy(stash->v4_path, v4_path,
						sizeof(stash->v4_path) - 1);
				}
			} else {
				tmpfd = safe_create(config, stash->v4_path);
			}

			if (tmpfd == -1) {
				CRIT("%s opening ccache", strerror(errno));
				prc = PAM_SYSTEM_ERR;
			} else {
				/* Mess with the file's ownership to make
				 * libkrb4 happy. */
				fchown(tmpfd, getuid(), getgid());
			}
		}
		if (RC_OK && strlen(stash->v4_path)) {
			int save = TRUE;

			DEBUG("opening ticket file `%s'", stash->v4_path);
			krb_set_tkt_string(stash->v4_path);
			krc = in_tkt(stash->v4_creds.pname,
				     stash->v4_creds.pinst);

			if (krc != KRB5_SUCCESS) {
				CRIT("error initializing %s for %s (code = %d),"
				     " punting", stash->v4_path, user, krc);
				save = TRUE;
				krc = KRB5_SUCCESS;
			}

			/* Store credentials in the ticket file. */
			if ((krc == KRB5_SUCCESS) && save) {
				DEBUG("save v4 creds (%s%s%s@%s:%d), %d",
				      stash->v4_creds.service,
				      strlen(stash->v4_creds.instance) ?
				      "." : "",
				      stash->v4_creds.instance ?
				      stash->v4_creds.instance : "",
				      stash->v4_creds.realm,
				      stash->v4_creds.kvno,
				      stash->v4_creds.lifetime);
				krb_save_credentials(stash->v4_creds.service,
						     stash->v4_creds.instance,
						     stash->v4_creds.realm,
						     stash->v4_creds.session,
						     stash->v4_creds.lifetime,
						     stash->v4_creds.kvno,
						     &stash->v4_creds.ticket_st,
						     stash->v4_creds.issue_date);
			}

			/* Close the ccache. */
			tf_close();
			close(tmpfd);
			tmpfd = -1;

			/* Set up the environment variable for Kerberos 4. */
			snprintf(v4_path, sizeof(v4_path),
				 "KRBTKFILE=%s", stash->v4_path);
			prc = pam_putenv(pamh, v4_path);
			if (prc != PAM_SUCCESS) {
				CRIT("%s setting environment",
				     pam_strerror(pamh, prc));
			}
			if (prc != PAM_SUCCESS) {
				CRIT("%s setting environment",
				     pam_strerror(pamh, prc));
			}
			DEBUG(v4_path);
		}
#endif
	}

#ifdef AFS
	/* Use the new tickets to create tokens. */
	if (RC_OK && (flags & (PAM_ESTABLISH_CRED | PAM_REINITIALIZE_CRED)) &&
	   config->get_tokens && config->cell_list) {
		if (!k_hasafs()) {
			CRIT("cells specified but AFS not running");
		} else {
			int i, rc;
			/* Afslog to all of the specified cells. */
			DEBUG("k_setpag()");
			rc = k_setpag();
			DEBUG("k_setpag() returned %d", rc);
			for (i = 0; config->cell_list[i] != NULL; i++) {
				DEBUG("afslog() to cell `%s'",
				      config->cell_list[i]);
				rc = krb_afslog(config->cell_list[i],
						config->realm);
				DEBUG("afslog() returned %d", rc);
			}
		}
	}
#endif

	/* Fix permissions on this file so that the user logging in will
	 * be able to use it. */
	if (RC_OK &&
	   (flags & (PAM_ESTABLISH_CRED | PAM_REINITIALIZE_CRED)) &&
	   (strlen(stash->v5_path) > 0)) {
		prc = safe_fixup(config, stash->v5_path, stash);
	}

#ifdef HAVE_LIBKRB4
	if (RC_OK &&
	   (flags & (PAM_ESTABLISH_CRED | PAM_REINITIALIZE_CRED)) &&
	   (strlen(stash->v4_path) > 0)) {
		prc = safe_fixup(config, stash->v4_path, stash);
	}
#endif

	if (RC_OK && (flags & PAM_DELETE_CRED) && config->retain_token) {
		DEBUG("retaining token beyond session-closure");
	}
	else if (RC_OK && (flags & PAM_DELETE_CRED) && !config->retain_token) {
		prc = pam_get_data(pamh,MODULE_STASH_NAME,(const void**)&stash);
		if ((prc == PAM_SUCCESS) && (strlen(stash->v5_path) > 0)) {
			/* Delete the v5 ticket cache. */
			DEBUG("removing %s", stash->v5_path);
			if (remove(stash->v5_path) == -1) {
				CRIT("error removing file %s: %s",
				     stash->v5_path, strerror(errno));
			} else {
				strcpy(stash->v5_path, "");
			}
		}
#ifdef HAVE_LIBKRB4
		if ((prc == PAM_SUCCESS) && (strlen(stash->v4_path) > 0)) {
			/* Delete the v4 ticket cache. */
			DEBUG("removing %s", stash->v4_path);
			if (remove(stash->v4_path) == -1) {
				CRIT("error removing file %s: %s",
				     stash->v4_path, strerror(errno));
			} else {
				strcpy(stash->v4_path, "");
			}
		}
#endif
#ifdef AFS
		/* Clear tokens unless we need them. */
		if ((prc == PAM_SUCCESS) && !config->setcred && k_hasafs()) {
			DEBUG("destroying tokens");
			k_unlog();
		}
#endif
	}

	/* Done with Kerberos. */
	if (context != NULL) {
		krb5_free_context(context);
	}

	pam_get_data(pamh, MODULE_RET_NAME, (const void**) &pret);
	if (pret) {
		DEBUG("recovered return code %d from prior call to "
		      "pam_sm_authenticate()", *pret);
		prc = *pret;
	}

	DEBUG("pam_sm_setcred returning %d (%s)", prc,
	      (prc != PAM_SUCCESS) ? pam_strerror(pamh, prc) : "Success");

	if (user != NULL) {
		free(user);
	}

	return prc;
}

/******************************************************************************/

int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct config *config = NULL;
	krb5_context context = NULL;
	int ret = PAM_SUCCESS;

	if (krb5_init_secure_context(&context) != KRB5_SUCCESS) {
		ret = PAM_SYSTEM_ERR;
	}
	if (ret == PAM_SUCCESS) {
		if (!(config = get_config(context, argc, argv))) {
			ret = PAM_SYSTEM_ERR;
		}
	}
	DEBUG("pam_sm_open_session() called");
	if (context != NULL) {
		krb5_free_context(context);
	}

	return pam_sm_setcred(pamh, flags | PAM_ESTABLISH_CRED, argc, argv);
}

int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct config *config = NULL;
	krb5_context context = NULL;
	int ret = PAM_SUCCESS;

	if (krb5_init_secure_context(&context) != KRB5_SUCCESS) {
		ret = PAM_SYSTEM_ERR;
	}
	if (ret == PAM_SUCCESS) {
		if (!(config = get_config(context, argc, argv))) {
			ret = PAM_SYSTEM_ERR;
		}
	}
	DEBUG("pam_sm_close_session() called");
	if (context != NULL) {
		krb5_free_context(context);
	}

	return pam_sm_setcred(pamh, flags | PAM_DELETE_CRED, argc, argv);
}

/* A callback function that simply fails. */
static krb5_error_code
fail()
{
	return KRB5KRB_ERR_GENERIC;
}

/* Perform account management (authorization(?)) checks on the user's
 * account. */
int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	krb5_context context = NULL;
	int prc = PAM_SUCCESS, krc = KRB5_SUCCESS, *pret;
	struct config *config = NULL;
	krb5_principal princ = NULL;
	krb5_creds increds;
	krb5_kdc_rep *rep = NULL;
	const char *user;
	char buf[LINE_MAX];

	/* Initialize Kerberos. */
#ifdef HAVE_INITIALIZE_KRB5_ERROR_TABLE
	initialize_krb5_error_table();
#endif
	if (krb5_init_secure_context(&context) != KRB5_SUCCESS) {
		prc = PAM_SYSTEM_ERR;
	}

	/* Read in the configuration. */
	if (RC_OK) {
		if ((config = get_config(context, argc, argv))) {
			prc = PAM_SYSTEM_ERR;
		}
	}
	DEBUG("pam_sm_acct_mgmt() called");

	/* Ask libpam for the user's name, and bail if she has none. */
	prc = pam_get_item(pamh, PAM_USER, (const void**)&user);
	if (user == NULL) {
		prc = PAM_USER_UNKNOWN;
	} else {
		krc = krb5_parse_name(context, user, &princ);
	}

	/* The principal and the user name are enough for us to go on. */
	if (RC_OK) {
		/* This is bit silly due to the fact that PAM doesn't let us
		 * authenticate as one user and authorize as another, but the
		 * empty .k5login case might crop up here.  Unlike most krb5
		 * API functions, kuserok returns 1 on success, 0 on failure. */
		krc = krb5_kuserok(context, princ, user);
		DEBUG("krb5_kuserok(%s, %s) = %d", user, user, krc);
		if (krc == 0) {
			/* Failure means we don't let the user in. */
			prc = PAM_PERM_DENIED;
		} else {
			/* Success means we continue on to other checks. */
			krc = KRB5_SUCCESS;
		}
	}

	/* If the user is authorized, check that the user's key hasn't
	 * expired. */
	if (RC_OK) {
		memset(&increds, 0, sizeof(increds));
		krc = krb5_parse_name(context, user, &increds.client);
	}
	if (RC_OK) {
		/* Get the name of the TGT for the default realm. */
		snprintf(buf, sizeof(buf), "krbtgt/%*s@%*s",
			 krb5_princ_realm(context, increds.client)->length,
			 krb5_princ_realm(context, increds.client)->data,
			 krb5_princ_realm(context, increds.client)->length,
			 krb5_princ_realm(context, increds.client)->data);
		krc = krb5_parse_name(context, buf, &increds.server);
		if (krc == KRB5_SUCCESS) {
			/* Get some initial credentials.  We don't care if the
			 * password check or decryption succeeds, just whether
			 * or not the attempt to fetch a TGT gives us a "key
			 * expired" error or not. */
			krc = krb5_get_in_tkt(context,
					      0,
					      NULL,
					      NULL,
					      NULL,
					      fail,
					      NULL,
					      fail,
					      NULL,
					      &increds,
					      NULL,
					      &rep);
			DEBUG("krb5_get_in_tkt(%s,%s) with bogus decryption "
			      "functions = %d", user, buf, krc);
			krb5_free_cred_contents(context, &increds);
			if (rep != NULL) {
				krb5_free_kdc_rep(context, rep);
			}
			if (krc == KRB5KDC_ERR_KEY_EXP) {
				prc = PAM_NEW_AUTHTOK_REQD;
			}
			krc = KRB5_SUCCESS;
		} else {
			prc = convert_kerror(krc);
		}
	}
	/* Clean up. */
	if (princ != NULL) {
		krb5_free_principal(context, princ);
	}
	if (context != NULL) {
		krb5_free_context(context);
	}
	DEBUG("pam_sm_acct_mgmt() returning %d (%s)",
	      prc, pam_strerror(pamh, prc));
	return prc;
}

/* Change the principal's password. */
int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	krb5_context context = NULL;
	krb5_principal principal, server;
	char *user = NULL, *authtok = NULL, *old_authtok = NULL;
	char current_pass[LINE_MAX], new_pass[LINE_MAX], retype_pass[LINE_MAX];
	struct config *config = NULL;
	int prc = PAM_SUCCESS, krc = KRB5_SUCCESS;
	int result_code;
	krb5_creds creds;
	krb5_data result_code_string, result_string;

	/* Initialize Kerberos. */
#ifdef HAVE_INITIALIZE_KRB5_ERROR_TABLE
	initialize_krb5_error_table();
#endif
	if (krb5_init_secure_context(&context) != KRB5_SUCCESS) {
		prc = PAM_SYSTEM_ERR;
	}
	if (RC_OK) {
		if (!(config = get_config(context, argc, argv))) {
			prc = PAM_SYSTEM_ERR;
		}
	}
	DEBUG("pam_sm_chauthtok() called");
	/* Reset the flags, since we're doing password changing. */
	if (RC_OK) {
		krb5_get_init_creds_opt_set_forwardable(&config->creds_opt,
							FALSE);
		krb5_get_init_creds_opt_set_proxiable(&config->creds_opt,
						      FALSE);
		krb5_get_init_creds_opt_set_renew_life(&config->creds_opt, 0);
	}

	/* Initialize prompt strings. */
	snprintf(current_pass, sizeof(current_pass), "Current %s password: ",
		 (config && config->banner) ? config->banner : "");
	snprintf(new_pass, sizeof(new_pass), "New %s password: ",
		 (config && config->banner) ? config->banner : "");
	snprintf(retype_pass, sizeof(retype_pass), "Retype new %s password: ",
		 (config && config->banner) ? config->banner : "");

	/* Figure out who the user is. */
	if (RC_OK) {
		const char *rouser = NULL;
		prc = pam_get_user(pamh, &rouser, "login: ");
		if (prc != PAM_SUCCESS) {
			CRIT("couldn't determine user");
			prc = PAM_USER_UNKNOWN;
		}
		if (rouser != NULL) {
			user = strdup(rouser);
		}
		if ((user != NULL) && (strlen(user) == 0)) {
			CRIT("cannot determine user's login");
			prc = PAM_USER_UNKNOWN;
		}
	}

	/* Build a principal structure out of the user's login. */
	if (RC_OK) {
		krc = krb5_parse_name(context, user, &principal);
		if (krc != KRB5_SUCCESS) {
			CRIT("%s", error_message(krc));
		}
	}

	/* Build a principal structure out of the password-changing
	 * service's name. */
	if (RC_OK) {
		krc = krb5_parse_name(context, PASSWORD_CHANGING_SERVICE,
				      &server);
		if (krc != KRB5_SUCCESS) {
			CRIT("%s", error_message(krc));
		}
	}

	/* Read the old password.  It's okay if this fails. */
	if (RC_OK) {
		pam_get_item(pamh, PAM_OLDAUTHTOK, (const void**) &old_authtok);
		pam_get_item(pamh, PAM_AUTHTOK, (const void**) &authtok);
	}

	/* flush out the case where the user has no Kerberos principal, and
	   avoid a spurious, potentially confusing password prompt */
	if (RC_OK) {
		krc = krb5_get_init_creds_password(context,
						   &creds,
						   principal,
						   (char*)user,
						   NULL,
						   NULL,
						   0,
						   PASSWORD_CHANGING_SERVICE,
						   &config->creds_opt);
		if (krc == KRB5_SUCCESS) {
			DEBUG("user exists, but users's password is equal to "
			      "user's name -- this should be changed");
		} else {
			if (krc == KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN) {
				DEBUG("user does not have a Kerberos "
				      "principal");
				prc = PAM_USER_UNKNOWN;
			} else
			if (krc == KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN) {
				DEBUG("password-changing service does not "
				      "exist?!?!?");
				prc = PAM_SYSTEM_ERR;
			} else {
				krc = PAM_SUCCESS;
			}
		}
	}

	/* We have two cases we have to deal with.  The first: check auth. */
	if (RC_OK && (flags & PAM_PRELIM_CHECK)) {
		if ((old_authtok == NULL) || (strlen(old_authtok) == 0)) {
			DEBUG("prompting for current password");
			prc = pam_prompt_for(pamh,
					     PAM_PROMPT_ECHO_OFF,
					     current_pass,
					     &old_authtok);
			if (RC_OK) {
				pam_set_item(pamh,
					     PAM_OLDAUTHTOK,
					     (const void*)old_authtok);
			} else {
				prc = PAM_AUTHTOK_RECOVERY_ERR;
				INFO("can't read current password for %s: %d "
				     "(%s)", user, prc,
				     pam_strerror(pamh, prc));
			}
		}
		if (RC_OK) {
			krc = krb5_get_init_creds_password(context,
							   &creds,
							   principal,
							   (char*)old_authtok,
							   NULL,
							   NULL,
							   0,
							   PASSWORD_CHANGING_SERVICE,
							   &config->creds_opt);
			if (krc == KRB5_SUCCESS) {
				DEBUG("%s cleared for password change", user);
			} else {
				INFO("can't change password for %s: %d (%s)",
				     user, krc, error_message(krc));
			}
		}
	}

	/* The second one is a bit messier. */
	if (RC_OK && (flags & PAM_UPDATE_AUTHTOK)) {
		DEBUG("attempting to change password for %s", user);

		if ((old_authtok == NULL) || (strlen(old_authtok) == 0)) {
			DEBUG("prompting for current password");
			prc = pam_prompt_for(pamh,
					     PAM_PROMPT_ECHO_OFF,
					     current_pass,
					     &old_authtok);
			if (prc != PAM_SUCCESS) {
				INFO("error in conversation: %s",
				     pam_strerror(pamh, prc));
				prc = PAM_AUTHTOK_RECOVERY_ERR;
			}
		}
		/* DEBUG("old_authtok = `%s'", old_authtok); FIXME */

		if (RC_OK && ((authtok == NULL) || (strlen(authtok) == 0)) &&
		   !config->use_authtok) {
			char *authtok2 = NULL;

			DEBUG("prompting for new password (1)");
			prc = pam_prompt_for(pamh,
					     PAM_PROMPT_ECHO_OFF,
					     new_pass,
					     &authtok);
			if (RC_OK) {
				DEBUG("prompting for new password (2)");
				prc = pam_prompt_for(pamh,
						     PAM_PROMPT_ECHO_OFF,
						     retype_pass,
						     &authtok2);
				if (prc != PAM_SUCCESS) {
					INFO("error in conversation: %s",
					     pam_strerror(pamh, prc));
					prc = PAM_AUTHTOK_ERR;
				}
			}
			if (RC_OK) {
				if (strcmp(authtok, authtok2) != 0) {
					pam_prompt_for(pamh,
						       PAM_ERROR_MSG,
						       "passwords do not match",
						       NULL);
					prc = PAM_TRY_AGAIN;
				} else {
					pam_set_item(pamh,
						     PAM_AUTHTOK,
						     (const void*) authtok);
				}
			}
		}
		/* DEBUG("authtok = `%s'", authtok); FIXME */
		if (RC_OK && ((authtok == NULL) || (strlen(authtok) == 0))) {
			prc = PAM_AUTHTOK_ERR;
		}

		if (RC_OK) {
			memset(&creds, 0, sizeof(creds));
			creds.client = principal;
			creds.server = server;
			krc = krb5_get_init_creds_password(context,
							   &creds,
							   principal,
							   (char*)old_authtok,
							   NULL,
							   NULL,
							   0,
							   PASSWORD_CHANGING_SERVICE,
							   &config->creds_opt);
			if (krc == KRB5_SUCCESS) {
				DEBUG("%s prepared for password change", user);
			} else {
				INFO("can't change password for %s: %d (%s)",
				     user, krc, error_message(krc));
			}
		}
		if (RC_OK) {
			krc = krb5_change_password(context,
						   &creds,
						   authtok,
						   &result_code,
						   &result_code_string,
						   &result_string);
			if ((krc == KRB5_SUCCESS) &&
			   (result_code == KRB5_KPASSWD_SUCCESS)) {
				INFO("%s's %s password has been changed",
				     user, config->banner);
			} else {
				INFO("changing %s's %s password failed: %*s "
				     "(%d: %*s)",
				     user, config->banner,
				     result_string.length,
				     result_string.data,
				     result_code,
				     result_code_string.length,
				     result_code_string.data);
			}
		}
	}

	if (prc == PAM_SUCCESS) {
		prc = convert_kerror(krc);
	}

	/* Clean up and return. */
	if (context != NULL) {
		krb5_free_context(context);
	}
	DEBUG("pam_sm_chauthtok() returning %d (%s)",
	      prc, pam_strerror(pamh, prc));
	return prc;
}

#ifdef MAIN
/* Don't actually run this.  This function is only here for helping to ensure
 * that all necessary libraries are included at link-time, and will probably
 * crash messily if you actually try to run it. */
int
main(int argc, char **argv)
{
	pam_sm_authenticate(NULL, 0, 0, NULL);
	pam_sm_setcred(NULL, 0, 0, NULL);
	pam_sm_acct_mgmt(NULL, 0, 0, NULL);
	pam_sm_open_session(NULL, 0, 0, NULL);
	pam_sm_chauthtok(NULL, 0, 0, NULL);
	pam_sm_close_session(NULL, 0, 0, NULL);
	return 0;
}
#endif
