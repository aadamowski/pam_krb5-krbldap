/*******************************************************************************
 A module for Linux-PAM to do Kerberos 5 authentication, convert the
 Kerberos 5 ticket to a Kerberos 4 ticket, and use it to grab AFS
 tokens for specified cells if possible.

 Copyright 2000,2001 Red Hat, Inc.
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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#endif
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif
#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif

/******************************************************************************/

#ifdef HAVE_COM_ERR_H
#include <com_err.h>
#endif

#ifdef HAVE_KRB5_H
#include <krb5.h>
#endif

#ifdef HAVE_KERBEROSIV_KRB_H
#include <kerberosIV/krb.h>
#endif

#ifdef AFS
#ifdef HAVE_KRBAFS_H
#include <krbafs.h>
#define MODULE_NAME "pam_krb5afs"
#else /* HAVE_KRBAFS_H */
#define MODULE_NAME "pam_krb5"
#endif /* HAVE_KRBAFS_H */
#else /* AFS */
#define MODULE_NAME "pam_krb5"
#endif /* AFS */

#ifdef HAVE_KADM5_ADMIN_H
#include <kadm5/admin.h>
#else
#define KADM5_STRUCT_VERSION	0x12345601
#define KADM5_API_VERSION_2	0x12345702
#endif

#ifndef KRB5_SUCCESS
#define KRB5_SUCCESS 0
#endif

#ifndef PASSWORD_CHANGE_SERVICE
#ifdef  KADM5_CHANGEPW_SERVICE
#define PASSWORD_CHANGE_SERVICE KADM5_CHANGEPW_SERVICE
#else
#define PASSWORD_CHANGE_SERVICE "kadmin/changepw"
#endif
#endif

#define MODULE_STASH_NAME MODULE_NAME "_cred_stash"
#define MODULE_RET_NAME MODULE_NAME "_ret_stash"

#define PAM_SM_AUTH
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

#define APPDEFAULT_APP	"pam"
#define DEFAULT_SERVICE	"host"
#define DEFAULT_KEYTAB	"/etc/krb5.keytab"
#define DEFAULT_LIFE	"36000"
#define DEFAULT_TKT_DIR	"/tmp"

#ifndef TRUE
#define FALSE 0
#define TRUE !FALSE
#endif

#define RC_OK ((krc == KRB5_SUCCESS) && (prc == PAM_SUCCESS))

#ifdef HAVE_LIBKRB524
extern int krb524_convert_creds_kdc(krb5_context, krb5_creds *, CREDENTIALS *);
#endif

/******************************************************************************/

/* Authentication. */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
				   const char **argv);

/* Credential management. */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
			      const char **argv);

/* Session management. */
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
				   const char **argv);

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
				    const char **argv);
    
/* Password-setting. */
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags,
                                int argc, const char **argv);

/******************************************************************************/

#define DEBUG if((config == NULL) || (config->debug)) dEBUG

/* User credentials. */
struct stash {
	uid_t uid;
	gid_t gid;
	char v5_path[PATH_MAX];
	char v4_path[PATH_MAX];
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
	int no_user_check;
	int validate;
	krb5_get_init_creds_opt creds_opt;
	long ticket_lifetime;
	long renew_lifetime;
	char *banner;
	char **cell_list;
	char *realm;
	char *required_tgs;
	char *ccache_dir;
	char *keytab;
};

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
CRIT(const char *x,...) {
	char buf[LINE_MAX];
	va_list a;
	va_start(a,x);
	vsnprintf(buf, sizeof(buf), x, a);
	va_end(a);
	syslog(LOG_CRIT, MODULE_NAME ": %s", buf);
}

#include "krb5conf.l.c"

static int
num_words(const char *s)
{
	int i, ret = 0;
	for(i = 0; s && (s[i] != '\0'); i++) {
		if(!isspace(s[i]) && (isspace(s[i+1]) || (s[i+1]=='\0'))) ret++;
	}
	return ret;
}

static const char *
nth_word(const char *s, int w)
{
	int i = 0, l = FALSE;
	for(i = 0; (s[i] != '\0') && (w > 0); i++) {
		if(l && !isspace(s[i + 1])) w--;
		l = isspace(s[i]);
		if(w == 0) break;
	}
	if(w == 0) {
		return &s[i];
	} else {
		return "";
	}
}

static char *
word_copy(const char *s)
{
	int i = 0, j = 0;
	char *ret = NULL;
	while((s[i] != '\0') && isspace(s[i])) i++;
	j = i;
	while((s[j] != '\0') && !isspace(s[j])) j++;
	ret = malloc(j - i + 1);
	if(ret != NULL) {
		memcpy(ret, &s[i], j - i);
		ret[j - i] = '\0';
	}
	return ret;
}

static int
xstrnlen(const char *str, int max_len)
{
	int i;
	for(i = 0; i < max_len; i++) {
		if(str[i] == '\0') {
			return i;
		}
	}
	return -1;
}

/* Attempt to open a possibly-pre-existing file in such a way that we can
 * write to it safely. */
static int
safe_create(struct config *config, const char *filename)
{
	struct stat ost, nst;
	int fd = -1, rc = -1, preexisting;

	rc = lstat(filename, &ost);
	preexisting = (rc == 0);
	if((rc == 0) || ((rc == -1) && (errno != ENOENT))) {
		errno = 0;
		fd = open(filename, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
	} else {
		return -1;
	}

	if(fd == -1) {
		NOTICE("error opening `%s': %s",
		       filename, strerror(errno));
		return -1;
	}

	rc = fstat(fd, &nst);
	if(rc == -1) {
		NOTICE("error getting information about `%s': %s",
		       filename, strerror(errno));
		close(fd);
		return -1;
	}

	if(preexisting) {
		if((ost.st_dev != nst.st_dev) ||
		   (ost.st_ino != nst.st_ino)) {
			NOTICE("sanity test failed for `%s': %s",
			       filename, strerror(errno));
			close(fd);
			return -1;
		}
	}

	if(!S_ISREG(nst.st_mode)) {
		NOTICE("`%s' is not a regular file", filename);
		close(fd);
		return -1;
	}

	if(nst.st_nlink > 1) {
		NOTICE("`%s' has too many hard links", filename);
		close(fd);
		return -1;
	}

	ftruncate(fd, 0);

	return fd;
}

/* Yes, this is very messy.  But the kerberos libraries will nuke any
 * temporary file we supply and create a new one, so keeping a file
 * handle around and fchown()ing it won't work. */
static int
safe_fixup(struct config *config, const char *filename, struct stash *stash)
{
	struct stat ost, nst;
	int rc, fd;

	rc = lstat(filename, &ost);
	if(rc == -1) {
		NOTICE("error getting information about `%s': %s",
		       filename, strerror(errno));
		return PAM_SYSTEM_ERR;
	}

	fd = open(filename, O_RDWR);

	if(fd == -1) {
		NOTICE("error opening `%s': %s", filename, strerror(errno));
		return PAM_SYSTEM_ERR;
	}

	rc = fstat(fd, &nst);
	if(rc == -1) {
		NOTICE("error getting information about `%s': %s",
		       filename, strerror(errno));
		close(fd);
		return PAM_SYSTEM_ERR;
	}

	if((ost.st_dev != nst.st_dev) ||
	   (ost.st_ino != nst.st_ino)) {
		NOTICE("sanity test failed for `%s': %s",
		       filename, strerror(errno));
		close(fd);
		return PAM_SYSTEM_ERR;
	}

	if(!S_ISREG(nst.st_mode)) {
		NOTICE("`%s' is not a regular file", filename);
		close(fd);
		return PAM_SYSTEM_ERR;
	}

	if(nst.st_nlink > 1) {
		NOTICE("`%s' has too many hard links", filename);
		close(fd);
		return PAM_SYSTEM_ERR;
	}

	DEBUG("setting ownership on `%s' to %d/%d", filename,
	      stash->uid, stash->gid);
	rc = fchown(fd, stash->uid, stash->gid);
	if((rc == -1) && (geteuid() == 0)) {
		CRIT("`%s' setting owner of ccache",
		     strerror(errno));
		close(fd);
		return PAM_SYSTEM_ERR;
	}

	DEBUG("setting permissions on `%s' to %d/%d", filename,
	      S_IRUSR | S_IWUSR);
	rc = fchmod(fd, S_IRUSR | S_IWUSR);
	if(rc == -1) {
		CRIT("`%s' setting mode of ticket file",
		     strerror(errno));
		close(fd);
		return PAM_SYSTEM_ERR;
	}

	close(fd);

	return PAM_SUCCESS;
}

static void
appdefault_string(krb5_context context, const char *option,
		  const char *default_value, char ** ret_value)
{
	int found = FALSE;
	const char *tmp;
	tmp = xkrb5_conf_read(option);
	if(tmp) {
		*ret_value = strdup(tmp);
		found = TRUE;
	}
#ifdef HAVE_KRB5_APPDEFAULT_STRING
	if(!found) {
		krb5_appdefault_string(context, APPDEFAULT_APP, NULL,
				       option, default_value, ret_value);
		found = TRUE;
	}
#endif
	if(!found) {
		*ret_value = strdup(default_value);
	}
}

static void
appdefault_boolean(krb5_context context, const char *option,
		   int default_value, int *ret_value)
{
	int found = FALSE;
	const char *tmp;
	tmp = xkrb5_conf_read(option);
	if(tmp) {
		if(!strcasecmp(tmp, "FALSE") ||
		   !strcasecmp(tmp, "OFF") ||
		   !strcasecmp(tmp, "NO")) {
			*ret_value = FALSE;
			found = TRUE;
		}
		if(!strcasecmp(tmp, "TRUE") ||
		   !strcasecmp(tmp, "ON") ||
		   !strcasecmp(tmp, "YES")) {
			*ret_value = TRUE;
			found = TRUE;
		}
	}
#ifdef HAVE_KRB5_APPDEFAULT_BOOLEAN
	if(!found) {
		krb5_appdefault_boolean(context, APPDEFAULT_APP, NULL,
					option, default_value, ret_value);
		found = TRUE;
	}
#endif
	if(!found) {
		*ret_value = default_value;
	}
}

static struct config *
get_config(krb5_context context, int argc, const char **argv)
{
	int i, j;
	struct config *ret = NULL, *config;
	char *foo, *hosts;
#ifdef AFS
	char *cells;
#endif
	krb5_address **addresses = NULL;
	krb5_address **hostlist;
	char tgsname[LINE_MAX] = DEFAULT_SERVICE "/";

	xkrb5_conf_parse_file();

	/* Defaults: try everything (try_first_pass, use a PAG, no debug). */
	ret = malloc(sizeof(struct config));
	if(ret == NULL) {
		return NULL;
	}
	config = ret;

	memset(ret, 0, sizeof(struct config));
	krb5_get_init_creds_opt_init(&ret->creds_opt);
	ret->try_first_pass = 1;
	ret->try_second_pass = 1;

	/* Whether or not to debug via syslog. */
	appdefault_boolean(context, "debug", ret->debug, &ret->debug);
	for(i = 0; i < argc; i++) {
		if(strcmp(argv[i], "debug") == 0) {
			ret->debug = 1;
		}
	}
	DEBUG("get_config() called");
			    
	/* The local realm. */
	krb5_get_default_realm(context, &ret->realm);

	/* Renewable lifetime. */
	appdefault_string(context, "renew_lifetime", DEFAULT_LIFE, &foo);
	ret->renew_lifetime = atol(foo);
	DEBUG("setting renewable lifetime to %d", ret->renew_lifetime);
	krb5_get_init_creds_opt_set_renew_life(&ret->creds_opt,
					       ret->renew_lifetime);

	/* Ticket lifetime. */
	appdefault_string(context, "ticket_lifetime", DEFAULT_LIFE, &foo);
	ret->ticket_lifetime = atol(foo);
	DEBUG("setting ticket lifetime to %d", ret->ticket_lifetime);
	krb5_get_init_creds_opt_set_tkt_life(&ret->creds_opt,
					     ret->ticket_lifetime);

	/* Forwardable? */
	appdefault_boolean(context, "forwardable", TRUE, &i);
	if(i) {
		DEBUG("making tickets forwardable");
		krb5_get_init_creds_opt_set_forwardable(&ret->creds_opt, TRUE);
	} else {
		DEBUG("making tickets non-forwardable");
		krb5_get_init_creds_opt_set_forwardable(&ret->creds_opt, FALSE);
	}

	/* Hosts to get tickets for. */
	appdefault_string(context, "hosts", "", &hosts);

	/* Get the addresses of local interfaces, and count them. */
	krb5_os_localaddr(context, &hostlist);
	for(j = 0; hostlist[j] != NULL; j++) ;

	/* Allocate enough space for all of these, plus one for the NULL. */
	addresses = malloc(sizeof(krb5_address) * (num_words(hosts) + 1 + j));
	if(addresses == NULL) {
		free(ret);
		return NULL;
	}

	/* Set the address list. */
	memset(addresses, 0, sizeof(krb5_address) * (num_words(hosts) + 1 + j));
	for(j = 0; hostlist[j] != NULL; j++) {
		addresses[j] = hostlist[j];
	}
	for(i = 0; i < num_words(hosts); i++) {
		foo = word_copy(nth_word(hosts, i));
		if(foo == NULL) {
			free(ret);
			return NULL;
		}
		krb5_os_hostaddr(context, foo, &hostlist);
		DEBUG("also getting ticket for host `%s'", foo);
		addresses[i + j] = hostlist[0];
	}
	krb5_get_init_creds_opt_set_address_list(&ret->creds_opt, addresses);

	/* Which directory to put ticket files in. */
	appdefault_string(context, "ccache_dir", "/tmp", &ret->ccache_dir);
	DEBUG("ticket directory set to `%s'", ret->ccache_dir);

	/* What to say we are when changing passwords. */
	appdefault_string(context, "banner", "Kerberos", &ret->banner);
	DEBUG("password-changing banner set to `%s'", ret->banner);

	/* Whether to get krb4 tickets using krb524convertcreds() or
	 * a v4 TGT request. */
	appdefault_boolean(context, "krb4_convert", FALSE, &ret->krb4_convert);
	DEBUG("krb4_convert %s", ret->krb4_convert ? "true" : "false");

	/* Whether to validate TGTs or not. */
	appdefault_boolean(context, "validate", FALSE, &ret->validate);
	DEBUG("validate %s", ret->validate ? "true" : "false");

#ifdef AFS
	/* Cells to get tokens for. */
	appdefault_string(context, "afs_cells", "", &cells);
	ret->cell_list = malloc(sizeof(char*) * (num_words(cells) + 1));
	if(ret->cell_list == NULL) {
		free(ret);
		return NULL;
	}
	memset(ret->cell_list, 0, sizeof(char*) * (num_words(cells) + 1));
	for(i = 0; i < num_words(cells); i++) {
		ret->cell_list[i] = word_copy(nth_word(cells, i));
		if(ret->cell_list[i] == NULL) {
			free(ret);
			return NULL;
		}
		DEBUG("will afslog to cell `%s'", ret->cell_list[i]);
		if(ret->krb4_convert != TRUE) {
			ret->krb4_convert = TRUE;
			DEBUG("krb4_convert forced on");
		}
	}
	ret->get_tokens = TRUE;
#endif

	/* Get the name of a service ticket the user must be able to obtain and
	 * a keytab with the key for the service in it which we can use to
	 * decrypt the credential to make sure the KDC's response wasn't
	 * spoofed.  This is an undocumented way to do it, but it's what people
	 * do if they need to validate the TGT. */
	if(gethostname(tgsname + strlen(tgsname),
		       sizeof(tgsname) - strlen(tgsname) - 1) == -1) {
		memset(&tgsname, 0, sizeof(tgsname));
	}
	appdefault_string(context, "required_tgs", "", &ret->required_tgs);
	DEBUG("required_tgs set to `%s'", ret->required_tgs);

	/* Path to the keytab file. */
	appdefault_string(context, "keytab", "/etc/krb5.keytab", &ret->keytab);
	DEBUG("keytab file name set to `%s'", ret->keytab);

	for(i = 0; i < argc; i++) {
		/* Required argument that we don't use but need to recognize.*/
		if(strcmp(argv[i], "no_warn") == 0) {
			continue;
		}
		/* Try the first password. */
		if(strcmp(argv[i], "try_first_pass") == 0) {
			ret->try_first_pass = 1;
			continue;
		}
		/* Only try the first password. */
		if(strcmp(argv[i], "use_first_pass") == 0) {
			ret->try_second_pass = 0;
			continue;
		}
		/* Don't try the password stored in PAM_AUTHTOK. */
		if(strcmp(argv[i], "skip_first_pass") == 0) {
			ret->try_first_pass = 0;
			continue;
		}
		/* Rely exclusively on PAM_AUTHTOK for password-changing. */
		if(strcmp(argv[i], "use_authtok") == 0) {
			ret->use_authtok = 1;
			continue;
		}
		if(strcmp(argv[i], "no_user_check") == 0) {
			ret->no_user_check = 1;
			continue;
		}
#ifdef AFS
		/* Do a setcred() from inside of the auth function. */
		if((strcmp(argv[i], "get_tokens") == 0) ||
		   (strcmp(argv[i], "tokens") == 0) ||
		   (strcmp(argv[i], "force_cred") == 0)) {
			ret->setcred = 1;
			continue;
		}
#endif
	}

	return ret;
}

/* Free some memory. */
static void
cleanup(pam_handle_t *pamh, void *data, int error_status)
{
	free(data);
}

/******************************************************************************/

/* Prompt the user for a single piece of information. */
static int
pam_prompt_for(pam_handle_t *pamh, int msg_style,
	       const char *msg, const char **out)
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
	if(ret != PAM_SUCCESS) {
		CRIT("no conversation function supplied");
	}

	/* Now actually prompt the user for that information. */
	if(ret == PAM_SUCCESS) {
		ret = converse->conv(1, promptlist, &responses,
				     converse->appdata_ptr);
		if(ret == PAM_SUCCESS) {
			if(out) {
				*out = NULL;
			}
			if(responses && responses[0].resp) {
				*out = strdup(responses[0].resp);
				if(*out == NULL) {
					ret = PAM_SYSTEM_ERR;
				}
			}
		} else {
			INFO("%s in conversation function getting "
			     "info from the user", pam_strerror(pamh, ret));
		}
	}

	return ret;
}

static int
pam_prompter(krb5_context context, void *data, const char *name,
	     const char *banner, int num_prompts, krb5_prompt prompts[])
{
	int i = 0, ret = PAM_SUCCESS;
	const char *p = NULL;
	char *q = NULL, *tmp = NULL;
	for(i = 0; i < num_prompts; i++) {
		int l = strlen(prompts[i].prompt) + strlen(": ") + 1;
		q = malloc(l);
		if(q == NULL) {
			return PAM_SYSTEM_ERR;
		}
		snprintf(q, l, "%s: ", prompts[i].prompt);
		ret = pam_prompt_for(data,
				     prompts[i].hidden ?
				     PAM_PROMPT_ECHO_OFF :
				     PAM_PROMPT_ECHO_ON,
				     q, &p);
		if(ret == PAM_SUCCESS) {
			tmp = strdup(p);
			if(tmp == NULL) {
				ret = PAM_BUF_ERR;
			} else {
				prompts[i].reply->length = strlen(tmp);
				prompts[i].reply->data = tmp;
				if(prompts[i].hidden) {
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
/* Validate the TGT in stash->v5_creds using the keytab and required_tgs
 * set in config.  Return zero only if validation fails, required_tgs is
 * set, and we can read the keytab file. */
static int
verify_tgt(const char *user, krb5_context context,
	   struct config *config, struct stash *stash)
{
	krb5_keytab keytab;
	krb5_keytab_entry entry;
	krb5_principal server;
	krb5_creds st, *tgs;
	krb5_ticket *ticket;
	krb5_error_code ret;
	struct stat buf;

	/* The only non-fatal errors. */
	if((config->required_tgs == NULL) ||
	   (strlen(config->required_tgs) == 0)) {
		DEBUG("TGT not verified because required_tgs was not set");
		return 1;
	}
	if((stat(config->keytab, &buf) == -1) && (errno == ENOENT)) {
		DEBUG("TGT not verified because keytab file %s doesn't exist",
		      config->keytab);
		return 1;
	}

	/* Parse out the service name into a principal. */
	DEBUG("verifying TGT");
	ret = krb5_parse_name(context, config->required_tgs, &server);
	if(ret) {
		CRIT("error building service principal for %s: %s",
		     config->required_tgs, error_message(ret));
		return 0;
	}

	/* Try to get a service ticket. */
	memset(&st, 0, sizeof(st));
	st.client = stash->v5_creds.client;
	st.server = server;
	ret = krb5_get_cred_via_tkt(context, &stash->v5_creds, 0, NULL,
				    &st, &tgs);
	if(ret) {
		CRIT("error getting credential for %s: %s",
		     config->required_tgs, error_message(ret));
		krb5_free_principal(context, server);
		return 0;
	}

	/* Decode the service information from the ticket. */
	ret = krb5_decode_ticket(&tgs->ticket, &ticket);
	if(ret) {
		CRIT("error decoding key information for %s: %s",
		     config->required_tgs, error_message(ret));
		krb5_free_principal(context, server);
		krb5_free_creds(context, tgs);
		return 0;
	}

	/* Open the keytab. */
	ret = krb5_kt_resolve(context, config->keytab, &keytab);
	if(ret) {
		DEBUG("error trying to open %s: %s",
		      config->keytab, error_message(ret));
		krb5_free_principal(context, server);
		krb5_free_creds(context, tgs);
		krb5_free_ticket(context, ticket);
		return 0;
	}

	/* Read the key for the service. */
	ret = krb5_kt_get_entry(context, keytab, server,
				ticket->enc_part.kvno,
				ticket->enc_part.enctype,
				&entry);
	if(ret) {
		if(ret == EACCES) {
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
		return (ret == EACCES);
	}

	/* Try to decrypt the encrypted part with the key. */
	ret = krb5_decrypt_tkt_part(context, &entry.key, ticket);
	if(ret) {
		CRIT("verification error: %s",
		     error_message(ret));
	} else {
		INFO("TGT for %s successfully verified", user);
	}

	krb5_free_principal(context, server);
	krb5_free_creds(context, tgs);
	krb5_free_ticket(context, ticket);
	krb5_kt_close(context, keytab);
	krb5_kt_free_entry(context, &entry);

	return !ret;
}
#else
static int
verify_tgt(const char *user, krb5_context context,
	   struct config *config, struct stash *stash)
{
	CRIT("verification error: verification not available because "
	     "krb5_decode_ticket() not available");
	return 0;
}
#endif

/* Big authentication module. */
int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	krb5_context context;
	krb5_principal principal;
	struct config *config;
	const char *user = NULL;
	const char *password = NULL;
	char *realm, *tmp;
	int krc = KRB5_SUCCESS, prc = PAM_SUCCESS, *pret = NULL;
	struct stash *stash = NULL;
	struct passwd *pwd = NULL;

	/* First parse the arguments; if there are problems, bail. */
	initialize_krb5_error_table();
	krc = krb5_init_context(&context);
	if(krc == KRB5_SUCCESS) {
		krb5_init_ets(context);
	} else {
		prc = PAM_SYSTEM_ERR;
	}

	if(RC_OK) {
		if(!(config = get_config(context, argc, argv))) {
			prc = PAM_SYSTEM_ERR;
		}
	}

	DEBUG("pam_sm_authenticate() called");

	/* Initialize Kerberos and grab some memory for the creds structures. */
	if(RC_OK) {
		stash = malloc(sizeof(struct stash));
		if(stash != NULL) {
			memset(stash, 0, sizeof(struct stash));
			krb5_get_default_realm(context, &realm);
			DEBUG("default Kerberos realm is %s", realm);
		} else {
			prc = PAM_SYSTEM_ERR;
			CRIT("Kerberos 5 initialize problem/malloc error");
		}
	}

	/* Grab some memory for storing the value to return in a subsequent
	 * setcred() call.  We have no idea what the stack looks like, so
	 * we *have* to help guarantee that the setcred call will work in
	 * exactly the way this authenticate call did. */
	if(RC_OK) {
		pret = malloc(sizeof(prc));
		if(pret != NULL) {
			*pret = PAM_SUCCESS;
		} else {
			prc = PAM_SYSTEM_ERR;
			CRIT("Kerberos 5 initialize problem/malloc error");
		}
	}

	/* Get the user's name, by any means possible. */
	if(RC_OK) {
		/* First try the PAM library. */
		pam_get_user(pamh, &user, "login: ");

		/* If there was an error, use the conversation function. */
		if((user == NULL) || (strlen(user) == 0)) {
			DEBUG("prompting for login");
			prc = pam_prompt_for(pamh, PAM_PROMPT_ECHO_ON,
					     "login: ", &user);
			if(RC_OK) {
				pam_set_item(pamh, PAM_USER, (const void*)user);
			}
		}

		/* If we got a login from either method, use it. */
		prc = pam_get_user(pamh, &user, "login: ");
		if(prc != PAM_SUCCESS) {
			CRIT("cannot determine user's login");
			prc = PAM_USER_UNKNOWN;
		}

		if((user == NULL) || (strlen(user) == 0)) {
			CRIT("cannot determine user's login");
			prc = PAM_USER_UNKNOWN;
		}
	}
	DEBUG("user is `%s'", user);

	/* Try to get and save the user's UID. */
	if(RC_OK) {
		if(config->no_user_check) {
			stash->uid = getuid();
			stash->gid = getgid();
			DEBUG("using current uid %d, gid %d",
			      stash->uid, stash->gid);
		} else {
			pwd = getpwnam(user);
			if(pwd != NULL) {
				stash->uid = pwd->pw_uid;
				stash->gid = pwd->pw_gid;
				DEBUG("%s has uid %d, gid %d", user,
				      stash->uid, stash->gid);
			} else {
				CRIT("getpwnam() failed for the user");
				prc = PAM_USER_UNKNOWN;
			}
		}
	}

	/* Build the user's principal. */
	if(RC_OK) {
		krc = krb5_parse_name(context, user, &principal);
		if(krc != KRB5_SUCCESS) {
			CRIT("%s building user principal for %s",
			     error_message(krc), user);
			prc = PAM_SYSTEM_ERR;
		}
	}

	/* Retrieve a password that may already have been entered. */
	if(RC_OK && config->try_first_pass) {
		pam_get_item(pamh, PAM_AUTHTOK, (const void**) &password);
	} else {
		password = NULL;
	}

	/* Now try to get a TGT using the password, prompting the user if it
	   fails and we're allowed to prompt for one. */
	if(RC_OK) {
		int authenticated = FALSE;

		DEBUG("attempting to authenticate %s", user);

		/* Set up the creds structure. */
		memset(&stash->v5_creds, 0, sizeof(stash->v5_creds));

		/* Who we're representing. */
		stash->v5_creds.client = principal;

		/* If we don't have a password, and we're not configured to
		 * prompt for one, we're done. */
		if((password == NULL) &&
		   (config->try_first_pass) &&
		   (!config->try_second_pass)) {
			authenticated = TRUE;
			krc = KRB5_LIBOS_CANTREADPWD;
		}

		/* Try the password, if we have one. */
		if(config->try_first_pass && password && !authenticated) {
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
			if(krc == KRB5_SUCCESS) {
				authenticated = TRUE;
			}
		}

		/* Try to converse if the password failed. */
		if(config->try_second_pass && !authenticated) {
			password = NULL;
			pam_prompt_for(pamh, PAM_PROMPT_ECHO_OFF,
				       "Password: ", &password);
			if(password) {
				tmp = strdup(password);
				if(tmp) {
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
			if(krc == KRB5_SUCCESS) {
				authenticated = TRUE;
			}
		}

		/* Figure out where to go from here. */
		if(krc != KRB5_SUCCESS) {
			CRIT("authenticate error: %s", error_message(krc));
			prc = PAM_AUTH_ERR;
		}
	}

	/* Verify that the TGT is good (i.e., that the reply wasn't spoofed). */
	if(RC_OK) {
		if(config->validate) {
			if(verify_tgt(user, context, config, stash) == 0) {
				prc = PAM_AUTH_ERR;
			}
		}
	}

	/* Log something. */
	if(RC_OK) {
		INFO("authentication succeeds for %s", user);
	} else {
		INFO("authentication fails for %s", user);
	}

	if(RC_OK) {
		prc = pam_set_data(pamh, MODULE_STASH_NAME, stash, cleanup);
		if(prc == PAM_SUCCESS) {
			DEBUG("credentials saved for %s", user);
		} else {
			DEBUG("error saving credentials for %s", user);
		}
	}

#ifdef HAVE_LIBKRB4
	/* Get Kerberos IV credentials if we are supposed to. */
	if(RC_OK && config->krb4_convert) {
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

		if(krb5_524_conv_principal(context, principal,
					   v4name, v4inst, v4realm) == KSUCCESS) {
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
			if(k4rc != KSUCCESS) {
				INFO("couldn't get v4 TGT for %s%s%s@%s (%s), "
				     "continuing", v4name,
				     strlen(v4inst) ? ".": "", v4inst, v4realm,
				     krb_get_err_text(k4rc));
			}
			if(k4rc == KSUCCESS) {
				unsigned char *p = ciphertext->dat;
				int l;

				/* Convert the password to a v4 key. */
				des_string_to_key((char*)goodpass, key);
				des_key_sched(key, key_schedule);

				/* Decrypt the TGT. */
				des_pcbc_encrypt(ciphertext->dat,
						 ciphertext->dat,
						 ciphertext->length,
						 key_schedule,
						 key,
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
				l = ciphertext->length;
				DEBUG("ciphertext length in TGT = %d", l);

				memcpy(&stash->v4_creds.session, p, 8);
				p += 8;
				l -= 8;

				/* Service name. */
				if(xstrnlen(p, l) > 0) {
					strncpy(stash->v4_creds.service, p,
						sizeof(stash->v4_creds.service)
						- 1);
				} else {
					INFO("service name in v4 TGT too long: %.8s", p);
				}
				p += (strlen(stash->v4_creds.service) + 1);
				l -= (strlen(stash->v4_creds.service) + 1);

				/* Service instance. */
				if(xstrnlen(p, l) > 0) {
					strncpy(stash->v4_creds.instance, p,
						sizeof(stash->v4_creds.instance)
						- 1);
				}
				p += (strlen(stash->v4_creds.instance) + 1);
				l -= (strlen(stash->v4_creds.instance) + 1);

				/* Service realm. */
				if(xstrnlen(p, l) > 0) {
					strncpy(stash->v4_creds.realm, p,
						sizeof(stash->v4_creds.realm)
						- 1);
				}
				p += (strlen(stash->v4_creds.realm) + 1);
				l -= (strlen(stash->v4_creds.realm) + 1);

				/* Lifetime, kvno, length. */
				if(l >= 3) {
					stash->v4_creds.lifetime = p[0];
					stash->v4_creds.kvno = p[1];
					stash->v4_creds.ticket_st.length = p[2];
				}
				p += 3;
				l -= 3;

				/* Ticket data. */
				if(l >= stash->v4_creds.ticket_st.length) {
					memcpy(stash->v4_creds.ticket_st.dat, p,
					      stash->v4_creds.ticket_st.length);
				}
				p += stash->v4_creds.ticket_st.length;
				l -= stash->v4_creds.ticket_st.length;

				/* Timestamp. */
				if(l >= 4) {
					memcpy(&stash->v4_creds.issue_date,
					       p, 4);
					/* We can't tell if we need to byte-swap
					 * or not, so just make up an issue date
					 * that looks reasonable. */
					stash->v4_creds.issue_date = time(NULL);
				}
				p += 4;
				l -= 4;


				DEBUG("Got v4 TGT for `%s%s%s@%s'",
				      stash->v4_creds.service,
				      strlen(stash->v4_creds.instance) ?
				      "." : "",
				      stash->v4_creds.instance,
				      stash->v4_creds.realm);
				stash->have_v4_creds = TRUE;

				/* Sanity checks. */
				if(l != 0) {
					INFO("Got %d extra bytes in v4 TGT",
					     ciphertext->length - l);
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
	if(RC_OK && config->setcred) {
		pam_sm_setcred(pamh, PAM_ESTABLISH_CRED, argc, argv);
		pam_sm_setcred(pamh, PAM_DELETE_CRED, argc, argv);
	}
#endif

	/* Catch any Kerberos error codes that fall through cracks and
	   convert them to appropriate PAM error codes. */
	switch(krc) {
		case KRB5_SUCCESS:
		case KRB5KDC_ERR_NONE: {
			/* Leave the PAM error unchanged. */
			break;
		}
		case KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN:
		case KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN: {
			prc = PAM_USER_UNKNOWN;
			break;
		}
		case KRB5_REALM_UNKNOWN:
		case KRB5_SERVICE_UNKNOWN: {
			prc = PAM_SYSTEM_ERR;
			break;
		}
		default: {
			prc = PAM_AUTH_ERR;
		}
	}

	/* Done with Kerberos. */
	krb5_free_context(context);

	/* Save the return code for later use by setcred(). */
	*pret = prc;
	prc = pam_set_data(pamh, MODULE_RET_NAME, pret, cleanup);
	if(prc == PAM_SUCCESS) {
		DEBUG("saved return code (%d) for later use", *pret);
	} else {
		INFO("error %d (%s) saving return code (%d)", prc,
			pam_strerror(pamh, prc), *pret);
	}
	prc = *pret;

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
	const char *user = NULL;
	int krc = KRB5_SUCCESS, prc = PAM_SUCCESS, *pret = NULL;
	struct config *config;

	/* First parse the arguments; if there are problems, bail. */
	initialize_krb5_error_table();
	krc = krb5_init_context(&context);
	if(krc == KRB5_SUCCESS) {
		krb5_init_ets(context);
	} else {
		prc = PAM_SYSTEM_ERR;
	}
	if(RC_OK) {
		if(!(config = get_config(context, argc, argv))) {
			prc = PAM_SYSTEM_ERR;
		}
	}
	DEBUG("pam_sm_setcred() called");

	/* Retrieve information about the user. */
	if(RC_OK) {
		prc = pam_get_item(pamh, PAM_USER, &user);
	}

	if(RC_OK && (flags & (PAM_ESTABLISH_CRED | PAM_REINITIALIZE_CRED))) {
		int tmpfd = -1;

		/* Retrieve credentials and create a ccache. */
		prc = pam_get_data(pamh, MODULE_STASH_NAME, (void*)&stash);
		if(prc == PAM_SUCCESS) {
			DEBUG("credentials retrieved");

			if(strlen(stash->v5_path) == 0) {
				snprintf(v5_path, sizeof(v5_path),
					 "%s/krb5cc_%d_XXXXXX",
					 config->ccache_dir, stash->uid);
				tmpfd = mkstemp(v5_path);
				if(tmpfd != -1) {
					memset(stash->v5_path, '\0',
					       sizeof(stash->v5_path));
					strncpy(stash->v5_path, v5_path,
						sizeof(stash->v5_path) - 1);
				}
			} else {
				tmpfd = safe_create(config, stash->v5_path);
			}

			if(tmpfd == -1) {
				CRIT("%s opening ccache", strerror(errno));
				prc = PAM_SYSTEM_ERR;
			} else {
				/* Mess with the file's ownership to make
				 * libkrb happy. */
				fchown(tmpfd, getuid(), getgid());
			}
		}
		if(RC_OK) {
			/* Open the ccache via Kerberos. */
			snprintf(v5_path, sizeof(v5_path), "FILE:%s",
				 stash->v5_path);
			krc = krb5_cc_resolve(context, v5_path, &ccache);
			if(krc == KRB5_SUCCESS) {
				krc = krb5_cc_initialize(context, ccache,
						        stash->v5_creds.client);
			}
			if(krc != KRB5_SUCCESS) {
				CRIT("error initializing ccache %s for %s: "
				     "%s", v5_path, user, error_message(krc));
			}

			/* Store credentials in the cache. */
			if(krc == KRB5_SUCCESS) {
				krb5_cc_store_cred(context, ccache,
						   &stash->v5_creds);
			}

			/* Close the ccache. */
			krb5_cc_close(context, ccache);
			close(tmpfd);
			tmpfd = -1;

			/* Set the environment variable to point to the cache.*/
			snprintf(v5_path, sizeof(v5_path),
				 "KRB5CCNAME=FILE:%s", stash->v5_path);
			prc = pam_putenv(pamh, v5_path);
			if(prc != PAM_SUCCESS) {
				CRIT("%s setting environment",
				     pam_strerror(pamh, prc));
			}
			prc = putenv(v5_path);
			if(prc != PAM_SUCCESS) {
				CRIT("%s setting environment",
				     pam_strerror(pamh, prc));
			}
			DEBUG("%s", v5_path);
		} else {
			DEBUG("Kerberos 5 credential retrieval failed for "
			      "%s, user is probably local", user);
			stash = NULL;
			prc = PAM_CRED_UNAVAIL;
		}

#ifdef HAVE_LIBKRB524
		/* Get Kerberos 4 credentials if we haven't already. */
		if(RC_OK && config->krb4_convert) {
			if(!stash->have_v4_creds) {
				DEBUG("converting credentials for %s", user);

				krc = krb524_convert_creds_kdc(context,
							      &stash->v5_creds,
							      &stash->v4_creds);

				DEBUG("krb524_convert_creds returned `%s' "
				      "for %s",
				      krc ? error_message(krc) :
				      "Success", user);

				if(krc == KRB5_SUCCESS) {
					INFO("v4 ticket conversion succeeded "
					     "for %s", user);
					stash->have_v4_creds = TRUE;
				} else {
					/* This shouldn't happen.  Either krb524d isn't
					   running on the KDC or the module is
					   misconfigured, or something weirder
					   still happened: we succeeded. */
					CRIT("v4 ticket conversion failed for "
					     "%s: %d (%s)", user,
					     krc, error_message(krc));
					krc = KRB5_SUCCESS;
				}
			}
		}
#endif
#ifdef HAVE_LIBKRB4
		if(RC_OK && stash->have_v4_creds) {
			if(strlen(stash->v4_path) == 0) {
				/* Create a new ticket file. */
				snprintf(v4_path, sizeof(v4_path),
					 "%s/tkt%d_XXXXXX",
					 config->ccache_dir, stash->uid);
				tmpfd = mkstemp(v4_path);
				if(tmpfd != -1) {
					memset(stash->v4_path, '\0',
					       sizeof(stash->v4_path));
					strncpy(stash->v4_path, v4_path,
						sizeof(stash->v4_path) - 1);
				}
			} else {
				tmpfd = safe_create(config, stash->v4_path);
			}

			if(tmpfd == -1) {
				CRIT("%s opening ccache", strerror(errno));
				prc = PAM_SYSTEM_ERR;
			} else {
				/* Mess with the file's ownership to make
				 * libkrb happy. */
				fchown(tmpfd, getuid(), getgid());
			}
		}
		if(RC_OK && strlen(stash->v4_path)) {
			int save = TRUE;

			DEBUG("opening ticket file `%s'", stash->v4_path);
			krb_set_tkt_string(stash->v4_path);
			krc = in_tkt(stash->v4_creds.pname,
				     stash->v4_creds.pinst);

			if(krc != KRB5_SUCCESS) {
				CRIT("error initializing %s for %s (code = %d),"
				     " punting", stash->v4_path, user, krc);
				save = TRUE;
				krc = KRB5_SUCCESS;
			}

			/* Store credentials in the ticket file. */
			if((krc == KRB5_SUCCESS) && save) {
				DEBUG("save v4 creds (%s%s%s@%s:%d), %d",
				      stash->v4_creds.service,
				      strlen(stash->v4_creds.instance) ? "." : "",
				      stash->v4_creds.instance ? stash->v4_creds.instance : "",
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
			if(prc != PAM_SUCCESS) {
				CRIT("%s setting environment",
				     pam_strerror(pamh, prc));
			}
			prc = putenv(v4_path);
			if(prc != PAM_SUCCESS) {
				CRIT("%s setting environment",
				     pam_strerror(pamh, prc));
			}
			DEBUG(v4_path);
		}
#endif
	}

#ifdef AFS
	/* Use the new tickets to create tokens. */
	if(RC_OK && (flags & (PAM_ESTABLISH_CRED | PAM_REINITIALIZE_CRED)) &&
	   config->get_tokens && config->cell_list) {
		if(!k_hasafs()) {
			CRIT("cells specified but AFS not running");
		} else {
			int i, rc;
			/* Afslog to all of the specified cells. */
			DEBUG("k_setpag()");
			rc = k_setpag();
			DEBUG("k_setpag() returned %d", rc);
			for(i = 0; config->cell_list[i] != NULL; i++) {
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
	if(RC_OK && (flags & (PAM_ESTABLISH_CRED | PAM_REINITIALIZE_CRED)) &&
	   (strlen(stash->v5_path) > 0)) {
		prc = safe_fixup(config, stash->v5_path, stash);
	}

#ifdef HAVE_LIBKRB4
	if(RC_OK && (flags & (PAM_ESTABLISH_CRED | PAM_REINITIALIZE_CRED)) &&
	   (strlen(stash->v4_path) > 0)) {
		prc = safe_fixup(config, stash->v4_path, stash);
	}
#endif

	if(RC_OK && (flags & PAM_DELETE_CRED)) {
		prc = pam_get_data(pamh,MODULE_STASH_NAME,(const void**)&stash);
		if((prc == PAM_SUCCESS) && (strlen(stash->v5_path) > 0)) {
			DEBUG("credentials retrieved");
			/* Delete the v5 ticket cache. */
			DEBUG("removing %s", stash->v5_path);
			if(remove(stash->v5_path) == -1) {
				CRIT("error removing file %s: %s",
				     stash->v5_path, strerror(errno));
			} else {
				strcpy(stash->v5_path, "");
			}
		}
#ifdef HAVE_LIBKRB4
		if((prc == PAM_SUCCESS) && (strlen(stash->v4_path) > 0)) {
			/* Delete the v4 ticket cache. */
			DEBUG("removing %s", stash->v4_path);
			if(remove(stash->v4_path) == -1) {
				CRIT("error removing file %s: %s",
				     stash->v4_path, strerror(errno));
			} else {
				strcpy(stash->v4_path, "");
			}
		}
#endif
#ifdef AFS
		/* Clear tokens unless we need them. */
		if(!config->setcred && k_hasafs()) {
			DEBUG("destroying tokens");
			k_unlog();
		}
#endif
	}

	/* Done with Kerberos. */
	krb5_free_context(context);

	pam_get_data(pamh, MODULE_RET_NAME, (const void**) &pret);
	if(pret) {
		DEBUG("recovered return code %d from prior call to "
		      "pam_sm_authenticate()", *pret);
		prc = *pret;
	}

	DEBUG("pam_sm_setcred returning %d (%s)", prc,
	      (prc != PAM_SUCCESS) ? pam_strerror(pamh, prc) : "Success");

	return prc;
}

/******************************************************************************/

int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct config *config;
	krb5_context context = NULL;
	int ret;

	if(krb5_init_context(&context) != KRB5_SUCCESS) {
		ret = PAM_SYSTEM_ERR;
	}
	if(ret == KRB5_SUCCESS) {
		if(!(config = get_config(context, argc, argv))) {
			ret = PAM_SYSTEM_ERR;
		}
	}
	DEBUG("pam_sm_open_session() called");
	if(context) krb5_free_context(context);

	return pam_sm_setcred(pamh, flags | PAM_ESTABLISH_CRED, argc, argv);
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
			 const char **argv)
{
	struct config *config;
	krb5_context context = NULL;
	int ret;

	if(krb5_init_context(&context) != KRB5_SUCCESS) {
		ret = PAM_SYSTEM_ERR;
	}
	if(ret == KRB5_SUCCESS) {
		if(!(config = get_config(context, argc, argv))) {
			ret = PAM_SYSTEM_ERR;
		}
	}
	DEBUG("pam_sm_close_session() called");
	if(context) krb5_free_context(context);

	return pam_sm_setcred(pamh, flags | PAM_DELETE_CRED, argc, argv);
}

int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	krb5_context context = NULL;
	krb5_principal principal;
	void *kadm5_handle = NULL;
	const char *user = NULL, *authtok = NULL, *old_authtok = NULL;
	char current_pass[LINE_MAX], new_pass[LINE_MAX], retype_pass[LINE_MAX];
	struct config *config;
	int ret = PAM_SUCCESS;

	/* Initialize Kerberos. */
	initialize_krb5_error_table();
	initialize_ovk_error_table();
	if(krb5_init_context(&context) != KRB5_SUCCESS) {
		ret = PAM_SYSTEM_ERR;
	}
	if(ret == KRB5_SUCCESS) {
		if(!(config = get_config(context, argc, argv))) {
			ret = PAM_SYSTEM_ERR;
		}
	}
	DEBUG("pam_sm_chauthtok() called");

	/* Initialize prompt strings. */
	snprintf(current_pass, sizeof(current_pass), "Current %s password: ",
		 (config && config->banner) ? config->banner : "");
	snprintf(new_pass, sizeof(new_pass), "New %s password: ",
		 (config && config->banner) ? config->banner : "");
	snprintf(retype_pass, sizeof(retype_pass), "Retype new %s password: ",
		 (config && config->banner) ? config->banner : "");

	/* Figure out who the user is. */
	if(ret == KRB5_SUCCESS) {
		ret = pam_get_user(pamh, &user, "login: ");
		if(ret != PAM_SUCCESS) {
			INFO("couldn't determine user");
			ret = PAM_USER_UNKNOWN;
		}
	}

	/* Build a principal structure out of the user's login. */
	if(ret == KRB5_SUCCESS) {
		ret = krb5_parse_name(context, user, &principal);
		if(ret != KRB5_SUCCESS) {
			CRIT("%s", error_message(ret));
		}
	}

	/* Read the old password.  It's okay if this fails. */
	if(ret == KRB5_SUCCESS) {
		pam_get_item(pamh, PAM_OLDAUTHTOK, (const void**) &old_authtok);
		pam_get_item(pamh, PAM_AUTHTOK, (const void**) &authtok);
	}

	/* flush out the case where the user has no Kerberos principal, and
	   avoid a spurious, potentially confusing password prompt */
	if(ret == KRB5_SUCCESS) {
		kadm5_handle = NULL;
		ret = kadm5_init_with_password(user,
					       user,
					       PASSWORD_CHANGE_SERVICE,
					       NULL,
					       KADM5_STRUCT_VERSION,
					       KADM5_API_VERSION_2,
					       &kadm5_handle);
		if(ret == KRB5_SUCCESS) {
			DEBUG("connected to kadmin server with user's name as "
			      "password -- should have a stronger password");
			kadm5_destroy(kadm5_handle);
		} else {
			if(ret == KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN) {
				DEBUG("user does not have a Kerberos "
				      "principal");
				ret = PAM_USER_UNKNOWN;
			} else
			if(ret == KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN) {
				DEBUG("password-changing service does "
				      "not exist?!?!?");
				ret = PAM_SYSTEM_ERR;
			} else {
				ret = PAM_SUCCESS;
			}
		}
	}

	/* We have two cases we have to deal with.  The first: check auth. */
	if((ret == KRB5_SUCCESS) && (flags & PAM_PRELIM_CHECK)) {
		if((old_authtok == NULL) || (strlen(old_authtok) == 0)) {
			DEBUG("prompting for current password");
			ret = pam_prompt_for(pamh, PAM_PROMPT_ECHO_OFF,
					     current_pass,
					     &old_authtok);
			if(ret == KRB5_SUCCESS) {
				pam_set_item(pamh, PAM_OLDAUTHTOK,
					     (const void*)old_authtok);
			} else {
				ret = PAM_AUTHTOK_RECOVERY_ERR;
				INFO("can't read current password for %s: %d (%s)",
				     user, ret, pam_strerror(pamh, ret));
			}
		}
		if(ret == KRB5_SUCCESS) {
			kadm5_handle = NULL;
			ret = kadm5_init_with_password(user,
						       old_authtok,
						       PASSWORD_CHANGE_SERVICE,
						       NULL,
						       KADM5_STRUCT_VERSION,
						       KADM5_API_VERSION_2,
						       &kadm5_handle);
			if(ret == KRB5_SUCCESS) {
				DEBUG("%s cleared for password change", user);
				kadm5_destroy(kadm5_handle);
			} else {
				INFO("can't change password for %s: %d (%s)",
				     user, ret, error_message(ret));
			}
		}
	}

	/* The second one is a bit messier. */
	if((ret == KRB5_SUCCESS) && (flags & PAM_UPDATE_AUTHTOK)) {
		DEBUG("attempting to change password for %s", user);

		if((old_authtok == NULL) || (strlen(old_authtok) == 0)) {
			DEBUG("prompting for current password");
			ret = pam_prompt_for(pamh, PAM_PROMPT_ECHO_OFF,
					     current_pass,
					     &old_authtok);
			if(ret != PAM_SUCCESS) {
				INFO("error in conversation: %s",
				     error_message(ret));
				ret = PAM_AUTHTOK_RECOVERY_ERR;
			}
		}
		/* DEBUG("old_authtok = `%s'", old_authtok); */

		if(((authtok == NULL) || (strlen(authtok) == 0)) &&
		   !config->use_authtok) {
			const char *authtok2 = NULL;

			DEBUG("prompting for new password (1)");
			ret = pam_prompt_for(pamh, PAM_PROMPT_ECHO_OFF,
					     new_pass, &authtok);
			if(ret == KRB5_SUCCESS) {
				DEBUG("prompting for new password (2)");
				ret = pam_prompt_for(pamh, PAM_PROMPT_ECHO_OFF,
						   retype_pass, &authtok2);
				if(ret != PAM_SUCCESS) {
					INFO("error in conversation: %s",
					     error_message(ret));
					ret = PAM_AUTHTOK_ERR;
				}
			}
			if(ret == KRB5_SUCCESS) {
				if(strcmp(authtok, authtok2) != 0) {
					pam_prompt_for(pamh, PAM_ERROR_MSG,
						     "passwords do not match",
						     NULL);
					ret = PAM_TRY_AGAIN;
				} else {
					pam_set_item(pamh, PAM_AUTHTOK,
						     (const void*) authtok);
				}
			}
		}
		/* DEBUG("authtok = `%s'", authtok); */

		if(ret == KRB5_SUCCESS) {
			kadm5_handle = NULL;
			ret = kadm5_init_with_password(user,
						       old_authtok,
						       PASSWORD_CHANGE_SERVICE,
						       NULL,
						       KADM5_STRUCT_VERSION,
						       KADM5_API_VERSION_2,
						       &kadm5_handle);
			if(ret == KRB5_SUCCESS) {
				DEBUG("connected to kadmin server");
			} else {
				INFO("error in kadm5_init: %d (%s)", ret,
				     error_message(ret));
			}
		}

		if(ret == KRB5_SUCCESS) {
			ret = kadm5_chpass_principal(kadm5_handle,
						     principal,
						     authtok);
			if(ret == KRB5_SUCCESS) {
				INFO("%s's %s password has been changed", user,
				     config->banner);
			} else {
				INFO("changing %s's %s password failed",
				     user, config->banner);
			}
			kadm5_destroy(kadm5_handle);
		}
	}

	/* Catch a few Kerberos error codes and convert to PAM equivalents. */
	switch(ret) {
		case KRB5_SUCCESS:
		case KRB5KDC_ERR_NONE: {
			break;
		}
		case KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN:
		case KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN: {
			ret = PAM_USER_UNKNOWN;
			break;
		}
		case KRB5_REALM_UNKNOWN:
		case KRB5_SERVICE_UNKNOWN: {
			ret = PAM_SYSTEM_ERR;
			break;
		}
		case KRB5KRB_AP_ERR_BAD_INTEGRITY: {
			ret = PAM_PERM_DENIED;
		}
		case PAM_TRY_AGAIN:
		case PAM_USER_UNKNOWN: {
			break;
		}
		default: {
			ret = PAM_AUTH_ERR;
		}
	}

	/* Clean up and return. */
	if(context) krb5_free_context(context);
	return ret;
}

#ifdef MAIN
/* Don't actually run this.  This function is only here for helping to ensure
   that all necessary libraries are included at link-time, and will probably
   segfault all over the place if you actually try to run it. */
int
main(int argc, char **argv)
{
	pam_sm_authenticate(NULL, 0, 0, NULL);
	pam_sm_setcred(NULL, 0, 0, NULL);
	pam_sm_open_session(NULL, 0, 0, NULL);
	pam_sm_chauthtok(NULL, 0, 0, NULL);
	pam_sm_close_session(NULL, 0, 0, NULL);
	return 0;
}
#endif
