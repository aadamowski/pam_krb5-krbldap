/*******************************************************************************
 Module for Linux-PAM to do Kerberos 5 authentication, convert the
 Kerberos 5 ticket to a Kerberos 4 ticket, and use it to grab AFS
 tokens for specified cells.

 Copyright 1999 Nalin Dahyabhai <nalin.dahyabhai@pobox.com>
 Distribution allowed under the X consortium license or the LGPL.
 Do me a favor and let me know if you're using it.
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

#ifdef HAVE_KRBAFS_H
#include <krbafs.h>
#endif

#ifndef KRB5_SUCCESS
#define KRB5_SUCCESS 0
#endif

#ifndef PASSWORD_CHANGE_SERVICE
#define PASSWORD_CHANGE_SERVICE "kadmin/changepw"
#endif

#define MODULE_NAME "pam_krb5afs"
#define MODULE_DATA_NAME "pam_krb5afs_module_data"

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

#define PROFILE_NAME "pam"
#define DEFAULT_CELLS "eos.ncsu.edu unity.ncsu.edu bp.ncsu.edu"
#define DEFAULT_LIFE 36000

#ifndef TRUE
#define FALSE 0
#define TRUE !FALSE
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

#define DEBUG if(config->debug) dEBUG

/* User credentials. */
struct stash {
	uid_t uid;
	gid_t gid;
	krb5_creds v5_creds;
};

/* Module-specific configuration data. */
struct config {
	unsigned char debug;
	unsigned char get_tokens;
	unsigned char try_first_pass;
	unsigned char try_second_pass;
	unsigned char use_authtok;
	unsigned char krb4_convert;
	unsigned char setcred;
	krb5_get_init_creds_opt creds_opt;
	int lifetime;
	char *banner;
	char **cell_list;
	char *realm;
	char *required_tgs;
};

static void dEBUG(const char *x,...) {
	char buf[LINE_MAX];
	va_list a;
	va_start(a,x);
	vsnprintf(buf, sizeof(buf), x, a);
	va_end(a);
	syslog(LOG_DEBUG, "%s", buf);
}
#if 0
static void NOTICE(const char *x,...) {
	char buf[LINE_MAX];
	va_list a;
	va_start(a,x);
	vsnprintf(buf, sizeof(buf), x, a);
	va_end(a);
	syslog(LOG_NOTICE, "%s", buf);
}
#endif
static void INFO(const char *x,...) {
	char buf[LINE_MAX];
	va_list a;
	va_start(a,x);
	vsnprintf(buf, sizeof(buf), x, a);
	va_end(a);
	syslog(LOG_INFO, "%s", buf);
}
static void CRIT(const char *x,...) {
	char buf[LINE_MAX];
	va_list a;
	va_start(a,x);
	vsnprintf(buf, sizeof(buf), x, a);
	va_end(a);
	syslog(LOG_CRIT, "%s", buf);
}

static int num_words(const char *s)
{
	int i, ret = 0;
	for(i = 0; s[i] != '\0'; i++) {
		if(!isspace(s[i]) && (isspace(s[i+1]) || (s[i+1]=='\0'))) ret++;
	}
	return ret;
}

static const char *nth_word(const char *s, int w)
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

static char *word_copy(const char *s)
{
	int i = 0, j = 0;
	char *ret = NULL;
	while((s[i] != '\0') && isspace(s[i])) i++;
	j = i;
	while((s[j] != '\0') && !isspace(s[j])) j++;
	ret = malloc(j - i + 1);
	memcpy(ret, &s[i], j - i);
	ret[j - i] = '\0';
	return ret;
}

struct config *get_config(krb5_context context, int argc, const char **argv)
{
	int i, j;
	struct config *ret = NULL;
	char *foo, *cells;
	profile_t profile;
	krb5_address **addresses = NULL;
	krb5_address **hostlist;

	/* Defaults: try everyting (try_first_pass, use a PAG, no debug). */
	ret = malloc(sizeof(struct config));
	if(ret == NULL) {
		return NULL;
	}
	memset(ret, 0, sizeof(struct config));
	krb5_get_init_creds_opt_init(&ret->creds_opt);
	ret->try_first_pass = 1;
	ret->try_second_pass = 1;

	/* Read configuration info from krb5.conf. */
	dEBUG("get_config() called");
	krb5_get_profile(context, &profile);

	/* Whether or not to debug via syslog. */
	profile_get_string(profile, PROFILE_NAME, "debug", NULL,
			   "false", &foo);
	if(!strcmp(foo, "true")) ret->debug = TRUE;
	for(i = 0; i < argc; i++) {
		if(strcmp(argv[i], "debug") == 0) {
			ret->debug = 1;
		}
	}
			    
	/* The local realm. */
	krb5_get_default_realm(context, &ret->realm);

	/* Ticket lifetime and other flags. */
	profile_get_integer(profile, PROFILE_NAME, "renew_lifetime", NULL,
			    DEFAULT_LIFE, &ret->lifetime);
	krb5_get_init_creds_opt_set_renew_life(&ret->creds_opt, ret->lifetime);
	dEBUG("setting renewable lifetime to %d", ret->lifetime);
	profile_get_integer(profile, PROFILE_NAME, "ticket_lifetime", NULL,
			    DEFAULT_LIFE, &ret->lifetime);
	krb5_get_init_creds_opt_set_tkt_life(&ret->creds_opt, ret->lifetime);
	dEBUG("setting ticket lifetime to %d", ret->lifetime);
	profile_get_string(profile, PROFILE_NAME, "forwardable", NULL,
			   DEFAULT_CELLS, &foo);
	if(!strcmp(foo, "true")) {
		dEBUG("making tickets forwardable");
		krb5_get_init_creds_opt_set_forwardable(&ret->creds_opt, TRUE);
	}

	/* Cells to get tokens for. */
#ifdef HAVE_KRBAFS_H
	profile_get_string(profile, PROFILE_NAME, "afs_cells", NULL,
			   DEFAULT_CELLS, &cells);
	ret->cell_list = malloc(sizeof(char*) * (num_words(cells) + 1));
	memset(ret->cell_list, 0, sizeof(char*) * (num_words(cells) + 1));
	for(i = 0; i < num_words(cells); i++) {
		ret->cell_list[i] = word_copy(nth_word(cells, i));
		dEBUG("will afslog to cell %s", ret->cell_list[i]);
	}
	ret->get_tokens = TRUE;
#endif

	/* Hosts to get tickets for. */
	profile_get_string(profile, PROFILE_NAME, "hosts", NULL,
			   "", &cells);
	addresses = malloc(sizeof(krb5_address) * (num_words(cells) + 2));
	memset(addresses, 0, sizeof(krb5_address) * (num_words(cells) + 2));
	krb5_os_localaddr(context, &hostlist);
	for(j = 0; hostlist[j] != NULL; j++) {
		addresses[j] = hostlist[j];
	}
	for(i = 0; i < num_words(cells); i++) {
		foo = word_copy(nth_word(cells, i));
		krb5_os_hostaddr(context, foo, &hostlist);
		dEBUG("also getting ticket for host %s", foo);
		addresses[i + j] = hostlist[0];
	}
	krb5_get_init_creds_opt_set_address_list(&ret->creds_opt, addresses);

	/* What to say we are when changing passwords. */
	profile_get_string(profile, PROFILE_NAME, "banner", NULL,
			   "Kerberos 5", &ret->banner);
	dEBUG("password-changing banner set to \"%s\"", ret->banner);

	/* Whether to get krb4 tickets using krb524convertcreds(). */
	profile_get_string(profile, PROFILE_NAME, "krb4_convert", NULL,
			   "true", &foo);
	if(!strcmp(foo, "true")) ret->krb4_convert = TRUE;
	dEBUG("krb4_convert %s", ret->krb4_convert ? "true" : "false");

	/* Get the name of a service ticket the user must be able to obtain,
	   as a double-check. */
	profile_get_string(profile, PROFILE_NAME, "required_tgs",
			 NULL, "", &ret->required_tgs);

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
#ifdef HAVE_KRBAFS_H
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
static void cleanup(pam_handle_t *pamh, void *data, int error_status)
{
	free(data);
}

/******************************************************************************/

/* Prompt the user for some info. */
static int pam_prompt_for(pam_handle_t *pamh, int msg_style,
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
			}
		} else {
			INFO("%s in conversation function getting "
			     "info from the user", pam_strerror(pamh, ret));
		}
	}

	return ret;
}

static int pam_prompter(krb5_context context, void *data, const char *name,
		        const char *banner, int num_prompts,
			krb5_prompt prompts[])
{
	int i = 0, ret = PAM_SUCCESS;
	const char *p = NULL;
	for(i = 0; i < num_prompts; i++) {
		ret = pam_prompt_for(data,
				     prompts[i].hidden ?
				     PAM_PROMPT_ECHO_ON :
				     PAM_PROMPT_ECHO_OFF,
				     prompts[i].prompt,
				     &p);
		if(ret == PAM_SUCCESS) {
			strncpy(prompts[i].reply->data, p,
				prompts[i].reply->length);
		} else {
			ret = KRB5_LIBOS_CANTREADPWD;
			break;
		}
	}
	return ret;
}

/* Big authentication module. */
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
			const char **argv)
{
	krb5_context context;
	krb5_principal principal;
	krb5_principal tgs;
	struct config *config;
	const char *user = NULL;
	const char *password = NULL;
	int ret = KRB5_SUCCESS;
	struct stash *stash = NULL;
	struct passwd *pwd;

	/* First parse the arguments; if there are problems, bail. */
	ret = krb5_init_context(&context);
	if(!(config = get_config(context, argc, argv))) {
		ret = PAM_BUF_ERR;
	}
	krb5_init_ets(context);
	DEBUG("pam_sm_authenticate() called");

	/* Initialize Kerberos and grab some memory for the creds structures. */
	if(ret == KRB5_SUCCESS) {
		char *realm;
		stash = malloc(sizeof(struct stash));
		if((ret == KRB5_SUCCESS) && (stash != NULL)) {
			memset(stash, 0, sizeof(struct stash));
			krb5_get_default_realm(context, &realm);
			DEBUG("default Kerberos realm is %s", realm);
		} else {
			ret = PAM_SYSTEM_ERR;
			CRIT("Kerberos 5 initialize problem/malloc error");
		}
	}

	/* Get the user's name, by any means possible. */
	if(ret == KRB5_SUCCESS) {
		/* First try the PAM library. */
		pam_get_user(pamh, &user, "login: ");

		/* If there was an error, use the conversation function. */
		if((user == NULL) || (strlen(user) == 0)) {
			ret = pam_prompt_for(pamh, PAM_PROMPT_ECHO_ON,
					     "login: ", &user);
			if(ret == PAM_SUCCESS) {
				ret = pam_set_item(pamh, PAM_USER,
						   (const void*)user);
			}
		}

		/* If we got a login from either method, use it. */
		ret = pam_get_user(pamh, &user, "login:");
		if(ret != PAM_SUCCESS) {
			CRIT("cannot determine user's login");
			ret = PAM_USER_UNKNOWN;
		}
	}
	DEBUG("user is \"%s\"", user);

	/* Try to get and save the user's UID. */
	pwd = getpwnam(user);
	if(pwd != NULL) {
		if(config->debug)
		stash->uid = pwd->pw_uid;
		stash->gid = pwd->pw_gid;
		DEBUG("%s has uid %d, gid %d", user, stash->uid, stash->gid);
	} else {
		CRIT("getpwnam(\"%s\") failed", user);
		ret = PAM_USER_UNKNOWN;
	}

	/* Build the user's principal. */
	if(ret == KRB5_SUCCESS) {
		ret = krb5_parse_name(context, user, &principal);
		if(ret != KRB5_SUCCESS) {
			CRIT("%s building user principal for %s",
			     error_message(ret), user);
			ret = PAM_SYSTEM_ERR;
		}
	}

	/* Retrieve a password that may already have been entered. */
	if((config->try_first_pass) && (ret == PAM_SUCCESS)) {
		pam_get_item(pamh, PAM_AUTHTOK, (const void**) &password);
	} else {
		password = NULL;
	}

	/* Now try to get a TGT using the password, prompting the user if it
	   fails and we're allowed ot prompt. */
	if(ret == KRB5_SUCCESS) {
		int done = 0;

		INFO("attempting to authenticate %s", user);
		/* Set up the creds structure. */
		memset(&stash->v5_creds, 0, sizeof(stash->v5_creds));
		/* Who we're representing. */
		stash->v5_creds.client = principal;
		/* Try the password. */
		if(config->try_first_pass && password && !done) {
			ret = krb5_get_init_creds_password(context,
							   &stash->v5_creds,
							   principal,
							   (char*)password,
							   NULL,
							   NULL,
							   0,
							   NULL,
							   &config->creds_opt);
			DEBUG("get_int_tkt returned %s",
			      ret ? error_message(ret) : "Success");
			if(ret == KRB5_SUCCESS) {
				done = 1;
			}
		}

		/* Try to converse if the password failed. */
		if(config->try_second_pass && !done) {
			ret = krb5_get_init_creds_password(context,
							   &stash->v5_creds,
							   principal,
							   NULL,
							   pam_prompter,
							   pamh,
							   0,
							   NULL,
							   &config->creds_opt);
			DEBUG("get_int_tkt returned %s",
			      ret ? error_message(ret) : "Success");
			if(ret == KRB5_SUCCESS) {
				done = 1;
			}
		}

		/* Figure out where to go from here. */
		if(ret != KRB5_SUCCESS) {
			INFO("authenticate error: %s", error_message(ret));
			ret = PAM_AUTH_ERR;
		}
	}

	if(ret == KRB5_SUCCESS) {
		/* If everything worked, then we're outta here. */
		INFO("authentication succeeds for %s", user);
	} else {
		INFO("authentication fails for %s", user);
	}

	/* Build a principal for the service credential we'll use for double-
	   checking the validity of the TGT. */
	if((ret == KRB5_SUCCESS) && (config->required_tgs != NULL) &&
	   (strlen(config->required_tgs) > 0)) {
		ret = krb5_parse_name(context, config->required_tgs, &tgs);
		if(ret != KRB5_SUCCESS) {
			CRIT("%s building principal for %s",
			     error_message(ret), config->required_tgs);
			ret = PAM_SYSTEM_ERR;
		}

		/* Attempt to use our new TGT to obtain a service ticket. */
		if(ret == KRB5_SUCCESS) {
			krb5_creds creds, *out_creds;
			memset(&creds, 0, sizeof(creds));
			creds.client = stash->v5_creds.client;
			creds.server = tgs;
			ret = krb5_get_cred_via_tkt(context,
						    &stash->v5_creds,
						    0,
						    NULL,
						    &creds,
						    &out_creds);
			if(ret == KRB5_SUCCESS) {
				INFO("TGT for %s verifies", user);
			} else {
				CRIT("TGT for %s was useless (%s)",
				     user, error_message(ret));
				ret = PAM_SYSTEM_ERR;
			}
		}
	} else {
		INFO("TGT for %s not verified (no required_tgs "
		     "defined)", user);
	}

	if(ret == PAM_SUCCESS) {
		ret = pam_set_data(pamh, MODULE_DATA_NAME, stash, cleanup);
		DEBUG("credentials saved for %s", user);
	}

#ifdef HAVE_KRBAFS_H
	/* Get tokens. */
	if(config->setcred) {
		pam_sm_setcred(pamh, PAM_ESTABLISH_CRED, argc, argv);
		pam_sm_setcred(pamh, PAM_DELETE_CRED, argc, argv);
	}
#endif

	/* Catch any Kerberos error codes that fall through cracks and
	   convert them to appropriate PAM error codes. */
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
		default: {
			ret = PAM_AUTH_ERR;
		}
	}

	/* Done with Kerberos. */
	krb5_free_context(context);

	DEBUG("pam_sm_authenticate returning %d (%s)", ret,
	      pam_strerror(pamh, ret));

	return ret;
}

/******************************************************************************/

/* Create and delete visible credentials as needed. */
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	krb5_context context;
	struct stash *stash;
	krb5_ccache ccache;
#ifdef HAVE_LIBKRB4
	CREDENTIALS v4_creds;
#endif
	char v4_path[PATH_MAX];
	char v5_path[PATH_MAX];
	const char *user = NULL;
	int ret = KRB5_SUCCESS;
	struct config *config;

	/* First parse the arguments; if there are problems, bail. */
	ret = krb5_init_context(&context);
	if(!(config = get_config(context, argc, argv))) {
		ret = PAM_BUF_ERR;
	}
	krb5_init_ets(context);
	DEBUG("pam_sm_setcred() called");

	/* Retrieve information about the user. */
	if(ret == PAM_SUCCESS) {
		ret = pam_get_user(pamh, &user, "login:");
	}

	if((flags & PAM_ESTABLISH_CRED) && (ret == KRB5_SUCCESS)) {
		/* Retrieve and create Kerberos tickets. */
		ret = pam_get_data(pamh, MODULE_DATA_NAME, (void*)&stash);
		if(ret == PAM_SUCCESS) {
			DEBUG("credentials retrieved");

			/* Set up the environment variable for Kerberos 5. */
			snprintf(v5_path, sizeof(v5_path),
				 "KRB5CCNAME=/tmp/krb5cc_%d_%d",
				 stash->uid, getpid());
			ret = pam_putenv(pamh, v5_path);
			if(ret != PAM_SUCCESS) {
				CRIT("%s setting environment",
				     pam_strerror(pamh, ret));
			}
			DEBUG("%s", v5_path);

			/* Create the v5 ticket cache. */
			snprintf(v5_path, sizeof(v5_path), "/tmp/krb5cc_%d_%d",
				 stash->uid, getpid());
			ret = krb5_cc_resolve(context, v5_path, &ccache);
			if(ret == KRB5_SUCCESS) {
				ret = krb5_cc_initialize(context, ccache,
						        stash->v5_creds.client);
			}
			if(ret != KRB5_SUCCESS) {
				CRIT("error initializing ccache %s for %s: "
				     "%s", v5_path, user, error_message(ret));
			}

			/* Store credentials in the cache. */
			if(ret == KRB5_SUCCESS) {
				krb5_cc_store_cred(context, ccache,
						   &stash->v5_creds);
				ret = krb5_cc_close(context, ccache);
				chown(v5_path, stash->uid, stash->gid);
			}
		} else {
			DEBUG("Kerberos 5 credential retrieval failed for "
			      "%s, user is probably local", user);
			stash = NULL;
			ret = PAM_CRED_UNAVAIL;
		}

#ifdef HAVE_LIBKRB524
		/* Get Kerberos 4 credentials. */
		if((ret == KRB5_SUCCESS) && (config->krb4_convert)) {
			DEBUG("converting credentials for %s", user);

			ret = krb524_convert_creds_kdc(context,
						       &stash->v5_creds,
						       &v4_creds);

			DEBUG("krb524_convert_creds returned \"%s\" for %s",
			      error_message(ret), user);

			if(ret == KRB5_SUCCESS) {
				INFO("v4 ticket conversion succeeded for %s",
				     user);
			} else {
				/* This shouldn't happen.  Either krb524d isn't
				   running on the KDC or the module is
				   misconfigured. */
				CRIT("v4 ticket conversion failed for %s: %s "
				     "(shouldn't happen)", user,
				     error_message(ret));
			}

			/* Set up the environment variable for Kerberos 4. */
			snprintf(v4_path, sizeof(v4_path),
				 "KRBTKFILE=/tmp/tkt%d_%d",
				 stash->uid, getpid());
			ret = pam_putenv(pamh, v4_path);
			if(ret != PAM_SUCCESS) {
				CRIT("%s setting environment",
				     pam_strerror(pamh, ret));
			}
			DEBUG(v4_path);

			/* Create the v4 ticket cache. */
			snprintf(v4_path, sizeof(v4_path),
				 "/tmp/tkt%d_%d", stash->uid, getpid());
			DEBUG("opening ticket file \"%s\"", v4_path);
			krb_set_tkt_string(strdup(v4_path));
			ret = in_tkt(v4_creds.pname,
				     v4_creds.pinst);
			if(ret != KRB5_SUCCESS) {
				CRIT("error initializing tf %s for %s, punting",
				     v4_path, user);
				ret = KRB5_SUCCESS;
			}

			/* Store credentials in the ticket file. */
			if(ret == KSUCCESS) {
				DEBUG("save v4 creds");
				krb_save_credentials(v4_creds.service,
						     v4_creds.instance,
						     v4_creds.realm,
						     v4_creds.session,
						     v4_creds.lifetime,
						     v4_creds.kvno,
						     &v4_creds.ticket_st,
						     v4_creds.issue_date);
			}
			chown(v4_path, stash->uid, stash->gid);
		}
#endif
	}

#ifdef HAVE_KRBAFS_H
	/* Use the new tickets to create tokens. */
	if((ret == PAM_SUCCESS) && config->get_tokens && config->cell_list) {
		if(!k_hasafs()) {
			CRIT("cells specified but AFS not running");
			ret = PAM_SYSTEM_ERR;
		}
		if(ret == PAM_SUCCESS) {
			int i;
			/* Afslog to all of the specified cells. */
			k_setpag();
			for(i = 0; config->cell_list[i] != NULL; i++) {
				DEBUG("afslog() to cell %s", config->cell_list[i]);
				krb_afslog(config->cell_list[i], config->realm);
			}
		}
	}
#endif

	if((flags & PAM_DELETE_CRED) && (ret == KRB5_SUCCESS)) {
		ret = pam_get_data(pamh,MODULE_DATA_NAME,(const void**)&stash);
		if(ret == PAM_SUCCESS) {
			DEBUG("credentials retrieved");
			/* Delete the v5 ticket cache. */
			snprintf(v5_path, sizeof(v5_path),
				 "/tmp/krb5cc_%d_%d", stash->uid, getpid());
			INFO("removing %s", v5_path);
			remove(v5_path);
#ifdef HAVE_LIBKRB524
			/* Delete the v4 ticket cache. */
			snprintf(v4_path, sizeof(v4_path),
				 "/tmp/tkt%d_%d", stash->uid, getpid());
			INFO("removing %s", v4_path);
			remove(v4_path);
#endif
#ifdef HAVE_KRBAFS_H
			/* Clear tokens unless we need them. */
			if(!config->setcred && k_hasafs()) {
				INFO("destroying tokens");
				k_unlog();
			}
#endif
		}
	}

	/* Done with Kerberos. */
	krb5_free_context(context);

	return ret;
}

/******************************************************************************/

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
			const char **argv)
{
	struct config *config;
	krb5_context context = NULL;
	int ret;

	ret = krb5_init_context(&context);
	if(!(config = get_config(context, argc, argv))) {
		ret = PAM_BUF_ERR;
	}
	DEBUG("pam_sm_close_session() called");
	if(context) krb5_free_context(context);

	return pam_sm_setcred(pamh, flags | PAM_ESTABLISH_CRED, argc, argv);
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
			 const char **argv)
{
	struct config *config;
	krb5_context context = NULL;
	int ret;

	ret = krb5_init_context(&context);
	if(!(config = get_config(context, argc, argv))) {
		ret = PAM_BUF_ERR;
	}
	DEBUG("pam_sm_close_session() called");
	if(context) krb5_free_context(context);

	return pam_sm_setcred(pamh, flags | PAM_DELETE_CRED, argc, argv);
}

int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	krb5_context context = NULL;
	krb5_principal server, client;
	krb5_creds creds;
	const char *user = NULL, *authtok = NULL, *old_authtok = NULL;
	char current_pass[LINE_MAX], new_pass[LINE_MAX], retype_pass[LINE_MAX];
	struct config *config;
	int ret = 0;

	/* Initialize Kerberos. */
	ret = krb5_init_context(&context);
	if(!(config = get_config(context, argc, argv))) {
		ret = PAM_BUF_ERR;
	}
	DEBUG("pam_sm_chauthtok() called");

	/* Initialize prompt strings. */
	snprintf(current_pass, sizeof(current_pass), "Current %s password: ",
		 config->banner ? config->banner : "");
	snprintf(new_pass, sizeof(new_pass), "New %s password: ",
		 config->banner ? config->banner : "");
	snprintf(retype_pass, sizeof(retype_pass), "Retype new %s password: ",
		 config->banner ? config->banner : "");

	/* Initialize the error table. */
	if(ret == KRB5_SUCCESS) {
		krb5_init_ets(context);
	}

	/* Figure out who the user is. */
	if(ret == KRB5_SUCCESS) {
		ret = pam_get_user(pamh, &user, "login:");
		if(ret != PAM_SUCCESS) {
			INFO("couldn't determine user");
			ret = PAM_USER_UNKNOWN;
		}
	}

	/* Build a principal structure out of the user's login. */
	if(ret == KRB5_SUCCESS) {
		ret = krb5_parse_name(context, user, &client);
		if(ret != KRB5_SUCCESS) {
			CRIT("%s", error_message(ret));
		}
	}

	/* Read the old password.  It's okay if this fails. */
	if(ret == PAM_SUCCESS) {
		pam_get_item(pamh, PAM_OLDAUTHTOK, (const void**) &old_authtok);
		pam_get_item(pamh, PAM_AUTHTOK, (const void**) &authtok);
	}

	/* We have two cases we have to deal with.  The first: check auth. */
	if((ret == KRB5_SUCCESS) && (flags & PAM_PRELIM_CHECK)) {
		memset(&creds, 0, sizeof(creds));
		creds.client = client;
		if((old_authtok == NULL) || (strlen(old_authtok) == 0)) {
			ret = pam_prompt_for(pamh, PAM_PROMPT_ECHO_OFF,
					     current_pass,
					     &old_authtok);
			if(ret == KRB5_SUCCESS) {
				pam_set_item(pamh, PAM_OLDAUTHTOK,
					     (const void*)old_authtok);
			} else {
				ret = PAM_AUTHTOK_RECOVERY_ERR;
			}
		}
		if(ret == KRB5_SUCCESS) {
			ret = krb5_get_init_creds_password(context,
							   &creds,
							   client,
							   (char*) old_authtok,
							   NULL,
							   NULL,
							   0,
							   NULL,
							   &config->creds_opt);
		}
		if(ret == KRB5_SUCCESS) {
			ret = krb5_parse_name(context, PASSWORD_CHANGE_SERVICE,
					      &server);
			if(ret != KRB5_SUCCESS) {
				CRIT("%s\n", error_message(ret));
			}
			ret = PAM_SYSTEM_ERR;
		}
		if(ret == KRB5_SUCCESS) {
			DEBUG("%s cleared for password change", user);
		} else {
			INFO("can't change password for %s: %s",
			     user, error_message(ret));
		}
	}

	/* The second one is a bit messier. */
	if((ret == KRB5_SUCCESS) && (flags & PAM_UPDATE_AUTHTOK)) {
		const char *authtok2;

		DEBUG("attempting to change password for %s", user);

		if((old_authtok == NULL) || (strlen(old_authtok) == 0)) {
			ret = pam_prompt_for(pamh, PAM_PROMPT_ECHO_OFF,
					     current_pass,
					     &old_authtok);
			if(ret != PAM_SUCCESS) {
				INFO("error in conversation: %s",
				     error_message(ret));
				ret = PAM_AUTHTOK_RECOVERY_ERR;
			}
		}

		if((authtok == NULL) || (strlen(authtok) == 0) ||
		   !config->use_authtok) {
			ret = pam_prompt_for(pamh, PAM_PROMPT_ECHO_OFF,
					     new_pass, &authtok);
			if(ret == KRB5_SUCCESS) {
				ret = pam_prompt_for(pamh, PAM_PROMPT_ECHO_OFF,
						   retype_pass, &authtok2);
				if(ret != PAM_SUCCESS) {
					INFO("error in conversation: %s",
					     error_message(ret));
				}
				ret = PAM_AUTHTOK_ERR;
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
		if(ret == KRB5_SUCCESS) {
			ret = krb5_parse_name(context, PASSWORD_CHANGE_SERVICE,
					      &server);
			if(ret != KRB5_SUCCESS) {
				CRIT("%s\n", error_message(ret));
			}
			ret = PAM_SYSTEM_ERR;
		}

		memset(&creds, 0, sizeof(creds));
		creds.client = client;
		creds.server = server;

		if(ret == KRB5_SUCCESS) {
			ret = krb5_get_init_creds_password(context,
							   &creds,
							   client,
							   (char*) old_authtok,
							   NULL,
							   NULL,
							   0,
							   NULL,
							   NULL);
		}

		if(ret != KRB5_SUCCESS) {
			INFO("error in get_init_creds: %s", error_message(ret));
		}

		if(ret == KRB5_SUCCESS) {
			krb5_data code_string, result_string;
			memset(&code_string, 0, sizeof(code_string));
			memset(&result_string, 0, sizeof(result_string));
			krb5_change_password(context,&creds,(char*)authtok,&ret,
					     &code_string,&result_string);
			if(ret == KRB5_SUCCESS) {
				DEBUG("attempt to change password for %s "
				      "resulted in %s, %s", user, code_string,
				      result_string);
				INFO("%s's %spassword has been changed", user,
				     config->banner);
			} else {
				INFO("attempt to change password for %s "
				     "resulted in %s, %s", user, code_string,
				     result_string);
			}
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
int main(int argc, char **argv)
{
	pam_sm_authenticate(NULL, 0, 0, NULL);
	pam_sm_setcred(NULL, 0, 0, NULL);
	pam_sm_open_session(NULL, 0, 0, NULL);
	pam_sm_chauthtok(NULL, 0, 0, NULL);
	pam_sm_close_session(NULL, 0, 0, NULL);
	return 0;
}
#endif
