/*******************************************************************************
 Module for Linux-PAM to do Kerberos 5 authentication, convert the
 Kerberos 5 ticket to a Kerberos 4 ticket, and use it to grab AFS
 tokens for specified cells.

 Copyright 1999 Nalin Dahyabhai <nalin.dahyabhai@pobox.com>
 Distribution allowed under the X consortium license, the LGPL, and/or the
 Artistic License.  Do me a favor and let me know if you're using it, though.
 ******************************************************************************/

#ident "$Id$"
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

#ifdef  PAM_KRB5_KRBAFS_DYNAMIC
#ifndef PAM_KRB5_KRBAFS
#define PAM_KRB5_KRBAFS
#endif
#endif

#ifdef  PAM_KRB5_KRBAFS
#ifndef PAM_KRB5_KRB4
#define PAM_KRB5_KRB4
#endif
#endif

#ifdef PAM_KRB5_KRB4
#ifdef HAVE_KERBEROSIV_KRB_H
#include <kerberosIV/krb.h>
#endif
#endif

#ifdef PAM_KRB5_KRBAFS
#ifdef PAM_KRB5_KRBAFS_DYNAMIC

/******************************************************************************/

/* Prototypes grabbed from krbafs.h */
void *libkrbafs_ptr = NULL;
int dummy_k_hasafs(void) { return 0; }
int(*k_hasafs)(void) = dummy_k_hasafs;
int(*krb_afslog)(const char *cell, const char *realm) = NULL;
int(*k_unlog)(void) = NULL;
int(*k_setpag)(void) = NULL;
#else
/* Link with the krbafs library. */
#include <krbafs.h>
#endif
#endif

/******************************************************************************/

/* Definitions and prototypes culled from kadm5's admin.h file. */
#ifndef KADM5_CHANGEPW_SERVICE
#define KADM5_CHANGEPW_SERVICE "kadmin/changepw"
#endif
#ifndef KADM5_STRUCT_VERSION_MASK
#define KADM5_STRUCT_VERSION_MASK       0x12345600
#endif
#ifndef KADM5_STRUCT_VERSION_1
#define KADM5_STRUCT_VERSION_1  (KADM5_STRUCT_VERSION_MASK|0x01)
#endif
#ifndef KADM5_STRUCT_VERSION
#define KADM5_STRUCT_VERSION    KADM5_STRUCT_VERSION_1
#endif
#ifndef KADM5_API_VERSION_MASK
#define KADM5_API_VERSION_MASK  0x12345700
#endif
#ifndef KADM5_API_VERSION_1
#define KADM5_API_VERSION_1     (KADM5_API_VERSION_MASK|0x01)
#endif
#ifndef KADM5_API_VERSION_2
#define KADM5_API_VERSION_2     (KADM5_API_VERSION_MASK|0x02)
#endif

typedef long	kadm5_ret_t;
kadm5_ret_t	kadm5_init_with_password(const char*, const char*, const char*,
					 struct _kadm5_config_params*,
					 krb5_ui_4, krb5_ui_4, const void **);
kadm5_ret_t	kadm5_chpass_principal(const void*,krb5_principal,const char*);

/******************************************************************************/

#ifndef KRB5_SUCCESS
#define KRB5_SUCCESS 0
#endif

#define MODULE_NAME "pam_krb5afs"
#define MODULE_DATA_NAME "pam_krb5afs_module_data"

#define PAM_SM_AUTH
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/_pam_macros.h>

/******************************************************************************/

struct stash {
	uid_t uid;
	gid_t gid;
	krb5_creds v5_creds;
#ifdef PAM_KRB5_KRB4
	CREDENTIALS v4_creds;
#endif
};

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

/* Module-specific flags. */
static struct {
	unsigned char debug, pag, try_first_pass, try_second_pass, use_authtok;
	krb5_flags kdc_options;
	char **cellnames;
	int cells;
} globals = {0, 0, 0, 0, 0, 0, NULL, 0};

/******************************************************************************/

/* Scan argv for flags. */
static int check_flags(int argc, const char **argv)
{
	int i, ret = 1;

	D(("... called."));

	/* Defaults: try everyting (try_first_pass, use a PAG, no debug). */
	globals.debug = 0;
	globals.pag = 1;
	globals.try_first_pass = 1;
	globals.try_second_pass = 1;
	globals.kdc_options = 0;

	/* Scan for flags we find interesting. */
	for(i = 0; i < argc; i++) {
		/* Provide debug info via syslog. */
		if(strcmp(argv[i], "debug") == 0) {
			globals.debug = 1;
		}
	}
	for(i = 0; i < argc; i++) {
		D(("Processing flag \"%s\".", argv[i]));
		/* Required arguments that we don't use but need to recognize.*/
		if(strcmp(argv[i], "no_warn") == 0) {
			continue;
		}
		if(strcmp(argv[i], "use_mapped_pass") == 0) {
			continue;
		}
		if(strcmp(argv[i], "try_first_pass") == 0) {
			continue;
		}
		/* Don't use a separate PAG for this session. DON'T USE THIS. */
		if(strcmp(argv[i], "nopag") == 0) {
			globals.pag = 0;
			continue;
		}
		/* Only try the first password. */
		if(strcmp(argv[i], "use_first_pass") == 0) {
			globals.try_second_pass = 0;
			continue;
		}
		/* Don't try the password stored in PAM_AUTHTOK. */
		if(strcmp(argv[i], "skip_first_pass") == 0) {
			globals.try_first_pass = 0;
			continue;
		}
		/* Rely exclusively on PAM_AUTHTOK and PAM_OLDAUTHTOK for
		   password-changing. */
		if(strcmp(argv[i], "use_authtok") == 0) {
			globals.use_authtok = 1;
			continue;
		}
		/* Useful KDC options. */
		if(strcmp(argv[i], "kdc_opt_forwardable") == 0) {
			globals.kdc_options |= KDC_OPT_FORWARDABLE;
			continue;
		}
		if(strcmp(argv[i], "kdc_opt_proxiable") == 0) {
			globals.kdc_options |= KDC_OPT_PROXIABLE;
			continue;
		}
		if(strcmp(argv[i], "kdc_opt_renewable") == 0) {
			globals.kdc_options |= KDC_OPT_RENEWABLE;
			continue;
		}
		/* It's a cell name.  Grab space to save it. */
		globals.cells++;
		globals.cellnames = realloc(globals.cellnames,
					    globals.cells * sizeof(char*));
		if(globals.cellnames) {
			/* Save the cell name. */
			D(("Processing cell \"%s\".", argv[i]));
			if(globals.debug)
			syslog(LOG_DEBUG, MODULE_NAME
			       ": option '%s' is a cell name.", argv[i]);
			globals.cellnames[globals.cells - 1] = strdup(argv[i]);
		} else {
			/* Aack. Barf. */
			D(("Memory error saving cell \"%s\".", argv[i]));
			syslog(LOG_CRIT, MODULE_NAME
			       ": error saving cell name \"%s\"", argv[i]);
			ret = 0;
		}
	}
	D(("Returning %s.", ret ? "successfully" : "failure code"));
	return ret;
}

/* Free some memory. */
static void cleanup(pam_handle_t *pamh, void *data, int error_status)
{
	D(("... called."));
	free(data);
}

/******************************************************************************/

/* Prompt the user for some info. */
static int pam_prompt_for(pam_handle_t *pamh, int msg_style,
			  const char *msg, const char **out)
{
	struct pam_message prompt_message;
	struct pam_response *responses;
	struct pam_conv *converse = NULL;
	int ret = PAM_SUCCESS;
	struct pam_message* promptlist[] = {
		&prompt_message,
		NULL
	};

	/* Get the conversation structure passed in by the app. */
	ret = pam_get_item(pamh, PAM_CONV, converse);
	if(ret != PAM_SUCCESS) {
	if(globals.debug)
		syslog(LOG_DEBUG, MODULE_NAME
		       ": no conversation function supplied");
		ret = PAM_CONV_ERR;
	}

	/* Now actually prompt the user for that information. */
	if(ret == PAM_SUCCESS) {
		prompt_message.msg_style = msg_style;
		prompt_message.msg = msg;
		ret = converse->conv(1, promptlist, &responses,
				     converse->appdata_ptr);
		if(ret == PAM_SUCCESS) {
			*out = strdup(responses[0].resp);
		} else {
			syslog(LOG_INFO, MODULE_NAME
			       ": %s in conversation function getting "
			       "info from the user", pam_strerror(pamh, ret));
		}
	}

	return ret;
}

/* Big authentication module. */
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
			const char **argv)
{
	krb5_context context;
	krb5_principal principal, server;
	const char *user = NULL;
	const char *first_pass = NULL, *second_pass = NULL;
	const struct pam_conv *converse = NULL;
	int ret = KRB5_SUCCESS;
	struct stash *stash = NULL;
	struct passwd *pwd;

	D(("... called."));

	/* First parse the arguments; if there are problems, bail. */
	if(!check_flags(argc, argv)) {
		ret = PAM_BUF_ERR;
	}
	if(globals.debug)
	syslog(LOG_DEBUG,MODULE_NAME ": pam_sm_authenticate called");

	/* Initialize Kerberos and grab some memory for the creds structures. */
	if(ret == KRB5_SUCCESS) {
		char *realm;
		ret = krb5_init_context(&context);
		stash = malloc(sizeof(struct stash));
		if((ret == KRB5_SUCCESS) && (stash != NULL)) {
			memset(stash, 0, sizeof(struct stash));
			krb5_get_default_realm(context, &realm);
			D(("Default Kerberos realm is \"%s\".", realm));
			if(globals.debug)
			syslog(LOG_DEBUG, MODULE_NAME
			       ": default Kerberos realm is %s", realm);
			krb5_init_ets(context);
		} else {
			D(("Kerberos 5 initialize problem/malloc error"));
			syslog(LOG_CRIT, MODULE_NAME
			       ": Kerberos 5 initialize problem/malloc error");
			ret = PAM_SYSTEM_ERR;
		}
	}

	/* Get the conversation function, if the application supplied one. */
	D(("Retrieving conversation function pointer."));
	if(ret == KRB5_SUCCESS) {
		pam_get_item(pamh, PAM_CONV, &converse);
		if(ret != KRB5_SUCCESS) {
			D(("Error retrieving conversation function ptr."));
			if(globals.debug)
			syslog(LOG_DEBUG, MODULE_NAME
			       ": no conversation function supplied by app");
		}
	}

	/* Get the user's name, by any means possible. */
	D(("About to try to determine who the user is."));
	if(ret == KRB5_SUCCESS) {
		/* First try the PAM library. */
		ret = pam_get_user(pamh, &user, "login:");

		/* If there was an error, use the conversation function. */
		if(((ret != PAM_SUCCESS) || (!user) || (strlen(user) == 0)) && converse) {
			const struct pam_message prompt_message[] = {
				{ PAM_PROMPT_ECHO_ON, "login: " },
			};
			const struct pam_message* promptlist[] = {
				&prompt_message[0], NULL
			};
			struct pam_response *responses = NULL;
			D(("About to ask the user who she is."));
			ret = converse->conv(1, promptlist, &responses,
					     converse->appdata_ptr);
			if(ret == PAM_SUCCESS) {
				ret = pam_set_item(pamh, PAM_USER,
						   strdup(responses[0].resp));
			}
		}

		/* If we got a login from either method, use it. */
		if(ret == PAM_SUCCESS) {
			ret = pam_get_user(pamh, &user, "login:");
		} else {
			D(("cannot determine user's login"));
			syslog(LOG_CRIT, MODULE_NAME
			       ": cannot determine user's login");
			ret = PAM_USER_UNKNOWN;
		}
	}
	D(("User = \"%s\".", user));
	if(globals.debug)
	syslog(LOG_DEBUG, MODULE_NAME ": user is \"%s\"", user);

	/* Try to get and save the user's UID. */
	pwd = getpwnam(user);
	if(pwd != NULL) {
		stash->uid = pwd->pw_uid;
		stash->gid = pwd->pw_gid;
		D(("%s has uid %d, gid %d", user, stash->uid, stash->gid));
		if(globals.debug)
		syslog(LOG_DEBUG, MODULE_NAME ": %s has uid %d, gid %d",
		       user, stash->uid, stash->gid);
	} else {
		D(("getpwnam(\"%s\") failed", user));
		syslog(LOG_CRIT, MODULE_NAME ": getpwnam(\"%s\") failed", user);
		ret = PAM_SYSTEM_ERR;
	}

	/* Build the user's principal. */
	if(ret == KRB5_SUCCESS) {
		ret = krb5_parse_name(context, user, &principal);
		if(ret != KRB5_SUCCESS) {
			D(("%s building user principal for %s",
			   error_message(ret), user));
			syslog(LOG_CRIT, MODULE_NAME
			       ": %s building user principal for %s",
			       error_message(ret), user);
			ret = PAM_SYSTEM_ERR;
		}
	}

	/* Build a principal for the TGT we're going to try to get. */
	D(("Building TGT principal."));
	if(ret == KRB5_SUCCESS) {
		krb5_data *realm = krb5_princ_realm(context, principal);
		ret = krb5_build_principal_ext(context,
					       &server,
					       realm->length,
					       realm->data,
					       KRB5_TGS_NAME_SIZE,
					       KRB5_TGS_NAME,
					       realm->length,
					       realm->data,
					       0);
		D(("Build_principal_ext = \"%s\".", error_message(ret)));
		if(ret != KRB5_SUCCESS) {
			D(("%s building TGT principal for %s",
			   error_message(ret), user));
			syslog(LOG_CRIT, MODULE_NAME
			       ": %s building TGT principal for %s",
			       error_message(ret), user);
			ret = PAM_SYSTEM_ERR;
		}
	}

	/* Retrieve a password that may already have been entered. */
	if((globals.try_first_pass) && (ret == PAM_SUCCESS)) {
		/* Try to retrieve a previously entered password from PAM. */
		pam_get_item(pamh, PAM_AUTHTOK, &first_pass);
	}

	/* Now try to get a TGT using one of the passwords. */
	if(ret == KRB5_SUCCESS) {
		int done = 0;
		D(("attempting to authenticate %s", user));
		syslog(LOG_NOTICE, MODULE_NAME
		       ": attempting to authenticate %s", user);
		/* Set up the creds structure. */
		memset(&stash->v5_creds, 0, sizeof(stash->v5_creds));
		/* Who we're representing. */
		stash->v5_creds.client = principal;
		/* What we want. */
		stash->v5_creds.server = server;
		/* Try the first password. */
		if(globals.try_first_pass && first_pass && !done) {
			ret = krb5_get_in_tkt_with_password(context,
							    globals.kdc_options,
							    NULL,
							    NULL,
							    KRB5_PADATA_NONE,
							    first_pass,
							    0,
							    &stash->v5_creds,
							    NULL);
			D(("get_in_tkt1 returned \"%s\".", error_message(ret)));
			if(globals.debug)
			syslog(LOG_DEBUG, MODULE_NAME
			       ": get_int_tkt returned %s", error_message(ret));
			if(ret == KRB5_SUCCESS) {
				done = 1;
			}
		}
		/* Try the second password if the first one failed or was
		   otherwise bad. */
		if(globals.try_second_pass && second_pass && !done) {
			if(converse) {
				pam_prompt_for(pamh, PAM_PROMPT_ECHO_OFF,
					       "Password: ", &second_pass);
			}
			ret = krb5_get_in_tkt_with_password(context,
							    globals.kdc_options,
							    NULL,
							    NULL,
							    KRB5_PADATA_NONE,
							    second_pass,
							    0,
							    &stash->v5_creds,
							    NULL);
			D(("get_in_tkt2 returned \"%s\".", error_message(ret)));
			if(globals.debug)
			syslog(LOG_DEBUG, MODULE_NAME
			       ": get_int_tkt returned %s", error_message(ret));
			if(ret == KRB5_SUCCESS) {
				/* Save the good authtok in case another module
				   needs it. */
				pam_set_item(pamh, PAM_AUTHTOK,
					     strdup(second_pass));
				done = 1;
			}
		}
		if(ret != KRB5_SUCCESS) {
			D(("get_in_tkt failed(\"%s\")", error_message(ret)));
			syslog(LOG_DEBUG, MODULE_NAME
			       ": get_in_tkt failed (\"%s\"), failing auth",
			       error_message(ret));
			syslog(LOG_NOTICE, MODULE_NAME
			       ": authenticate error: %s", error_message(ret));
			ret = PAM_AUTH_ERR;
		}
	}
	D(("reached"));

	if(ret == KRB5_SUCCESS) {
		/* If everything worked, then we're outta here. */
		D(("Authentication succeeded."));
		syslog(LOG_NOTICE, MODULE_NAME
		       ": authentication succeeds for %s", user);
	} else {
		D(("Authentication failed."));
		syslog(LOG_NOTICE, MODULE_NAME
		       ": authentication fails for %s", user);
	}
	D(("reached"));

#ifdef CRITICAL_SERVICE
{
	/* Build a principal for the service credential we'll use for double-
	   checking the validity of the TGT. */
	krb5_principal tgs;
	D(("Building service principal for \"%s\".", CRITICAL_SERVICE));
	if(ret == KRB5_SUCCESS) {
		ret = krb5_parse_name(context, CRITICAL_SERVICE, &tgs);
		D(("krb5_parse_name = \"%s\".", error_message(ret)));
		if(ret != KRB5_SUCCESS) {
			syslog(LOG_CRIT, MODULE_NAME
			       ": %s building principal for %s",
			       error_message(ret), CRITICAL_SERVICE);
			ret = PAM_SYSTEM_ERR;
		}
	}
	/* Attempt to use our new TGT to obtain the service ticket. */
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
			D(("TGT for %s verifies as good", user));
			syslog(LOG_INFO, MODULE_NAME
			       ": TGT for %s verifies as good", user);
		} else {
			D(("TGT for %s was useless (%s) - spoofed?", user,
			   error_message(ret)));
			syslog(LOG_CRIT, MODULE_NAME
			       ": TGT for %s was useless (%s) - spoofed?",
			       user, error_message(ret));
			ret = PAM_SYSTEM_ERR;
		}
	}
}
#endif

	/* Retrieve a password that may already have been entered. */
#ifdef PAM_KRB5_KRB4
	/* Get Kerberos 4 credentials via the krb524 service. */
	if(ret == KRB5_SUCCESS) {
		D(("Getting krb4 credentials for %s.", user));
		if(globals.debug)
		syslog(LOG_DEBUG, MODULE_NAME
		       ": converting credentials for %s", user);

		ret = krb524_convert_creds_kdc(context,
					       &stash->v5_creds,
					       &stash->v4_creds);
		D(("Convert_creds returned \"%s\".", error_message(ret)));
		if(globals.debug)
		syslog(LOG_DEBUG, MODULE_NAME
		       ": krb524_convert_creds returned \"%s\" for %s",
		       error_message(ret), user);

		if(ret == KRB5_SUCCESS) {
			D(("Krb4 creds obtained successfully."));
			syslog(LOG_NOTICE, MODULE_NAME ": v4 ticket conversion "
			       "succeeded for %s", user);
		} else {
			/* This shouldn't happen.  Either krb524d isn't running
			   or either the KDC or the module is misconfigured. */
			D(("v4 ticket conversion failed for %s: %s (shouldn't "
			   "happen)", user, error_message(ret)));
			syslog(LOG_CRIT, MODULE_NAME ": v4 ticket conversion "
			       "failed for %s: %s (shouldn't happen)", user,
			       error_message(ret));
		}
	}
	D(("reached"));
#endif /* PAM_KRB5_KRB4 */

	/* Save all of the Kerberos credentials as module-specific data. */
	if(ret == PAM_SUCCESS) {
		ret = pam_set_data(pamh, MODULE_DATA_NAME, stash, cleanup);
		D(("Credentials saved for %s.", user));
		if(globals.debug)
		syslog(LOG_DEBUG, MODULE_NAME ": credentials saved for %s",
		       user);
	}
	D(("reached"));

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
	D(("reached"));

	/* Done with Kerberos. */
	krb5_free_context(context);

	D(("Returning %d (%s).", ret, pam_strerror(pamh, ret)));
	if(globals.debug)
	syslog(LOG_DEBUG,MODULE_NAME ": pam_sm_authenticate returning %d (%s)",
	       ret, pam_strerror(pamh, ret));

	return ret;
}

/******************************************************************************/

/* Create and delete visible credentials as needed. */
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	krb5_context context;
	struct stash *stash;
	krb5_ccache ccache;
#ifdef PAM_KRB5_KRB4
	char v4_path[PATH_MAX];
#endif
	char v5_path[PATH_MAX];
	char *user = NULL;
	int ret = KRB5_SUCCESS;

	D(("... called."));
	/* First parse the arguments; if there are problems, bail. */
	if(!check_flags(argc, argv)) {
		ret = PAM_BUF_ERR;
	}

	/* Retrieve information about the user. */
	if(ret == PAM_SUCCESS) {
		ret = pam_get_user(pamh, &user, "login:");
	}

	/* Create a Kerberos context. */
	if(ret == PAM_SUCCESS) {
		ret = krb5_init_context(&context);
		if(ret != KRB5_SUCCESS) {
			D(("error intializing Kerberos 5"));
			syslog(LOG_CRIT, MODULE_NAME
			       ": error intializing Kerberos 5");
			ret = PAM_SYSTEM_ERR;
		}
	}

	if(ret == PAM_SUCCESS) {
		char *realm;
		krb5_get_default_realm(context, &realm);
		D(("Default Kerberos realm is \"%s\".", realm));
		if(globals.debug)
		syslog(LOG_DEBUG, MODULE_NAME ": default realm is %s", realm);
		krb5_init_ets(context);
	}

	if((flags & PAM_ESTABLISH_CRED) && (ret == KRB5_SUCCESS)) {
		/* Retrieve and create Kerberos tickets. */
		ret = pam_get_data(pamh, MODULE_DATA_NAME, &stash);
		if(ret == PAM_SUCCESS) {
			D(("Credentials retrieved."));
			if(globals.debug)
			syslog(LOG_DEBUG,MODULE_NAME ": credentials retrieved");

#ifdef PAM_KRB5_KRB4
			/* Set up the environment variable for Kerberos 4. */
			D(("Setting KRBTKFILE in environment."));
			snprintf(v4_path, sizeof(v4_path),
				 "KRBTKFILE=/tmp/tkt%d_%d",
				 stash->uid, getpid());
			ret = pam_putenv(pamh, v4_path);
			if(ret != PAM_SUCCESS) {
				D(("%s setting environment",
				   pam_strerror(pamh, ret)));
				syslog(LOG_CRIT, "%s setting environment",
				       pam_strerror(pamh, ret));
			}
			D(("%s", v4_path));
			if(globals.debug)
			syslog(LOG_DEBUG,MODULE_NAME ": %s", v4_path);

			/* Create the v4 ticket cache. */
			snprintf(v4_path, sizeof(v4_path),
				 "/tmp/tkt%d_%d", stash->uid, getpid());
			D(("Opening ticket file \"%s\".", v4_path));
			if(globals.debug)
			syslog(LOG_DEBUG, MODULE_NAME
			       ": opening ticket file \"%s\"", v4_path);
			krb_set_tkt_string(v4_path);
			ret = in_tkt(stash->v4_creds.pname,
				     stash->v4_creds.pinst);
			if(ret != KRB5_SUCCESS) {
				syslog(LOG_CRIT, MODULE_NAME
				       ": error initializing tf %s for %s",
				       v4_path, user);
			}

			/* Store credentials in the ticket file. */
			if(ret == KSUCCESS) {
				D(("Saving v4 creds to file."));
				if(globals.debug)
				syslog(LOG_DEBUG,MODULE_NAME ": save v4 creds");
				krb_save_credentials(stash->v4_creds.service,
						    stash->v4_creds.instance,
						    stash->v4_creds.realm,
						    stash->v4_creds.session,
						    stash->v4_creds.lifetime,
						    stash->v4_creds.kvno,
						    &stash->v4_creds.ticket_st,
						    stash->v4_creds.issue_date);
			}
			chown(v4_path, stash->uid, stash->gid);
#endif
			/* Set up the environment variable for Kerberos 5. */
			D(("Setting KRB5CCNAME in environment."));
			snprintf(v5_path, sizeof(v5_path),
				 "KRB5CCNAME=/tmp/krb5cc_%d_%d",
				 stash->uid, getpid());
			ret = pam_putenv(pamh, v5_path);
			if(ret != PAM_SUCCESS) {
				D(("%s setting environment",
				  pam_strerror(pamh, ret)));
				syslog(LOG_CRIT, "%s setting environment",
				       pam_strerror(pamh, ret));
			}
			D(("%s", v5_path));
			if(globals.debug)
			syslog(LOG_DEBUG,MODULE_NAME ": %s", v5_path);

			/* Create the v5 ticket cache. */
			snprintf(v5_path, sizeof(v5_path), "/tmp/krb5cc_%d_%d",
				 stash->uid, getpid());
			D(("Opening ccache \"%s\".", v5_path));
			ret = krb5_cc_resolve(context, v5_path, &ccache);
			if(ret == KRB5_SUCCESS) {
				ret = krb5_cc_initialize(context, ccache,
						        stash->v5_creds.client);
			}
			if(ret != KRB5_SUCCESS) {
				D(("error initializing ccache %s for %s: %s",
				   v5_path, user, error_message(ret)));
				syslog(LOG_CRIT, MODULE_NAME
				       ": error initializing ccache %s for %s: "
				       "%s", v5_path, user, error_message(ret));
			}

			/* Store credentials in the cache. */
			if(ret == KRB5_SUCCESS) {
				D(("Storing credentials in ccache."));
				krb5_cc_store_cred(context, ccache,
						   &stash->v5_creds);
				ret = krb5_cc_close(context, ccache);
				chown(v5_path, stash->uid, stash->gid);
			}
		} else {
			D(("Krb5 credential retrieval failed for %s.", user));
			if(globals.debug)
			syslog(LOG_DEBUG, MODULE_NAME
			       ": credential retrieval failed for %s, "
			       "user is probably local", user);
			stash = NULL;
			ret = PAM_CRED_UNAVAIL;
		}
#ifdef PAM_KRB5_KRBAFS
#ifdef PAM_KRB5_KRBAFS_DYNAMIC
		if(ret == KRB5_SUCCESS) {
			/* Try the default name. */
			libkrbafs_ptr = dlopen("libkrbafs.so", RTLD_NOW);
			/* Try alternates. */
			if(libkrbafs_ptr == NULL) {
				libkrbafs_ptr = dlopen("libkafs.so", RTLD_NOW);
			}
			if(libkrbafs_ptr == NULL) {
				libkrbafs_ptr = dlopen("libkrbafs.so.0.9.8", RTLD_NOW);
			}
			if(libkrbafs_ptr == NULL) {
				libkrbafs_ptr = dlopen("libkafs.so.1.0.0", RTLD_NOW);
			}
			if(libkrbafs_ptr == NULL) {
				libkrbafs_ptr = dlopen("libkafs.so.0.9.9", RTLD_NOW);
			}
			if(libkrbafs_ptr == NULL) {
				libkrbafs_ptr = dlopen("libkafs.so.0.9.8", RTLD_NOW);
			}
			/* Get the symbol addresses we need. */
			if(libkrbafs_ptr != NULL) {
				k_hasafs = dlsym(libkrbafs_ptr, "k_hasafs");
				krb_afslog = dlsym(libkrbafs_ptr, "krb_afslog");
				k_unlog = dlsym(libkrbafs_ptr, "k_unlog");
				k_setpag = dlsym(libkrbafs_ptr, "k_setpag");
			}
			/* All have to succeed for us to continue if we need
			   to get AFS tokens. */
			if((libkrbafs_ptr == NULL) && (globals.cells > 0)) {
				D(("Cells configured but couldn't load "
				   "shared library."));
				syslog(LOG_CRIT, MODULE_NAME
				       ": cells specified but couldn't load "
				       "shared library");
				ret = PAM_SYSTEM_ERR;
			}
		}
#endif
		/* Use the new tickets to create tokens. */
		if((ret == KRB5_SUCCESS) && k_hasafs() && (stash != NULL)) {
			if(globals.cells > 0) {
				int i;
				char realm[LINE_MAX];
				/* If we are supposed to create a new PAG for
				   the user, do it. */
				if(globals.pag) {
					k_setpag();
				}
				/* Get the user's realm. */
				memset(realm, 0, sizeof(realm));
				if(krb5_princ_realm(context, stash->v5_creds.client)->length < sizeof(realm))
				memcpy(realm,
				       krb5_princ_realm(context, stash->v5_creds.client)->data,
				       krb5_princ_realm(context, stash->v5_creds.client)->length);
				/* Afslog to all of the specified cells. */
				for(i = 0; i < globals.cells; i++) {
					#ifdef DEBUG
					int krbafsret =
					#endif
					krb_afslog(globals.cellnames[i], realm);
					D(("afslog()ing to \"%s\" gave %d.",
					   globals.cellnames[i], krbafsret));
					syslog(LOG_INFO, MODULE_NAME
					       ": afslog() to %s",
					       globals.cellnames[i]);
				}
			} else {
				D(("No cells configured."));
				if(globals.debug)
				syslog(LOG_DEBUG, MODULE_NAME
				       ": no cells configured.");
			}
		} else {
			if(globals.cells > 0) {
				D(("Cells specified but AFS not running."));
				syslog(LOG_CRIT, MODULE_NAME
				       ": cells specified but AFS not running");
			}
		}
#endif /* PAM_KRB5_KRBAFS */
	}

	if((flags & PAM_DELETE_CRED) && (ret == KRB5_SUCCESS)) {
		ret = pam_get_data(pamh, MODULE_DATA_NAME, &stash);
		if(ret == PAM_SUCCESS) {
			D(("Credentials retrieved."));
			if(globals.debug)
			syslog(LOG_DEBUG,MODULE_NAME ": credentials retrieved");
#ifdef PAM_KRB5_KRB4
			/* Delete the v4 ticket cache. */
			snprintf(v4_path, sizeof(v4_path),
				 "/tmp/tkt%d_%d", stash->uid, getpid());
			D(("Removing ticket file \"%s\".", v4_path));
			syslog(LOG_INFO, MODULE_NAME ": removing %s", v4_path);
			remove(v4_path);
#endif
			/* Delete the v5 ticket cache. */
			snprintf(v5_path, sizeof(v5_path),
				 "/tmp/krb5cc_%d_%d", stash->uid, getpid());
			D(("Removing credential cache \"%s\".", v5_path));
			syslog(LOG_INFO, MODULE_NAME ": removing %s", v5_path);
			remove(v5_path);
#ifdef PAM_KRB5_KRBAFS
			if(k_hasafs()) {
				if(globals.cells > 0) {
					/* If we are supposed to create a new
					   PAG for the user, do it. */
					if(globals.pag) {
						D(("Deleting tokens."));
						if(globals.debug)
						syslog(LOG_DEBUG, MODULE_NAME 
						       ": deleting tokens");
						k_unlog();
					}
				}
			}
#endif /* PAM_KRB5_KRBAFS */
		}
	}

	/* Done with Kerberos. */
	krb5_free_context(context);

	D(("Returning %d.", ret));
	return ret;
}

/******************************************************************************/

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
			const char **argv)
{
	D(("Opening session."));
	return pam_sm_setcred(pamh, flags | PAM_ESTABLISH_CRED, argc, argv);
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
			 const char **argv)
{
	D(("Closing session."));
	return pam_sm_setcred(pamh, flags | PAM_DELETE_CRED, argc, argv);
}

/******************************************************************************/

int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	krb5_context context = NULL;
	krb5_principal server, client;
	krb5_creds creds;
	const char *user = NULL, *authtok = NULL, *old_authtok = NULL;
	const void *kadm5_handle = NULL;
	const struct pam_conv *converse = NULL;
	int ret = 0;

	D(("called with flags: %s%s",
	   flags & PAM_PRELIM_CHECK ? "PRELIM_CHECK " : "",
	   flags & PAM_UPDATE_AUTHTOK ? "UPDATE_AUTHTOK " : ""));

	/* Initialize Kerberos. */
	ret = krb5_init_context(&context);
	if(ret != KRB5_SUCCESS) {
		D(("error initializing Kerberos 5"));
		syslog(LOG_CRIT, MODULE_NAME ": error initializing Kerberos 5");
		ret = PAM_SYSTEM_ERR;
	}

	/* Parse the arguments; if there are problems, bail. */
	if(!check_flags(argc, argv)) {
		ret = PAM_BUF_ERR;
	}

	/* Initialize the error table. */
	if(ret == KRB5_SUCCESS) {
		krb5_init_ets(context);
	}

	/* Figure out who the user is. */
	if(ret == KRB5_SUCCESS) {
		ret = pam_get_user(pamh, &user, "login:");
		D(("user is \"%s\"", user));
		if(ret != PAM_SUCCESS) {
			syslog(LOG_INFO, MODULE_NAME
			       ": couldn't determine user");
			ret = PAM_USER_UNKNOWN;
		}
	}

	/* Build a principal structure out of the user's login. */
	if(ret == KRB5_SUCCESS) {
		ret = krb5_parse_name(context, user, &client);
		if(ret != KRB5_SUCCESS) {
			D(("%s\n", error_message(ret)));
			syslog(LOG_CRIT, MODULE_NAME
			       ": %s\n", error_message(ret));
			ret = PAM_AUTH_ERR;
		}
	}

	/* If we need to prompt the user ourselves, get the conversation ptr. */
	if(!globals.use_authtok && (ret == PAM_SUCCESS)) {
		ret = pam_get_item(pamh, PAM_CONV, &converse);
		if(ret != PAM_SUCCESS) {
			syslog(LOG_CRIT, MODULE_NAME
			       ": use_authtok not specified and "
			       "no conversation function supplied");
			ret = PAM_AUTHTOK_RECOVER_ERR;
		}
	}

	/* Read the old password.  It's okay if this fails. */
	if(ret == PAM_SUCCESS) {
		ret = pam_get_item(pamh, PAM_OLDAUTHTOK, &old_authtok);
		D(("old password is \"%s\"", old_authtok));
	}

	/* Read the old password and save it. */
	if(!globals.use_authtok&&(old_authtok == NULL)&&(ret == PAM_SUCCESS)) {
		const struct pam_message prompt_message[] = {
			{ PAM_PROMPT_ECHO_OFF, "Enter password: " },
		};
		const struct pam_message* promptlist[] = {
			&prompt_message[0], NULL
		};
		struct pam_response *responses = NULL;
		D(("About to ask the user for current password."));
		ret = converse->conv(1, promptlist, &responses,
				     converse->appdata_ptr);
		if(ret == PAM_SUCCESS) {
			ret = pam_set_item(pamh, PAM_OLDAUTHTOK,
					   strdup(responses[0].resp));
		} else {
			syslog(LOG_INFO, MODULE_NAME
			       ": %s reading current password for %s",
			       pam_strerror(pamh, ret), user);
			ret = PAM_AUTHTOK_RECOVER_ERR;
		}
	}

	/* Read the old password.  Require success this time. */
	if(ret == PAM_SUCCESS) {
		ret = pam_get_item(pamh, PAM_OLDAUTHTOK, &old_authtok);
		D(("old password is \"%s\"", old_authtok));
		if((ret != PAM_SUCCESS) || (old_authtok == NULL)) {
			syslog(LOG_CRIT, MODULE_NAME
			       ": couldn't recover old password");
			ret = PAM_AUTHTOK_RECOVER_ERR;
		}
	}

	/* We have two cases we have to deal with.  The first: check auth. */
	if(flags & PAM_PRELIM_CHECK) {
		/* We want to get a TGT, but not store it. */
		if(ret == KRB5_SUCCESS) {
			ret = krb5_build_principal_ext(context, &server,
						       krb5_princ_realm(context,
								client)->length,
						       krb5_princ_realm(context,
								client)->data,
						       KRB5_TGS_NAME_SIZE,
						       KRB5_TGS_NAME,
						       krb5_princ_realm(context,
								client)->length,
						       krb5_princ_realm(context,
								client)->data,
						       NULL);
		}
		if(ret != KRB5_SUCCESS) {
			D(("%s\n", error_message(ret)));
			syslog(LOG_INFO, MODULE_NAME ": %s\n",
			       error_message(ret));
			ret = PAM_AUTH_ERR;
		}

		memset(&creds, 0, sizeof(creds));
		creds.client = client;
		creds.server = server;

		/* See if we can get an in-memory-only ticket. */
		if(ret == PAM_SUCCESS) {
			ret = krb5_get_in_tkt_with_password(context,
							    0,
							    NULL,
							    NULL,
							    KRB5_PADATA_NONE,
							    old_authtok,
							    0,
							    &creds,
							    NULL);
			D(("%s getting TGT", error_message(ret)));
			if(ret != KRB5_SUCCESS) {
				syslog(LOG_INFO, MODULE_NAME "%s",
				       error_message(ret));
				ret = PAM_AUTH_ERR;
			}
		}
	}

	/* The second case:  actually handle the password-change. */
	if(flags & PAM_UPDATE_AUTHTOK) {
		/* Read the new password and save it. */
		if(!globals.use_authtok && (ret == PAM_SUCCESS)) {
			const struct pam_message prompt_message[] = {
				{ PAM_PROMPT_ECHO_OFF, "New Kerberos password:" },
				{ PAM_PROMPT_ECHO_OFF, "Retype new Kerberos password: " },
			};
			const struct pam_message* promptlist[] = {
				&prompt_message[0], &prompt_message[1], NULL
			};
			struct pam_response *responses = NULL;
			D(("About to ask the user for new password."));
			ret = converse->conv(2, promptlist, &responses,
					     converse->appdata_ptr);
			if(strcmp(responses[0].resp, responses[1].resp) != 0) {
				D(("new passwords for %s don't match", user));
				syslog(LOG_INFO, MODULE_NAME
				       ": new passwords for %s not same", user);
				ret = PAM_AUTHTOK_ERR;
			}
			if(ret == PAM_SUCCESS) {
				ret = pam_set_item(pamh, PAM_AUTHTOK,
						   strdup(responses[0].resp));
			} else {
				D(("error reading %s's current password",user));
				syslog(LOG_INFO, MODULE_NAME
				       ": error reading current password for %s", user);
				ret = PAM_AUTHTOK_RECOVER_ERR;
			}
		}

		/* Read the old password. */
		if(ret == PAM_SUCCESS) {
			ret = pam_get_item(pamh, PAM_OLDAUTHTOK, &old_authtok);
			D(("old password is \"%s\"", old_authtok));
			if((ret != PAM_SUCCESS) || (old_authtok == NULL)) {
				syslog(LOG_CRIT, MODULE_NAME
				       ": couldn't recover old password");
				ret = PAM_AUTHTOK_RECOVER_ERR;
			}
		}
		/* Read the new password. */
		if(ret == PAM_SUCCESS) {
			ret = pam_get_item(pamh, PAM_AUTHTOK, &authtok);
			D(("new password is \"%s\"", authtok));
			if((ret != PAM_SUCCESS) || (authtok == NULL)) {
				syslog(LOG_CRIT, MODULE_NAME
				       ": couldn't read new password");
				ret = PAM_AUTHTOK_ERR;
			}
			ret = PAM_SUCCESS;
		}

		/* Build the password-changing service principal. */
		if(ret == KRB5_SUCCESS) {
			ret = krb5_build_principal(context, &server,
						   krb5_princ_realm(context,
								client)->length,
						   krb5_princ_realm(context,
								client)->data,
						   "kadmin", "changepw", NULL);
			if(ret != KRB5_SUCCESS) {
				D(("%s\n", error_message(ret)));
				syslog(LOG_CRIT, MODULE_NAME ": %s\n",
				       error_message(ret));
				ret = PAM_SYSTEM_ERR;
			}
		}

		memset(&creds, 0, sizeof(creds));
		creds.client = client;
		creds.server = server;

		/* Read the old password. */
		if(ret == PAM_SUCCESS) {
			ret = pam_get_item(pamh, PAM_OLDAUTHTOK, &old_authtok);
			D(("old password is \"%s\"", old_authtok));
			if(ret != PAM_SUCCESS) {
				syslog(LOG_CRIT, MODULE_NAME
				       ": couldn't determine old password");
				ret = PAM_AUTHTOK_RECOVER_ERR;
			}
		}

		if(ret == PAM_SUCCESS) {
			ret = kadm5_init_with_password(user, old_authtok,
						       KADM5_CHANGEPW_SERVICE,
						       NULL,
						       KADM5_STRUCT_VERSION,
						       KADM5_API_VERSION_2,
						       &kadm5_handle);
			D(("%s in kadm5_init", error_message(ret)));
			if(ret != KRB5_SUCCESS) {
				syslog(LOG_INFO, MODULE_NAME
				       ": %s\n", error_message(ret));
				ret = PAM_AUTH_ERR;
			}
		}

		if(ret == KRB5_SUCCESS) {
			ret = kadm5_chpass_principal(&kadm5_handle, client,
						     authtok);
		}
	}

	/* Catch a few Kerberos error codes and convert to PAM equivalents. */
	switch(ret) {
		case KRB5_SUCCESS:
		case KRB5KDC_ERR_NONE: {
			D(("Kerberos status = %s", error_message(ret)));
			break;
		}
		case KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN:
		case KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN: {
			D(("Kerberos status = %s", error_message(ret)));
			ret = PAM_USER_UNKNOWN;
			break;
		}
		case KRB5_REALM_UNKNOWN:
		case KRB5_SERVICE_UNKNOWN: {
			D(("Kerberos status = %s", error_message(ret)));
			ret = PAM_SYSTEM_ERR;
			break;
		}
		default: {
			ret = PAM_AUTH_ERR;
		}
	}

	/* Clean up and return. */
	if(context) krb5_free_context(context);
	D(("returning %d (%s)", ret, pam_strerror(pamh, ret)));
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
	pam_sm_chauthtok(NULL, 0, 0, NULL)
	pam_sm_close_session(NULL, 0, 0, NULL);
	return 0;
}
#endif
