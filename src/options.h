#ifndef pam_krb5_options_h
#define pam_krb5_options_h

struct _pam_krb5_options {
	int debug;

	int addressless;
	int forwardable;
	int proxiable;
	int renewable;
	int tokens;
	int user_check;
	int use_authtok;
	int use_first_pass;
	int use_second_pass;
	int validate;
	int v4;
	int warn;

	int renew_lifetime;

	uid_t minimum_uid;

	char *banner;
	char *ccache_dir;
	char *keytab;
	char *realm;
	char **hosts;

	char **afs_cells;
};

struct _pam_krb5_options *_pam_krb5_options_init(pam_handle_t *pamh,
						 int argc,
						 PAM_KRB5_MAYBE_CONST char **argv,
						 krb5_context ctx);
void _pam_krb5_options_free(pam_handle_t *pamh,
			    krb5_context ctx,
			    struct _pam_krb5_options *options);

#endif
