#ifndef pam_krb5_userinfo_h
#define pam_krb5_userinfo_h

struct _pam_krb5_user_info {
	uid_t uid;
	gid_t gid;
	krb5_principal principal_name;
	char *unparsed_name;
};

struct _pam_krb5_user_info *_pam_krb5_user_info_init(krb5_context ctx,
						     const char *name,
						     const char *realm,
						     int check_user);
void _pam_krb5_user_info_free(krb5_context ctx,
			      struct _pam_krb5_user_info *info);

#endif
