#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <krb5.h>
#include <com_err.h>

/* ================ Snarfed from kadm5/admin.h and other areas. ============= */

#define KADM5_ADMIN_SERVICE     "kadmin/admin"
#define KADM5_CHANGEPW_SERVICE  "kadmin/changepw"
#define KADM5_HIST_PRINCIPAL    "kadmin/history"

#define KADM5_MASK_BITS         0xffffff00

#define KADM5_STRUCT_VERSION_MASK       0x12345600
#define KADM5_STRUCT_VERSION_1  (KADM5_STRUCT_VERSION_MASK|0x01)
#define KADM5_STRUCT_VERSION    KADM5_STRUCT_VERSION_1

#define KADM5_API_VERSION_MASK  0x12345700
#define KADM5_API_VERSION_1     (KADM5_API_VERSION_MASK|0x01)
#define KADM5_API_VERSION_2     (KADM5_API_VERSION_MASK|0x02)

#define KADM5_CONFIG_REALM              0x000001
#define KADM5_CONFIG_DBNAME             0x000002
#define KADM5_CONFIG_MKEY_NAME          0x000004
#define KADM5_CONFIG_MAX_LIFE           0x000008
#define KADM5_CONFIG_MAX_RLIFE          0x000010
#define KADM5_CONFIG_EXPIRATION         0x000020
#define KADM5_CONFIG_FLAGS              0x000040
#define KADM5_CONFIG_ADMIN_KEYTAB       0x000080
#define KADM5_CONFIG_STASH_FILE         0x000100
#define KADM5_CONFIG_ENCTYPE            0x000200
#define KADM5_CONFIG_ADBNAME            0x000400
#define KADM5_CONFIG_ADB_LOCKFILE       0x000800
#define KADM5_CONFIG_PROFILE            0x001000
#define KADM5_CONFIG_ACL_FILE           0x002000
#define KADM5_CONFIG_KADMIND_PORT       0x004000
#define KADM5_CONFIG_ENCTYPES           0x008000
#define KADM5_CONFIG_ADMIN_SERVER       0x010000
#define KADM5_CONFIG_DICT_FILE          0x020000
#define KADM5_CONFIG_MKEY_FROM_KBD      0x040000

typedef long            kadm5_ret_t;

typedef struct _kadm5_config_params {
     long               mask;
     char *             realm;
     char *             profile;
     int                kadmind_port;

     char *             admin_server;

     char *             dbname;
     char *             admin_dbname;
     char *             admin_lockfile;
     char *             admin_keytab;
     char *             acl_file;
     char *             dict_file;

     int                mkey_from_kbd;
     char *             stash_file;
     char *             mkey_name;
     krb5_enctype       enctype;
     krb5_deltat        max_life;
     krb5_deltat        max_rlife;
     krb5_timestamp     expiration;
     krb5_flags         flags;
     /* krb5_key_salt_tuple *keysalts; */
     void               *keysalts;
     krb5_int32         num_keysalts;
} kadm5_config_params;

kadm5_ret_t    kadm5_init_with_password(char *client_name,
                                        char *pass, 
                                        char *service_name,
                                        kadm5_config_params *params,
                                        krb5_ui_4 struct_version,
                                        krb5_ui_4 api_version,
                                        void **server_handle);
kadm5_ret_t    kadm5_init_with_creds(char *client_name,
                                     krb5_ccache cc,
                                     char *service_name,
                                     kadm5_config_params *params,
                                     krb5_ui_4 struct_version,
                                     krb5_ui_4 api_version,
                                     void **server_handle);
kadm5_ret_t    kadm5_chpass_principal(void *server_handle,
                                      krb5_principal principal,
                                      char *pass);
kadm5_ret_t    kadm5_destroy(void *server_handle);

/* ========================================================================== */

int check_user(const char *user, const char *password)
{
	krb5_context context = NULL;
	krb5_principal server, client;
	krb5_creds creds;
	krb5_ccache ccache;
	int ret;

	ret = krb5_init_context(&context);
	if(ret == 0) {
		krb5_init_ets(context);
	} else {
		fprintf(stderr, "%s\n", error_message(ret));
		exit(0);
	}

	if(ret == 0) {
		krb5_cc_resolve(context, "/tmp/krb5cc_500", &ccache);
	} else {
		fprintf(stderr, "%s\n", error_message(ret));
		exit(0);
	}

	if(ret == 0) {
		ret = krb5_parse_name(context, user, &client);
	} else {
		fprintf(stderr, "%s\n", error_message(ret));
		exit(0);
	}

	if(ret == 0) {
		krb5_cc_initialize(context, ccache, client);
	} else {
		fprintf(stderr, "%s\n", error_message(ret));
		exit(0);
	}

	if(ret == 0) {
		ret = krb5_build_principal(context, &server,
					   krb5_princ_realm(context, client)->length,
					   krb5_princ_realm(context, client)->data,
					   "kadmin", "changepw", NULL);
	} else {
		fprintf(stderr, "%s\n", error_message(ret));
		exit(0);
	}

	memset(&creds, 0, sizeof(creds));
	creds.client = client;
	creds.server = server;

	if(ret == 0) {
		ret = krb5_get_in_tkt_with_password(context, 0, NULL, NULL,
						    KRB5_PADATA_NONE, password,
						    ccache, &creds, NULL);
	} else {
		fprintf(stderr, "%s\n", error_message(ret));
		exit(0);
	}

	if(context) krb5_free_context(context);
	return ret;
}

int main(int argc, char **argv)
{
	krb5_context context = NULL;
	kadm5_config_params params;
	kadm5_ret_t ret;

	char buf[LINE_MAX];
	char *user = "example";
	char *password = NULL;
	void *server_handle = NULL;
	krb5_principal client;

	ret = krb5_init_context(&context);

	if(ret == 0) {
		krb5_init_ets(context);
	} else {
		fprintf(stderr, "%s intializing context\n", error_message(ret));
		exit(0);
	}

	if(argc < 2) {
		fprintf(stderr, "You must supply a principal name!\n");
		exit(0);
	}

	if(ret == 0) {
		ret = krb5_parse_name(context, user = argv[1], &client);
	} else {
		fprintf(stderr, "%s initializer errtab\n", error_message(ret));
		exit(0);
	}

	if(ret == 0) {
		memset(&params, 0, sizeof(params));
		strncpy(buf, krb5_princ_realm(context, client)->data,
			krb5_princ_realm(context, client)->length);
		params.realm = buf;
		// params.mask |= KADM5_CONFIG_REALM;
		params.admin_server = "kerberos.eos.ncsu.edu";
		// params.mask |= KADM5_CONFIG_ADMIN_SERVER;
	} else {
		fprintf(stderr, "%s parsing principal\n", error_message(ret));
		exit(0);
	}
	if(ret == 0) {
		password = getpass("Password: ");
		ret = kadm5_init_with_password(user, password,
					       KADM5_CHANGEPW_SERVICE,
					       NULL,
					       KADM5_STRUCT_VERSION,
					       KADM5_API_VERSION_2,
					       &server_handle);
	} else {
		fprintf(stderr, "%s getting TGT\n", error_message(ret));
		exit(0);
	}

	if(ret == 0) {
		char *p2 = getpass("New password: ");
		password = getpass("New password (verify): ");
		if(strcmp(password, p2) == 0) {
			ret = kadm5_chpass_principal(server_handle, client,
						     p2);
		} else {
			fprintf(stderr, "passwords do not match\n");
			exit(0);
		}
	} else {
		fprintf(stderr, "%s/%d connecting to kadm5\n",
				 error_message(ret), (int) ret);
		exit(0);
	}

	if(server_handle) kadm5_destroy(server_handle);
	if(context) krb5_free_context(context);
	return 0;
}
