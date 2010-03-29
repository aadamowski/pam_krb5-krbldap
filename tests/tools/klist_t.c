#include "../../config.h"
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <krb5.h>
int
main(int argc, char **argv)
{
	krb5_context ctx;
	krb5_ccache ccache;
	krb5_creds creds;
	krb5_cc_cursor cursor;
	krb5_error_code ret;

	ctx = NULL;
	ret = krb5_init_context(&ctx);
	if (ret != 0) {
		printf("Error initializing Kerberos.\n");
		return ret;
	}
	ccache = NULL;
	ret = krb5_cc_default(ctx, &ccache);
	if (ret != 0) {
		printf("Error initializing ccache.\n");
		return ret;
	}
	cursor = NULL;
	ret = krb5_cc_start_seq_get(ctx, ccache, &cursor);
	if (ret == 0) {
		memset(&creds, 0, sizeof(creds));
		while (krb5_cc_next_cred(ctx, ccache, &cursor, &creds) == 0) {
			if (creds.times.renew_till != 0) {
				printf("%lu\n",
				       (unsigned long) creds.times.renew_till -
				       (unsigned long) creds.times.starttime);
			} else {
				printf("0\n");
			}
			break;
		}
		krb5_cc_end_seq_get(ctx, ccache, &cursor);
	}
	krb5_cc_close(ctx, ccache);
	krb5_free_context(ctx);
	return 0;
}
