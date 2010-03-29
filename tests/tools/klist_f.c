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
			if (creds.ticket_flags & TKT_FLG_FORWARDABLE) {
				printf("F");
			}
			if (creds.ticket_flags & TKT_FLG_FORWARDED) {
				printf("f");
			}
			if (creds.ticket_flags & TKT_FLG_PROXIABLE) {
				printf("P");
			}
			if (creds.ticket_flags & TKT_FLG_RENEWABLE) {
				printf("R");
			}
			if (creds.ticket_flags & TKT_FLG_INITIAL) {
				printf("I");
			}
			if (creds.ticket_flags & TKT_FLG_PRE_AUTH) {
				printf("A");
			}
			if (creds.ticket_flags &
			    TKT_FLG_TRANSIT_POLICY_CHECKED) {
				printf("T");
			}
			printf("\n");
		}
		krb5_cc_end_seq_get(ctx, ccache, &cursor);
	}
	krb5_cc_close(ctx, ccache);
	krb5_free_context(ctx);
	return 0;
}
