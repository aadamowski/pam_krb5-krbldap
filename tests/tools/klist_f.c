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
#if defined(HAVE_KRB5_CREDS_FLAGS_B)
			if (creds.flags.b.forwardable) {
				printf("F");
			}
#elif defined(HAVE_KRB5_CREDS_TICKET_FLAGS)
			if (creds.ticket_flags & TKT_FLG_FORWARDABLE) {
				printf("F");
			}
#else
#error "Don't know how to check for the forwardable ticket flag."
#endif
#if defined(HAVE_KRB5_CREDS_FLAGS_B)
			if (creds.flags.b.forwarded) {
				printf("f");
			}
#elif defined(HAVE_KRB5_CREDS_TICKET_FLAGS)
			if (creds.ticket_flags & TKT_FLG_FORWARDED) {
				printf("f");
			}
#else
#error "Don't know how to check for the forwardable ticket flag."
#endif
#if defined(HAVE_KRB5_CREDS_FLAGS_B)
			if (creds.flags.b.proxiable) {
				printf("P");
			}
#elif defined(HAVE_KRB5_CREDS_TICKET_FLAGS)
			if (creds.ticket_flags & TKT_FLG_PROXIABLE) {
				printf("P");
			}
#else
#error "Don't know how to check for the forwarded ticket flag."
#endif
#if defined(HAVE_KRB5_CREDS_FLAGS_B)
			if (creds.flags.b.renewable) {
				printf("R");
			}
#elif defined(HAVE_KRB5_CREDS_TICKET_FLAGS)
			if (creds.ticket_flags & TKT_FLG_RENEWABLE) {
				printf("R");
			}
#else
#error "Don't know how to check for the renewable ticket flag."
#endif
#if defined(HAVE_KRB5_CREDS_FLAGS_B)
			if (creds.flags.b.initial) {
				printf("I");
			}
#elif defined(HAVE_KRB5_CREDS_TICKET_FLAGS)
			if (creds.ticket_flags & TKT_FLG_INITIAL) {
				printf("I");
			}
#else
#error "Don't know how to check for the is-initial-ticket ticket flag."
#endif
#if defined(HAVE_KRB5_CREDS_FLAGS_B)
			if (creds.flags.b.preauth) {
				printf("A");
			}
#elif defined(HAVE_KRB5_CREDS_TICKET_FLAGS)
			if (creds.ticket_flags & TKT_FLG_PRE_AUTH) {
				printf("A");
			}
#else
#error "Don't know how to check for the preauthenticated ticket flag."
#endif
#if defined(HAVE_KRB5_CREDS_FLAGS_B)
			if (creds.flags.b.transited_policy_checked) {
				printf("f");
			}
#elif defined(HAVE_KRB5_CREDS_TICKET_FLAGS)
			if (creds.ticket_flags &
			    TKT_FLG_TRANSIT_POLICY_CHECKED) {
				printf("T");
			}
#else
#error "Don't know how to check for the transited-policy-checked ticket flag."
#endif
			printf("\n");
		}
		krb5_cc_end_seq_get(ctx, ccache, &cursor);
	}
	krb5_cc_close(ctx, ccache);
	krb5_free_context(ctx);
	return 0;
}
