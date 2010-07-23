#include "../../config.h"
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <krb5.h>

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif

#include "../../src/options.h"
#include "../../src/v5.h"

int
main(int argc, char **argv)
{
	krb5_context ctx;
	krb5_address **addresses;
	krb5_ccache ccache;
	krb5_creds creds;
	krb5_cc_cursor cursor;
	krb5_error_code ret;
	int count, lcount;

	ctx = NULL;
	ret = krb5_init_context(&ctx);
	if (ret != 0) {
		printf("Error initializing Kerberos.\n");
		return ret;
	}
	addresses = NULL;
#if defined(HAVE_KRB5_GET_ALL_CLIENT_ADDRS)
	ret = krb5_get_all_client_addrs(ctx, &addresses);
#elif defined(HAVE_KRB5_OS_LOCALADDR)
	ret = krb5_os_localaddr(ctx, &addresses);
#else
#error "Don't know how to get default address list."
#endif
	if (ret != 0) {
		printf("Error getting local address list.\n");
		return ret;
	}
	lcount = 0;
	while ((addresses != NULL) && (addresses[lcount] != NULL)) {
		lcount++;
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
		count = v5_creds_address_count(&creds);
		while (krb5_cc_next_cred(ctx, ccache, &cursor, &creds) == 0) {
			count += v5_creds_address_count(&creds);
		}
#ifdef BASE_ZERO
		printf("%d\n", count);
#else
		printf("%d\n", count - lcount);
#endif
		krb5_cc_end_seq_get(ctx, ccache, &cursor);
	}
	krb5_cc_close(ctx, ccache);
	krb5_free_context(ctx);
	return 0;
}
