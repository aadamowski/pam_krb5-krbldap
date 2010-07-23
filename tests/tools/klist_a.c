#include "../../config.h"
#include <sys/types.h>
#include <stdio.h>
#include <string.h>

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif

#include KRB5_H
#ifdef USE_KRB4
#include KRB4_DES_H
#include KRB4_KRB_H
#ifdef KRB4_KRB_ERR_H
#include KRB4_KRB_ERR_H
#endif
#endif

#ifndef HAVE_ERROR_MESSAGE_DECL
#ifdef HAVE_COM_ERR_H
#include <com_err.h>
#elif defined(HAVE_ET_COM_ERR_H)
#include <et/com_err.h>
#endif
#endif

#include "../../src/options.h"
#include "../../src/v5.h"

#if defined(HAVE_KRB5_GET_ALL_CLIENT_ADDRS)
static int
local_address_count(krb5_context ctx)
{
	krb5_addresses addresses;
	memset(&addresses, 0, sizeof(addresses));
	if (krb5_get_all_client_addrs(ctx, &addresses) == 0) {
		return addresses.len;
	}
	return -1;
}
#elif defined(HAVE_KRB5_OS_LOCALADDR)
static int
local_address_count(krb5_context ctx)
{
	int lcount;
	krb5_address **addresses;
	addresses = NULL;
	if (krb5_os_localaddr(ctx, &addresses) == 0) {
		lcount = 0;
		while ((addresses != NULL) && (addresses[lcount] != NULL)) {
			lcount++;
		}
		return lcount;
	}
	return -1;
}
#else
#error "Don't know how to get default address list."
#endif

int
main(int argc, char **argv)
{
	krb5_context ctx;
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
	lcount = local_address_count(ctx);
	if (lcount < 0) {
		printf("Error getting default address list.\n");
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
