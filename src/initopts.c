#include "../config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif

#include <krb5.h>
#include "initopts.h"
#include "log.h"
#include "options.h"

#ident "$Id$"

#if defined(HAVE_KRB5_OS_LOCALADDR) && \
    defined(HAVE_KRB5_OS_HOSTADDR) && \
    defined(HAVE_KRB5_COPY_ADDR)
static void
_pam_krb5_set_default_address_list(krb5_context ctx,
				   krb5_get_init_creds_opt *k5_options,
				   struct _pam_krb5_options *options)
{
	krb5_address **addresses;
	if (krb5_os_localaddr(ctx, &addresses) == 0) {
		krb5_get_init_creds_opt_set_address_list(k5_options, addresses);
		/* the options structure "adopts" the address array */
	}
}
static void
_pam_krb5_set_empty_address_list(krb5_context ctx,
				 krb5_get_init_creds_opt *k5_options)
{
	krb5_get_init_creds_opt_set_address_list(k5_options, NULL);
}
static void
_pam_krb5_set_extra_address_list(krb5_context ctx,
				 krb5_get_init_creds_opt *k5_options,
				 struct _pam_krb5_options *options)
{
	int n_hosts, total, i, j, k;
	krb5_address ***hosts, **locals, **complete;

	n_hosts = 0;
	for (i = 0;
	     (options->hosts != NULL) && (options->hosts[i] != NULL);
	     i++) {
		n_hosts++;
	}

	hosts = malloc(n_hosts * sizeof(krb5_address **));
	if (hosts == NULL) {
		warn("not enough memory to set up extra hosts list");
		return;
	}
	memset(hosts, 0, n_hosts * sizeof(krb5_address **));

	total = 0;
	for (i = 0; i < n_hosts; i++) {
		if (krb5_os_hostaddr(ctx, options->hosts[i], &hosts[i]) != 0) {
			hosts[i] = NULL;
			warn("error resolving host \"%s\"", options->hosts[i]);
		}
		for (j = 0; (hosts[i] != NULL) && (hosts[i][j] != NULL); j++) {
			total++;
		}
	}

	locals = NULL;
	if (krb5_os_localaddr(ctx, &locals) != 0) {
		warn("error retrieving local address list");
		for (i = 0; i < n_hosts; i++) {
			if (hosts[i] != NULL) {
				krb5_free_addresses(ctx, hosts[i]);
			}
		}
		free(hosts);
		return;
	}

	for (i = 0; (locals != NULL) && (locals[i] != NULL); i++) {
		total++;
	}

	complete = malloc((total + 1) * sizeof(krb5_address *));
	if (complete == NULL) {
		warn("not enough memory to set up extra hosts list");
		return;
	}
	memset(complete, 0, (total + 1) * sizeof(krb5_address *));

	k = 0;
	for (i = 0; (locals != NULL) && (locals[i] != NULL); i++) {
		krb5_copy_addr(ctx, locals[i], &complete[k++]);
	}
	for (i = 0; i < n_hosts; i++) {
		for (j = 0; (hosts[i] != NULL) && (hosts[i][j] != NULL); j++) {
			krb5_copy_addr(ctx, hosts[i][j], &complete[k++]);
		}
	}

	krb5_get_init_creds_opt_set_address_list(k5_options, complete);

	for (i = 0; i < n_hosts; i++) {
		if (hosts[i] != NULL) {
			krb5_free_addresses(ctx, hosts[i]);
		}
	}
	free(hosts);
}
#elif defined(HAVE_KRB5_GET_ALL_CLIENT_ADDRS)
static void
_pam_krb5_set_default_address_list(krb5_context ctx,
				   krb5_get_init_creds_opt *k5_options,
				   struct _pam_krb5_options *options)
{
	krb5_addresses addresses, *tmp;
	if (krb5_get_all_client_addrs(ctx, &addresses) == 0) {
		tmp = malloc(sizeof(krb5_addresses));
		if (tmp != NULL) {
			*tmp = addresses;
			krb5_get_init_creds_opt_set_address_list(k5_options,
								 tmp);
			/* the options structure "adopts" the address list */
		}
	}
}
static void
_pam_krb5_set_empty_address_list(krb5_context ctx,
				 krb5_get_init_creds_opt *k5_options)
{
	krb5_addresses *tmp;
	tmp = malloc(sizeof(krb5_addresses));
	if (tmp == NULL) {
		warn("not enough memory to set up extra hosts list");
		return;
	}
	memset(tmp, 0, sizeof(krb5_addresses));
	tmp->len = 0;
	tmp->val = NULL;
	krb5_get_init_creds_opt_set_address_list(k5_options, tmp);
}
static void
_pam_krb5_set_extra_address_list(krb5_context ctx,
				 krb5_get_init_creds_opt *k5_options,
				 struct _pam_krb5_options *options)
{
	int i;
	krb5_addresses addresses, *list;

	list = malloc(sizeof(krb5_addresses));
	if (list == NULL) {
		warn("out of memory setting extra address list");
		return;
	}
	memset(list, 0, sizeof(krb5_addresses));
	list->len = 0;
	list->val = NULL;

	if (krb5_get_all_client_addrs(ctx, &addresses) == 0) {
		krb5_append_addresses(ctx, list, &addresses);
		krb5_free_addresses(ctx, &addresses);
	}
	for (i = 0;
	     (options->hosts != NULL) && (options->hosts[i] != NULL);
	     i++) {
		if (krb5_parse_address(ctx, options->hosts[i],
				       &addresses) == 0) {
			krb5_append_addresses(ctx, list, &addresses);
			krb5_free_addresses(ctx, &addresses);
		} else {
			warn("error resolving host \"%s\"", options->hosts[i]);
		}
	}

	krb5_get_init_creds_opt_set_address_list(k5_options, list);
}
#else
static void
_pam_krb5_set_default_address_list(krb5_context ctx,
				   krb5_get_init_creds_opt *k5_options,
				   struct _pam_krb5_options *options)
{
#ifdef HAVE_KRB5_OS_LOCALADDR
	krb5_address **addresses;
	if (krb5_os_localaddr(ctx, &addresses) == 0) {
		krb5_get_init_creds_opt_set_address_list(k5_options, addresses);
		/* the options structure "adopts" the address array */
	}
#endif
}
static void
_pam_krb5_set_empty_address_list(krb5_context ctx,
				 krb5_get_init_creds_opt *k5_options)
{
	/* this *may* work */
	krb5_get_init_creds_opt_set_address_list(k5_options, NULL);
}
static void
_pam_krb5_set_extra_address_list(krb5_context ctx,
				 krb5_get_init_creds_opt *k5_options,
				 struct _pam_krb5_options *options)
{
	warn("The \"hosts\" configuration directive is not supported "
	     "with your release of Kerberos.  Please check if your "
	     "release supports an `extra_addresses' directive instead.");
}
#endif

void
_pam_krb5_set_init_opts(krb5_context ctx, krb5_get_init_creds_opt *k5_options,
			struct _pam_krb5_options *options)
{
	/* Only enable or disable these flags if we were told one way or
	 * another, to avoid stepping on library-wide configuration. */
	if (options->forwardable != -1) {
		krb5_get_init_creds_opt_set_forwardable(k5_options,
							options->forwardable);
	}
	if (options->proxiable != -1) {
		krb5_get_init_creds_opt_set_proxiable(k5_options,
						      options->proxiable);
	}
	if ((options->renewable != -1) && (options->renew_lifetime != -1)) {
		krb5_get_init_creds_opt_set_renew_life(k5_options,
						       options->renewable ?
						       options->renew_lifetime :
						       0);
	}
	if (options->addressless == 1) {
		krb5_get_init_creds_opt_set_address_list(k5_options, NULL);
		_pam_krb5_set_empty_address_list(ctx, k5_options);
	}
	if (options->addressless == 0) {
		_pam_krb5_set_default_address_list(ctx, k5_options, options);
		if ((options->hosts != NULL) &&
		    (options->hosts[0] != NULL)) {
			_pam_krb5_set_extra_address_list(ctx, k5_options,
							 options);
		}
	}
}
