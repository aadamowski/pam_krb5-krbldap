#ifndef pam_krb5_initopts_h
#define pam_krb5_initopts_h

#include "options.h"

void _pam_krb5_set_init_opts(krb5_context ctx,
			     krb5_get_init_creds_opt *k5_options,
			     struct _pam_krb5_options *options);

#endif
