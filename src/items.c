#include "../config.h"

#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif

#include "items.h"

#ident "$Id$"

int
_pam_krb5_has_item(pam_handle_t *pamh, int item)
{
	PAM_KRB5_MAYBE_CONST void *data;
	data = NULL;
	if ((pam_get_item(pamh, item, &data) == PAM_SUCCESS) &&
	    (data != NULL)) {
		return 1;
	}
	return 0;
}

int
_pam_krb5_get_item_text(pam_handle_t *pamh, int item, char **text)
{
	if (item != PAM_CONV) {
		return pam_get_item(pamh, item,
				    (PAM_KRB5_MAYBE_CONST void**) text);
	}
	return PAM_SERVICE_ERR;
}

int
_pam_krb5_get_item_conv(pam_handle_t *pamh, struct pam_conv **conv)
{
	return pam_get_item(pamh, PAM_CONV, (PAM_KRB5_MAYBE_CONST void**) conv);
}
