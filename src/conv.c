#include "../config.h"

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif

#include <krb5.h>
#include "conv.h"
#include "items.h"
#include "prompter.h"

#ident "$Id$"

/* A PAM conversation function takes as its input a pointer to a pointer to a
 * message structure.  This adds an ambiguity -- is it a pointer to an array,
 * or an array of pointers?  (Basically, is the second message at
 * (*messages)[2] or at *(messages[2])?)  If we call the conversation function
 * through this function, both should work, and we make sure that the
 * conversation function gets the proper appdata pointer as well, so that's one
 * less thing about which we have to worry. */
int
_pam_krb5_conv_call(pam_handle_t *pamh,
		    PAM_KRB5_MAYBE_CONST struct pam_message *messages,
		    int n_prompts,
		    struct pam_response **responses)
{
	struct pam_conv *conv;
	int i;
	struct pam_response *drop_responses;
	PAM_KRB5_MAYBE_CONST struct pam_message **message_array;

	/* Get the address of the conversation structure provided by the
	 * application. */
	i = _pam_krb5_get_item_conv(pamh, &conv);
	if (i != PAM_SUCCESS) {
		return i;
	}
	if (conv == NULL) {
		return PAM_CONV_ERR;
	}

	/* Allocate the array for storing pointers to elements in the array
	 * which we were passed. */
	message_array = malloc(sizeof(struct pam_message*) * n_prompts);
	if (message_array == NULL) {
		return PAM_BUF_ERR;
	}
	memset(message_array, 0, sizeof(struct pam_message*) * n_prompts);

	/* Initialize the array so that each element holds a pointer to a
	 * corresponding element in the passed-in array. */
	for (i = 0; i < n_prompts; i++) {
		message_array[i] = &(messages[i]);
	}

	/* Call the converation function. */
	if (responses == NULL) {
		responses = &drop_responses;
		drop_responses = NULL;
	}
	i = conv->conv(n_prompts, message_array, responses, conv->appdata_ptr);
	if (responses == &drop_responses) {
		_pam_krb5_maybe_free_responses(drop_responses, n_prompts);
	}

	/* Clean up. */
	memset(message_array, 0, sizeof(struct pam_message*) * n_prompts);
	free(message_array);

	return i;
}
