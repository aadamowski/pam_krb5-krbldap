#include "../config.h"

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif

#include <krb5.h>
#include "conv.h"
#include "log.h"
#include "prompter.h"
#include "xstr.h"

#ident "$Id$"

void
_pam_krb5_maybe_free_responses(struct pam_response *responses, int n_responses)
{
#ifndef LEAKY_BUT_SAFER
	int i;
	if (responses != NULL) {
		for (i = 0; i < n_responses; i++) {
			if (responses[i].resp != NULL) {
				free(responses[i].resp);
			}
			responses[i].resp = NULL;
		}
		free(responses);
	}
#endif
}

krb5_error_code
_pam_krb5_prompter(krb5_context context, void *data,
		   const char *name, const char *banner,
		   int num_prompts, krb5_prompt prompts[])
{
	struct pam_message *messages;
	struct pam_response *responses;
	int offset;
	int i;

	/* If we have a name or banner, we need to make space for it in the
	 * messages structure, so keep track of the offset to the first actual
	 * prompt. */
	if ((name != NULL) && (strlen(name) > 0)) {
		offset = 1;
	} else {
		offset = 0;
	}
	if ((banner != NULL) && (strlen(banner) > 0)) {
		offset++;
	}

	/* Allocate space for the prompts. */
	messages = malloc(sizeof(struct pam_message) * (num_prompts + offset));
	if (messages == NULL) {
		return KRB5_LIBOS_CANTREADPWD;
	}
	memset(messages, 0,
	       sizeof(struct pam_message) * (num_prompts + offset));

	/* If the name and/or banner were given, make them the first prompts. */
	if ((name != NULL) && (strlen(name) > 0)) {
		messages[0].msg = name;
		messages[0].msg_style = PAM_TEXT_INFO;
	}
	if ((banner != NULL) && (strlen(banner) > 0)) {
		if ((name != NULL) && (strlen(name) > 0)) {
			messages[1].msg = banner;
			messages[1].msg_style = PAM_TEXT_INFO;
		} else {
			messages[0].msg = banner;
			messages[0].msg_style = PAM_TEXT_INFO;
		}
	}
	/* Copy the prompt strings over. */
	for (i = 0; i < num_prompts; i++) {
		messages[i + offset].msg = prompts[i].prompt;
		messages[i + offset].msg_style = prompts[i].hidden ?
						 PAM_PROMPT_ECHO_OFF :
						 PAM_PROMPT_ECHO_ON;
	}

	/* Get some responses. */
	responses = NULL;
	i = _pam_krb5_conv_call((pam_handle_t*) data,
				messages, num_prompts + offset,
				&responses);

	/* We can discard the messages now. */
	free(messages);
	messages = NULL;

	/* If we failed, and we asked questions, bail now. */
	if ((i != PAM_SUCCESS) ||
	    ((num_prompts > 0) && (responses == NULL))) {
		return KRB5_LIBOS_CANTREADPWD;
	}

	/* Check for successfully-read responses. */
	for (i = 0; i < num_prompts; i++) {
		if (responses[i + offset].resp_retcode != PAM_SUCCESS) {
			_pam_krb5_maybe_free_responses(responses, num_prompts);
			return KRB5_LIBOS_CANTREADPWD;
		}
		if (xstrlen(responses[i + offset].resp) >= prompts[i].reply->length) {
			_pam_krb5_maybe_free_responses(responses, num_prompts);
			return KRB5_LIBOS_CANTREADPWD;
		}
	}

	/* Gather up the results. */
	for (i = 0; i < num_prompts; i++) {
		strcpy(prompts[i].reply->data, responses[i + offset].resp);
	}

	_pam_krb5_maybe_free_responses(responses, num_prompts);
	return 0; /* success! */
}

int
_pam_krb5_prompt_for(pam_handle_t *pamh, const char *prompt, char **response)
{
	struct pam_message message;
	struct pam_response *responses;
	int i;

	memset(&message, 0, sizeof(message));
	message.msg = prompt;
	message.msg_style = PAM_PROMPT_ECHO_OFF;
	responses = NULL;

	i = _pam_krb5_conv_call(pamh,
				&message, 1,
				&responses);
	if ((i == 0) && (responses != NULL)) {
		*response = xstrdup(responses[0].resp);
	}

	_pam_krb5_maybe_free_responses(responses, 1);

	return i;
}

int
_pam_krb5_prompt_for_2(pam_handle_t *pamh,
		       const char *prompt, char **response,
		       const char *prompt2, char **response2)
{
	struct pam_message messages[2];
	struct pam_response *responses;
	int i;

	memset(&messages, 0, sizeof(messages));
	messages[0].msg = prompt;
	messages[0].msg_style = PAM_PROMPT_ECHO_OFF;
	messages[1].msg = prompt2;
	messages[1].msg_style = PAM_PROMPT_ECHO_OFF;
	responses = NULL;

	i = _pam_krb5_conv_call(pamh,
				messages, 2,
				&responses);
	if ((i == 0) && (responses != NULL)) {
		*response = xstrdup(responses[0].resp);
		*response2 = xstrdup(responses[1].resp);
	}

	_pam_krb5_maybe_free_responses(responses, 2);

	return i;
}
