/*
 * Copyright 2003,2004,2005,2006 Red Hat, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of the
 * GNU Lesser General Public License, in which case the provisions of the
 * LGPL are required INSTEAD OF the above restrictions.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN
 * NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "../config.h"

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif

#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif

#include KRB5_H
#include <stdio.h>
#include "conv.h"
#include "log.h"
#include "options.h"
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
				xstrfree(responses[i].resp);
			}
			responses[i].resp = NULL;
		}
		free(responses);
	}
#endif
}

static int
_pam_krb5_prompt_is_password(krb5_prompt *prompt, const char *password)
{
	size_t length;
	if (password == NULL) {
		return 0;
	}
	length = strlen(password);
	if (prompt->reply->length == length) {
		if (memcmp(prompt->reply->data, password, length) == 0) {
			return 1;
		}
	}
	return 0;
}

krb5_error_code
_pam_krb5_always_fail_prompter(krb5_context context, void *data,
			       const char *name, const char *banner,
			       int num_prompts, krb5_prompt prompts[])
{
	return KRB5_LIBOS_CANTREADPWD;
}

krb5_error_code
_pam_krb5_prompter(krb5_context context, void *data,
		   const char *name, const char *banner,
		   int num_prompts, krb5_prompt prompts[])
{
	struct pam_message *messages;
	struct pam_response *responses;
	int headers, i, j, ret, num_msgs;
	char *tmp;
	struct _pam_krb5_prompter_data *pdata = data;
	PAM_KRB5_MAYBE_CONST void *authtok;

	/* If we're configured to not prompt the user for information, then
	 * answer each prompt with PAM_AUTHTOK. */
	if (!pdata->options->prompt_for_libkrb5) {
		/* Retrieve the PAM_AUTHTOK. */
		if (pam_get_item(pdata->pamh, PAM_AUTHTOK,
				 &authtok) != PAM_SUCCESS) {
			return KRB5_LIBOS_CANTREADPWD;
		}
		/* Provide it as the answer to every question. */
		for (i = 0; i < num_prompts; i++) {
			if (prompts[i].reply->length > strlen(authtok)) {
				return KRB5_LIBOS_CANTREADPWD;
			}
			strcpy(prompts[i].reply->data, authtok);
			prompts[i].reply->length = strlen(authtok);
		}
		return 0;
	}

	/* If we have a name or banner, we need to make space for it in the
	 * messages structure, so keep track of the number of non-prompts which
	 * we'll be throwing at the user. */
	if ((name != NULL) && (strlen(name) > 0)) {
		headers = 1;
	} else {
		headers = 0;
	}
	if ((banner != NULL) && (strlen(banner) > 0)) {
		headers++;
	}

	/* Allocate space for the prompts. */
	messages = malloc(sizeof(struct pam_message) * (num_prompts + headers));
	if (messages == NULL) {
		return KRB5_LIBOS_CANTREADPWD;
	}
	memset(messages, 0,
	       sizeof(struct pam_message) * (num_prompts + headers));

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
	for (i = j = 0; i < num_prompts; i++) {
		/* Skip any prompt for which the supplied default answer is the
		 * previously-entered password -- it's just a waste of the
		 * user's time.  */
		if (_pam_krb5_prompt_is_password(&prompts[i],
						 pdata->previous_password)) {
			continue;
		}
		tmp = malloc(strlen(prompts[i].prompt) + 3);
		if (tmp != NULL) {
			sprintf(tmp, "%s: ", prompts[i].prompt);
		}
		messages[j + headers].msg = tmp;
		messages[j + headers].msg_style = prompts[i].hidden ?
						  PAM_PROMPT_ECHO_OFF :
						  PAM_PROMPT_ECHO_ON;
		j++;
	}
	num_msgs = j + headers;

	/* Get some responses. */
	responses = NULL;
	ret = _pam_krb5_conv_call(pdata->pamh, messages, num_msgs, &responses);

	/* We can discard the messages now. */
	for (i = j = 0; i < num_prompts; i++) {
		if (_pam_krb5_prompt_is_password(&prompts[i],
						 pdata->previous_password)) {
			continue;
		}
		free((char*) messages[j + headers].msg);
		messages[j + headers].msg = NULL;
		j++;
	}
	free(messages);
	messages = NULL;

	/* If we failed, and we asked questions, bail now. */
	if ((ret != PAM_SUCCESS) ||
	    ((j > 0) && (responses == NULL))) {
		return KRB5_LIBOS_CANTREADPWD;
	}

	/* Check for successfully-read responses. */
	for (i = j = 0; i < num_prompts; i++) {
		if (_pam_krb5_prompt_is_password(&prompts[i],
						 pdata->previous_password)) {
			continue;
		}
		/* If the conversation function failed to read anything. */
		if (responses[j + headers].resp_retcode != PAM_SUCCESS) {
			_pam_krb5_maybe_free_responses(responses, num_msgs);
			return KRB5_LIBOS_CANTREADPWD;
		}
		/* Or it claimed it could but didn't. */
		if (responses[j + headers].resp == NULL) {
			_pam_krb5_maybe_free_responses(responses, num_msgs);
			return KRB5_LIBOS_CANTREADPWD;
		}
		/* Or it did and we have no space for the answer. */
		if ((unsigned int)xstrlen(responses[j + headers].resp) >= prompts[i].reply->length) {
			_pam_krb5_maybe_free_responses(responses, num_msgs);
			return KRB5_LIBOS_CANTREADPWD;
		}
		j++;
	}

	/* Gather up the results. */
	for (i = j = 0; i < num_prompts; i++) {
		if (_pam_krb5_prompt_is_password(&prompts[i],
						 pdata->previous_password)) {
			continue;
		}
		/* Double-check for NULL here.  We should have caught it above
		 * if that was the case, but it doesn't hurt. */
		if (responses[j + headers].resp == NULL) {
			_pam_krb5_maybe_free_responses(responses, num_msgs);
			return KRB5_LIBOS_CANTREADPWD;
		}
		/* Save the response text. */
		strcpy(prompts[i].reply->data, responses[j + headers].resp);
		prompts[i].reply->length = strlen(responses[j + headers].resp);
		j++;
	}

	_pam_krb5_maybe_free_responses(responses, num_msgs);
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
