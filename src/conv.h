#ifndef pam_krb5_conv_h
#define pam_krb5_conv_h

int _pam_krb5_conv_call(pam_handle_t *pamh,
			PAM_KRB5_MAYBE_CONST struct pam_message *messages,
			int n_prompts,
			struct pam_response **responses);

#endif
