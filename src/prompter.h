#ifndef pam_krb5_prompter_h
#define pam_krb5_prompter_h

krb5_error_code
_pam_krb5_prompter(krb5_context context, void *data,
		   const char *name, const char *banner,
		   int num_prompts, krb5_prompt prompts[]);
int _pam_krb5_prompt_for(pam_handle_t *pamh,
			 const char *prompt, char **response);
int _pam_krb5_prompt_for_2(pam_handle_t *pamh,
			   const char *prompt, char **response,
			   const char *prompt2, char **response2);
void _pam_krb5_maybe_free_responses(struct pam_response *responses,
				    int n_responses);

#endif
