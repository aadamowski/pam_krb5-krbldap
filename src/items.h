#ifndef pam_krb5_items_h
#define pam_krb5_items_h

int _pam_krb5_has_item(pam_handle_t *pamh, int item);
int _pam_krb5_get_item_text(pam_handle_t *pamh, int item, char **text);
int _pam_krb5_get_item_conv(pam_handle_t *pamh, struct pam_conv **conv);

#endif
