#ifndef pam_krb5_log_h
#define pam_krb5_log_h

void debug(const char *fmt, ...) PAM_KRB5_GNUC_PRINTF (1, 2);
void warn(const char *fmt, ...) PAM_KRB5_GNUC_PRINTF (1, 2);
void notice(const char *fmt, ...) PAM_KRB5_GNUC_PRINTF (1, 2);
void crit(const char *fmt, ...) PAM_KRB5_GNUC_PRINTF (1, 2);

#endif
