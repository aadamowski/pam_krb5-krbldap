/* Sample validation code for debugging. */

#include <krb5.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
	char person[] = "jrandomuser@EXAMPLE.COM";
	char tgtname[] = "krbtgt/EXAMPLE.COM@EXAMPLE.COM";
	char service[] = "host/randomhost.example.com@EXAMPLE.COM";
	char password[LINE_MAX] = "bubbubba";
	char *unparsed;
	krb5_principal client, tgtprinc, server;
	krb5_creds tgt, st, *tgts;
	krb5_ticket *ticket;
	krb5_keytab keytab;
	krb5_keytab_entry entry;
	krb5_context context;
	int ret;

	initialize_krb5_error_table();

	ret = krb5_init_context(&context);
	if(ret) {
		fprintf(stderr, "Error in krb5_init_context().\n");
		return 1;
	}

	ret = krb5_parse_name(context, person, &client);
	if(ret) {
		fprintf(stderr, "Error in krb5_parse_name().\n");
		return 1;
	}

	ret = krb5_parse_name(context, tgtname, &tgtprinc);
	if(ret) {
		fprintf(stderr, "Error in krb5_parse_name().\n");
		return 1;
	}

	ret = krb5_parse_name(context, service, &server);
	if(ret) {
		fprintf(stderr, "Error in krb5_parse_name().\n");
		return 1;
	}

	memset(&tgt, 0, sizeof(tgt));
	tgt.client = client;
	tgt.server = tgtprinc;

	ret = krb5_get_init_creds_password(context, &tgt, client, password,
					   NULL, NULL, 0, tgtname, NULL);
	if(ret) {
		fprintf(stderr, "Error in get_init_creds().\n");
		return 1;
	}

	memset(&st, 0, sizeof(st));
	st.client = client;
	st.server = server;

	ret = krb5_get_cred_via_tkt(context, &tgt, 0, NULL, &st, &tgts);
	if(ret) {
		fprintf(stderr, "Error in get_credentials(): %s.\n",
			error_message(ret));
		return 1;
	}

	ret = krb5_unparse_name(context, tgts[0].server, &unparsed);
	if(ret) {
		fprintf(stderr, "Error in unparse_name(): %s.\n",
			error_message(ret));
		return 1;
	} else {
		fprintf(stderr, "Got cred for \"%s\".\n", unparsed);
	}

	ret = krb5_kt_resolve(context, "/etc/krb5.keytab", &keytab);
	if(ret) {
		fprintf(stderr, "Error in kt_resolve(): %s.\n",
			error_message(ret));
		return 1;
	}

	ret = krb5_decode_ticket(&tgts[0].ticket, &ticket);
	if(ret) {
		fprintf(stderr, "Error in decode_ticket(): %s.\n",
			error_message(ret));
	}

	fprintf(stderr, "kvno = %d.\n", ticket->enc_part.kvno);

	ret = krb5_kt_get_entry(context, keytab, server, ticket->enc_part.kvno,
		       		ticket->enc_part.enctype, &entry);
	if(ret) {
		fprintf(stderr, "Error in get_entry(): %s.\n",
			error_message(ret));
		return 1;
	}

#ifdef BREAK_VALIDATION
	entry.key.contents[0] = 5;
#endif
	ret = krb5_decrypt_tkt_part(context, &entry.key, ticket);
	if(ret) {
		fprintf(stderr, "Error in decrypt(): %s.\n",
			error_message(ret));
	}

	return 0;
}
