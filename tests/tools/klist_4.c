#include "../../config.h"
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include KRB5_H
#ifdef USE_KRB4
#include KRB4_DES_H
#include KRB4_KRB_H
#ifdef KRB4_KRB_ERR_H
#include KRB4_KRB_ERR_H
#endif
#endif

int
main(int argc, char **argv)
{
	char pname[ANAME_SZ + 1], pinst[INST_SZ + 1];
	CREDENTIALS cred;
	int ret;

	ret = tf_init(tkt_string(), R_TKT_FIL);
	if (ret != 0) {
		printf("Error initializing ticket file \"%s\".\n",
		       tkt_string());
		return ret;
	}
	memset(&cred, 0, sizeof(cred));
	ret = tf_get_pname(pname);
	if (ret != 0) {
		printf("Error reading names from \"%s\".\n", tkt_string());
		return ret;
	}
	ret = tf_get_pinst(pinst);
	if (ret != 0) {
		printf("Error reading names from \"%s\".\n", tkt_string());
		return ret;
	}
	ret = tf_get_cred(&cred);
	if (ret != 0) {
		printf("Error reading creds from \"%s\".\n", tkt_string());
		return ret;
	}
	printf("%lu\n", (unsigned long) cred.lifetime);
	tf_close();
	return 0;
}
