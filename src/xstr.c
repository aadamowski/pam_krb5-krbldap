#include "../config.h"

#include <stdlib.h>
#include <string.h>
#include "xstr.h"

#ident "$Id$"

int
xstrlen(const char *s)
{
	if (s != NULL) {
		return strlen(s);
	}
	return 0;
}

char *
xstrdup(const char *s)
{
	char *ret;
	int len;
	len = xstrlen(s);
	ret = malloc(len + 1);
	if (ret != NULL) {
		memset(ret, '\0', len + 1);
		if (s != NULL) {
			strcpy(ret, s);
		}
	}
	return ret;
}

char *
xstrndup(const char *s, int n)
{
	char *ret;
	int len;
	len = xstrlen(s);
	ret = malloc(len + 1);
	if (ret != NULL) {
		memset(ret, '\0', len + 1);
		if (s != NULL) {
			if (n < len) {
				memmove(ret, s, n);
			} else {
				memmove(ret, s, len);
			}
		}
	}
	return ret;
}
