#include "../config.h"
#include <sys/types.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include "log.h"

#ident "$Id$"

static int
llen(unsigned long l)
{
	int ret = 1;
	while (l != 0) {
		ret++;
		l /= 10;
	}
	return ret;
}

void
debug(const char *fmt, ...)
{
	va_list args;
	char *fmt2;

	va_start(args, fmt);

	fmt2 = malloc(strlen(PACKAGE) + 4 + llen(getpid()) + strlen(fmt) + 1);
	if (fmt2 != NULL) {
		sprintf(fmt2, "%s[%lu]: %s", PACKAGE,
			(unsigned long) getpid(), fmt);
		vsyslog(LOG_DEBUG, fmt2, args);
	} else {
		vsyslog(LOG_DEBUG, fmt, args);
	}

	va_end(args);
}

void
warn(const char *fmt, ...)
{
	va_list args;
	char *fmt2;

	va_start(args, fmt);

	fmt2 = malloc(strlen(PACKAGE) + 4 + llen(getpid()) + strlen(fmt) + 1);
	if (fmt2 != NULL) {
		sprintf(fmt2, "%s[%lu]: %s", PACKAGE,
			(unsigned long) getpid(), fmt);
		vsyslog(LOG_WARNING, fmt2, args);
	} else {
		vsyslog(LOG_WARNING, fmt, args);
	}

	va_end(args);
}

void
notice(const char *fmt, ...)
{
	va_list args;
	char *fmt2;

	va_start(args, fmt);

	fmt2 = malloc(strlen(PACKAGE) + 4 + llen(getpid()) + strlen(fmt) + 1);
	if (fmt2 != NULL) {
		sprintf(fmt2, "%s[%lu]: %s", PACKAGE,
			(unsigned long) getpid(), fmt);
		vsyslog(LOG_NOTICE, fmt2, args);
	} else {
		vsyslog(LOG_NOTICE, fmt, args);
	}

	va_end(args);
}

void
crit(const char *fmt, ...)
{
	va_list args;
	char *fmt2;

	va_start(args, fmt);

	fmt2 = malloc(strlen(PACKAGE) + 4 + llen(getpid()) + strlen(fmt) + 1);
	if (fmt2 != NULL) {
		sprintf(fmt2, "%s[%lu]: %s", PACKAGE,
			(unsigned long) getpid(), fmt);
		vsyslog(LOG_CRIT, fmt2, args);
	} else {
		vsyslog(LOG_CRIT, fmt, args);
	}

	va_end(args);
}
