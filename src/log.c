/*
 * Copyright 2003 Red Hat, Inc.
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