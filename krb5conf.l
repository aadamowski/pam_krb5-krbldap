%{

#include <stdlib.h>

#include "string.h"
#include "y.tab.c"

%}

%%

\#.*							{};
\;.*							{};
[[:blank:]]+						{};
\r{0,1}\n						{ xkrb5_conf_lineno++; return NEWLINE; };
[^[:blank:]#;\[\]{}=\n][^[:blank:]#;\n]*		{ yylval.sval = strdup(yytext); return STRING; };
=							{ return EQUALS; };
\[[^[:blank:]]+\]					{ char *p;
							  yylval.sval = strdup(yytext + 1);
							  p = strrchr(yylval.sval, ']');
							  if(p) {
								  *p = '\0';
							  }
							  return SECTION; };
\{							{ return CURLYLEFT; };
\}							{ return CURLYRIGHT; };
