%{
#include "string.h"
#include "y.tab.c"
%}
%%
[[:blank:]]*			{};
[^[:blank:]#;\[\]{}=\n]*	{ yylval.sval = strdup(yytext); return STRING; };
\#.*				{};
\;.*				{};
=				{ return EQUALS; };
\n				{ xkrb5_conf_lineno++; return NEWLINE; };
\[				{ return SQUARELEFT; };
\]				{ return SQUARERIGHT; };
\{				{ return CURLYLEFT; };
\}				{ return CURLYRIGHT; };
