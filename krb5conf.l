%{
#include "string.h"
#include "krb5conf.y.c"
%}
%%
[\t ]+			{};
\#.+\n			{};
[A-Za-z0-9_:/\.]+	{ yylval.sval = strdup(yytext); return STRING; };
[A-Za-z0-9_:/\.][A-Za-z0-9_:/\.\- \t]+[A-Za-z0-9_:/\.] { yylval.sval = strdup(yytext); return STRING; };
=			{ return EQUALS; };
\n			{ xkrb5_conf_lineno++; return NEWLINE; };
\[			{ return SQUARELEFT; };
\]			{ return SQUARERIGHT; };
\{			{ return CURLYLEFT; };
\}			{ return CURLYRIGHT; };
