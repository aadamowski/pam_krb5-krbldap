%{

#include <stdio.h>

int xkrb5_conf_lineno = 1;
char *xkrb5_conf_section = NULL;
struct xkrb5_conf_entry {
	char *key;
	char *value;
	struct xkrb5_conf_entry *next;
} *xkrb5_conf_entries = NULL;
int xkrb5_conf_parse();
int xkrb5_conf_lex();
extern char *xkrb5_conf_text;
extern FILE *xkrb5_conf_in;

%}

%union {
	char *sval;
	int ival;
}

%token <sval> STRING
%type  <sval> strings
%token EQUALS
%token NEWLINE
%token <sval> SECTION
%token CURLYLEFT
%token CURLYRIGHT

%%

lines:
	line |
	lines line;
line:
	NEWLINE |
	sectionstart |
	assignment |
	subsection;

sectionstart:
	SECTION NEWLINE
	{
		if(xkrb5_conf_section) {
			free(xkrb5_conf_section);
		}
		xkrb5_conf_section = $1;
	}

subsection:
	subsectionstart subsectionstop |
	subsectionstart assignments subsectionstop;

subsectionstart:
	STRING EQUALS CURLYLEFT NEWLINE
	{
		char *tmp;
		if(xkrb5_conf_section) {
			tmp = malloc(strlen(xkrb5_conf_section) + 1 + strlen($1) + 1);
			strcpy(tmp, xkrb5_conf_section);
			strcat(tmp, "\177");
			strcat(tmp, $1);
			free(xkrb5_conf_section);
			xkrb5_conf_section = tmp;
		}
	}
subsectionstop:
	CURLYRIGHT NEWLINE
	{
		if(xkrb5_conf_section) {
			char *p;
			p = strchr(xkrb5_conf_section, '\177');
			if(p) {
				*p = '\0';
			}
		}
	}

assignments:
	assignment |
	assignments assignment;

assignment:
	NEWLINE |
	STRING EQUALS strings NEWLINE
	{
		struct xkrb5_conf_entry *entry = NULL;
		size_t l;
		entry = malloc(sizeof(struct xkrb5_conf_entry));
		memset(entry, 0, sizeof(struct xkrb5_conf_entry));
		l = strlen(xkrb5_conf_section) + 1 + strlen($1) + 1;
		entry->key = malloc(l);
		strcpy(entry->key, xkrb5_conf_section);
		strcat(entry->key, "\177");
		strcat(entry->key, $1);
		entry->value = $3;
		entry->next = xkrb5_conf_entries;
		xkrb5_conf_entries = entry;
	}

strings:
	STRING |
	strings STRING;

%%

#ifdef KRB5CONF_APP
#ifndef APPDEFAULT_APP
#define APPDEFAULT_APP "pam"
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE (!FALSE)
#endif

#ifndef CRIT
#define CRIT printf
#endif
#endif

int
yyerror(const char *error)
{
	CRIT("error parsing /etc/krb5.conf at line %d at `%s': %s\n",
	     xkrb5_conf_lineno, xkrb5_conf_text, error);
	return 0;
}

int
yywrap()
{
	return 1;
}

const char *
xkrb5_conf_read(const char *key)
{
	struct xkrb5_conf_entry *entry;
	char buf[8192];

	snprintf(buf, sizeof(buf), "%s\177%s",
		 APPDEFAULT_APP, key);
	for(entry = xkrb5_conf_entries;
	    entry != NULL;
	    entry = entry->next) {
		if(strcmp(entry->key, buf) == 0) {
			return entry->value;
		}
	}
#ifndef HAVE_KRB5_APPDEFAULT_STRING
	snprintf(buf, sizeof(buf), "%s\177%s\177%s",
		 "appdefaults", APPDEFAULT_APP, key);
	for(entry = xkrb5_conf_entries;
	    entry != NULL;
	    entry = entry->next) {
		if(strcmp(entry->key, buf) == 0) {
			return entry->value;
		}
	}
#endif
	return NULL;
}

void
xkrb5_conf_parse_file()
{
	static int parsed = FALSE;
#ifdef KRB5CONF_APP
	xkrb5_conf_debug = TRUE;
#endif
	if(!parsed) {
		xkrb5_conf_in = fopen("/etc/krb5.conf", "r");
		if(xkrb5_conf_in) {
			do {
				xkrb5_conf_parse();
			} while(!feof(xkrb5_conf_in));
			fclose(xkrb5_conf_in);
		}
		parsed = TRUE;
	}
}

#ifdef KRB5CONF_APP
int
main()
{
	xkrb5_conf_parse_file();
	return 0;
}
#endif
