#include <dlfcn.h>
#include <stdio.h>
/* Simple program to see if dlopen() would succeed. */
int main(int argc, char **argv)
{
	int i;
	for(i = 1; i < argc; i++) {
		if(dlopen(argv[i], RTLD_NOW)) {
			fprintf(stdout, "dlopen() of \"%s\" succeeded.\n",
				argv[i]);
		} else {
			fprintf(stdout, "dlopen() of \"%s\" failed: %s\n",
				argv[i], dlerror());
		}
	}
	return 0;
}
