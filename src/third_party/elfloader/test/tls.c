// gcc -o tls tls.c -fPIC -fPIE
#include <stdio.h>

__thread int tbss_entry = 0;
__thread int tdata_entry = 0xdeadbeef;

int main( int argc, const char* argv[] )
{
	for( int i = 0; i < argc; i++ )
	{
		printf( "arg %d: %s\n", i, argv[i] );
	}

	printf("arg %d %d", tbss_entry, tdata_entry);
}