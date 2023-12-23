// gcc -o test test.c -fPIC -fPIE
// gcc -o test_nopie test.c -no-pie
#include <stdio.h>
int main( int argc, const char* argv[] )
{
	for( int i = 0; i < argc; i++ )
	{
		printf( "arg %d: %s\n", i, argv[i] );
	}
}