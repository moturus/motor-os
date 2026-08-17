#define _GNU_SOURCE

#include <assert.h>
#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static void check_tmp(const char *expected) {
	char name[L_tmpnam];
	assert(tmpnam(name) == name);
	assert(strncmp(name, expected, strlen(expected)) == 0);

	FILE *file = tmpfile();
	assert(file);
	assert(fputs("temporary file", file) >= 0);
	assert(fclose(file) == 0);
}

int main(void) {
	assert(strcmp(P_tmpdir, "/user/tmp") == 0);
	assert(strcmp(_PATH_DEFPATH, "/system/bin:/user/bin") == 0);
	assert(strcmp(_PATH_STDPATH, "/system/bin:/user/bin") == 0);
	assert(strcmp(_PATH_BSHELL, "/system/bin/sh") == 0);
	assert(strcmp(_PATH_TMP, "/user/tmp/") == 0);

	char path[64];
	size_t path_len = confstr(_CS_PATH, path, sizeof(path));
	assert(path_len == strlen("/system/bin:/user/bin") + 1);
	assert(strcmp(path, "/system/bin:/user/bin") == 0);

	assert(unsetenv("TMPDIR") == 0);
	check_tmp("/user/tmp/");
	assert(setenv("TMPDIR", "/devtools/tmp", 1) == 0);
	check_tmp("/devtools/tmp/");

	setusershell();
	assert(strcmp(getusershell(), "/system/bin/sh") == 0);
	assert(strcmp(getusershell(), "/system/bin/rush") == 0);
	assert(getusershell() == NULL);
	endusershell();

	int status = system("true");
	assert(WIFEXITED(status));
	assert(WEXITSTATUS(status) == 0);

	puts("native-temp PASS");
	return 0;
}
