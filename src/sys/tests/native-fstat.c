#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <moto_rt.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static int fail(const char *message) {
	fprintf(stderr, "native-fstat: %s\n", message);
	return 1;
}

static int check_stdio(int terminal) {
	for (int fd = 0; fd < 3; ++fd) {
		struct stat st;
		if (fstat(fd, &st)) {
			int saved_errno = errno;
			moto_file_attr_t attr;
			int raw = moto_rt_fstat(fd, &attr);
			fprintf(stderr,
			        "native-fstat: fd %d: fstat errno %d; raw %d, type %u, id %llu:%llu\n",
			        fd, saved_errno, raw, raw ? 0 : attr.file_type,
			        (unsigned long long)(raw ? 0 : attr.entry_id_hi),
			        (unsigned long long)(raw ? 0 : attr.entry_id_lo));
			return fail("fstat on standard descriptor failed");
		}
		if (terminal ? !S_ISCHR(st.st_mode) : !S_ISFIFO(st.st_mode))
			return fail("standard descriptor has the wrong type");
		if (!st.st_ino)
			return fail("standard descriptor has no identity");
		if (!!isatty(fd) != terminal)
			return fail("isatty disagrees with the requested mode");
	}
	return 0;
}

static int check_pseudo_sockets(void) {
	struct stat st;
	int tcp = socket(AF_INET, SOCK_STREAM, 0);
	if (tcp < 0 || fstat(tcp, &st) || !S_ISSOCK(st.st_mode))
		return fail("fresh TCP socket does not report S_IFSOCK");
	if (fstatat(tcp, "", &st, AT_EMPTY_PATH) || !S_ISSOCK(st.st_mode))
		return fail("AT_EMPTY_PATH does not report S_IFSOCK");
	if (close(tcp))
		return fail("closing TCP socket failed");
	errno = 0;
	if (!fstat(tcp, &st) || errno != EBADF)
		return fail("closed TCP socket did not report EBADF");

	int udp = socket(AF_INET, SOCK_DGRAM, 0);
	if (udp < 0 || fstat(udp, &st) || !S_ISSOCK(st.st_mode))
		return fail("fresh UDP socket does not report S_IFSOCK");
	struct sockaddr_in local;
	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(udp, (struct sockaddr *)&local, sizeof(local)))
		return fail("fstat auto-bound the fresh UDP socket");
	if (fstat(udp, &st) || !S_ISSOCK(st.st_mode))
		return fail("bound UDP socket does not report S_IFSOCK");
	if (close(udp))
		return fail("closing UDP socket failed");
	return 0;
}

int main(int argc, char **argv) {
	int terminal = argc == 2 && !strcmp(argv[1], "pty");
	if (argc > 2 || (argc == 2 && !terminal))
		return fail("usage: native-fstat [pty]");
	if (moto_rt_version() != MOTO_RT_VERSION)
		return fail("moto_rt.h and the linked shim disagree");
	if (check_stdio(terminal))
		return 1;

	struct stat st;
	errno = 0;
	if (!fstat(-1, &st) || errno != EBADF)
		return fail("invalid descriptor did not report EBADF");
	if (!terminal && check_pseudo_sockets())
		return 1;

	puts("native-fstat PASS");
	return 0;
}
