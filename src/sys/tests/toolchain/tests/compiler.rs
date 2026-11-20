use crate::support::{Scratch, command, compile, interactive, output, success};

pub fn run() {
    let scratch = Scratch::new("native-compiler");
    let root = &scratch.0;
    for (tool, source, executable, expected) in [
        (
            "cc",
            "hello.c",
            "hello-c",
            "Hello from Motor-native clang!\n",
        ),
        (
            "c++",
            "hello.cpp",
            "hello-cpp",
            "Hello from Motor-native clang++!\n",
        ),
        (
            "rustc",
            "hello.rs",
            "hello-rust",
            "hello from rustc running natively on motor os\n10! = 3628800\n",
        ),
        (
            "clippy-driver",
            "hello.rs",
            "hello-clippy",
            "hello from rustc running natively on motor os\n10! = 3628800\n",
        ),
    ] {
        compile(
            root,
            &format!("/user/bin/dev/{tool}"),
            &[&format!("/none/dev/hello-world/{source}"), "-o", executable],
        );
        assert_eq!(
            success(&mut command(root, &format!("./{executable}")), b"").stdout,
            expected.as_bytes()
        );
    }
    success(command(root, "/user/bin/dev/ar").arg("--version"), b"");
    for (name, text) in SOURCES {
        scratch.write(name, text);
    }
    for (tool, source, executable) in [
        ("cc", "native-fstat.c", "fstat"),
        ("cc", "native-temp.c", "temp"),
        ("c++", "native-temp.cpp", "temp-cpp"),
    ] {
        compile(
            root,
            &format!("/user/bin/dev/{tool}"),
            &[source, "-o", executable],
        );
    }
    success(&mut command(root, "./fstat"), b"");
    success(
        command(root, "./fstat")
            .env("MOTURUS_STDIO_IS_TERMINAL", "true")
            .arg("pty"),
        b"",
    );
    for executable in ["./temp", "./temp-cpp"] {
        let mut check = command(root, executable);
        if interactive() {
            check.env("MOTOR_TEST_INTERACTIVE", "1");
        }
        success(&mut check, b"");
    }
    let bad = output(
        command(root, "/user/bin/dev/cc")
            .env("MOTOR_OS_CAPS", "0x204")
            .arg("--motor-invalid-option"),
        b"",
    );
    assert!(!bad.status.success(), "{bad:?}");
    assert!(
        String::from_utf8_lossy(&bad.stderr).contains("unknown argument"),
        "{bad:?}"
    );

    scratch.write(
        "temp.rs",
        "fn main() { println!(\"{}\", std::env::temp_dir().display()); }\n",
    );
    compile(root, "/user/bin/dev/rustc", &["temp.rs", "-o", "rust-temp"]);
    // The explicit environment wins in either role; the runtime supplies each
    // role's TMPDIR before a child starts when none was provided.
    let explicit = success(command(root, "./rust-temp").env("TMPDIR", root), b"");
    assert_eq!(
        String::from_utf8(explicit.stdout).unwrap().trim(),
        root.to_str().unwrap()
    );
    let fallback = success(command(root, "./rust-temp").env_remove("TMPDIR"), b"");
    assert_eq!(
        String::from_utf8(fallback.stdout).unwrap().trim(),
        if interactive() {
            "/user/tmp"
        } else {
            "/none/tmp"
        }
    );
    println!("native C, C++, Rust, libc and descriptor checks: PASS");
}

const SOURCES: &[(&str, &str)] = &[
    (
        "native-fstat.c",
        r####"#define _GNU_SOURCE

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
"####,
    ),
    (
        "native-temp.c",
        r####"#define _GNU_SOURCE

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
	assert(strcmp(_PATH_DEFPATH, "/user/bin") == 0);
	assert(strcmp(_PATH_STDPATH, "/user/bin") == 0);
	assert(strcmp(_PATH_BSHELL, "/user/bin/sh") == 0);
	assert(strcmp(_PATH_TMP, "/user/tmp/") == 0);

	char path[64];
	size_t path_len = confstr(_CS_PATH, path, sizeof(path));
	assert(path_len == strlen("/user/bin") + 1);
	assert(strcmp(path, "/user/bin") == 0);

	assert(unsetenv("TMPDIR") == 0);
	if (getenv("MOTOR_TEST_INTERACTIVE")) check_tmp("/user/tmp/");
	assert(setenv("TMPDIR", "/none/tmp", 1) == 0);
	check_tmp("/none/tmp/");

	setusershell();
	assert(strcmp(getusershell(), "/user/bin/sh") == 0);
	assert(strcmp(getusershell(), "/user/bin/rush") == 0);
	assert(getusershell() == NULL);
	endusershell();

	int status = system("true");
	assert(WIFEXITED(status));
	assert(WEXITSTATUS(status) == 0);

	FILE *pipe = popen("printf native-popen", "r");
	assert(pipe);
	char output[32];
	assert(fgets(output, sizeof(output), pipe) == output);
	assert(strcmp(output, "native-popen") == 0);
	status = pclose(pipe);
	assert(WIFEXITED(status));
	assert(WEXITSTATUS(status) == 0);

	puts("native-temp PASS");
	return 0;
}
"####,
    ),
    (
        "native-temp.cpp",
        r####"#include <cassert>
#include <cstdlib>
#include <filesystem>
#include <iostream>

int main() {
	assert(unsetenv("TMPDIR") == 0);
	assert(unsetenv("TMP") == 0);
	assert(unsetenv("TEMP") == 0);
	assert(unsetenv("TEMPDIR") == 0);
	assert(std::filesystem::temp_directory_path() == "/user/tmp");

	assert(setenv("TMPDIR", "/none/tmp", 1) == 0);
	assert(std::filesystem::temp_directory_path() == "/none/tmp");

	std::cout << "native-temp-cpp PASS\n";
	return 0;
}
"####,
    ),
];
