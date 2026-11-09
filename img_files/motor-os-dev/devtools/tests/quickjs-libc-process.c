#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <moto_rt.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "--child")) {
        char cwd[4096];
        assert(getcwd(cwd, sizeof(cwd)) && !strcmp(cwd, "/user/tmp"));
        assert(getenv("QJS_LIBC_PROBE") && !strcmp(getenv("QJS_LIBC_PROBE"), "native"));
        puts("native libc child");
        return 17;
    }

    char executable[4096], parent_cwd[4096], current_cwd[4096];
    size_t size = sizeof(executable);
    assert(moto_rt_exepath((uint8_t *)executable, &size) == 0);
    assert(getcwd(parent_cwd, sizeof(parent_cwd)));
    char *args[] = {executable, "--child", NULL};
    char *env[] = {"QJS_LIBC_PROBE=native", NULL};
    posix_spawn_file_actions_t actions;
    assert(posix_spawn_file_actions_init(&actions) == 0);
    assert(posix_spawn_file_actions_addchdir_np(&actions, "/user/tmp") == 0);
    assert(posix_spawn_file_actions_addopen(&actions, 1, "quickjs-libc-child.out",
                                          O_WRONLY | O_CREAT | O_TRUNC, 0600) == 0);
    pid_t pid;
    assert(posix_spawn(&pid, executable, &actions, NULL, args, env) == 0);
    assert(posix_spawn_file_actions_destroy(&actions) == 0);
    int status = 0;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 17);
    assert(waitpid(pid, &status, 0) == -1 && errno == ECHILD);
    assert(getcwd(current_cwd, sizeof(current_cwd)) && !strcmp(parent_cwd, current_cwd));
    FILE *out = fopen("/user/tmp/quickjs-libc-child.out", "r");
    char line[64];
    assert(out && fgets(line, sizeof(line), out) && !strcmp(line, "native libc child\n"));
    assert(fclose(out) == 0 && unlink("/user/tmp/quickjs-libc-child.out") == 0);

    char *sleep_args[] = {"sysbox", "sleep", "60", NULL};
    assert(posix_spawnp(&pid, "sysbox", NULL, NULL, sleep_args, environ) == 0);
    assert(waitpid(-1, &status, WNOHANG) == 0);
    assert(kill(pid, 0) == 0 && kill(pid, SIGKILL) == 0);
    assert(waitpid(-1, &status, 0) == pid);
    assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    assert(kill(pid, 0) == -1 && errno == ESRCH);

    FILE *pipe = popen("printf 'native libc popen'", "r");
    assert(pipe && fgets(line, sizeof(line), pipe) && !strcmp(line, "native libc popen"));
    assert(pclose(pipe) == 0);
    pipe = popen("exit 7", "r");
    assert(pipe && waitpid(-1, &status, 0) > 0);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 7);
    assert(pclose(pipe) == -1 && errno == ECHILD);

    // open() gives a new writable file its execute bits. Other files keep theirs.
    const char *path = "/user/tmp/quickjs-libc-mode";
    unlink(path);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0755);
    assert(fd >= 0 && access(path, X_OK) == 0 && access(path, W_OK) == 0);
    assert(write(fd, "x", 1) == 1 && close(fd) == 0 && unlink(path) == 0);
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    assert(fd >= 0 && access(path, X_OK) == -1 && close(fd) == 0);
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    assert(fd >= 0 && access(path, X_OK) == -1);
    // fchmod can widen rw- to rwx, which Motor allows only through r-x.
    assert(fchmod(fd, 0755) == 0 && access(path, X_OK) == 0 && access(path, W_OK) == 0);
    assert(close(fd) == 0 && unlink(path) == 0);
    // A new read-only mode is not applied: the caller may still write to the fd.
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0555);
    assert(fd >= 0 && write(fd, "x", 1) == 1 && close(fd) == 0 && unlink(path) == 0);
    puts("quickjs libc process APIs: PASS");
    return 0;
}
