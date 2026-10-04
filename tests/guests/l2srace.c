/* Many processes making the first link to one file at the same moment.
 *
 * Under chroot-ng -l a file's first link moves its contents into the hidden
 * store and leaves a symlink in its place, and a second process asking for a
 * link of that same name at that same moment used to see the plain file it
 * had been a moment ago: it moved the symlink onto the data file, which was
 * then a symlink to itself, and the contents were gone ("Symbolic link loop"
 * from every name of the group). The first link took no lock; every later
 * one did, which is why the failure needs a file nobody has linked yet.
 *
 * Each round makes a fresh file and releases PROCS children together, each
 * linking it under a name of its own, and then judges the result as a kernel's
 * would be: every link succeeded, every name reads the file's contents, and
 * the link count is the number of names. One line is printed; the caller
 * compares it with the line a correct run prints.
 *
 * usage: l2srace ROUNDS PROCS */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAXPROCS 64

/* Does `path` read as exactly `want`, and is it one of `nlink` names? */
static int judge(const char *path, const char *want, int nlink, int *unreadable,
                 int *badcount) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        (*unreadable)++;
        return -1;
    }
    char buf[64];
    ssize_t n = read(fd, buf, sizeof buf - 1);
    if (n < 0)
        n = 0;
    buf[n] = '\0';
    if (strcmp(buf, want) != 0)
        (*unreadable)++;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_nlink != (nlink_t)nlink)
        (*badcount)++;
    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: l2srace ROUNDS PROCS\n");
        return 2;
    }
    int rounds = atoi(argv[1]), procs = atoi(argv[2]);
    if (rounds < 1 || procs < 1 || procs > MAXPROCS) {
        fprintf(stderr, "l2srace: ROUNDS >= 1, 1 <= PROCS <= %d\n", MAXPROCS);
        return 2;
    }
    int linkfail = 0, unreadable = 0, badcount = 0, broken = 0;
    for (int r = 0; r < rounds; r++) {
        char name[32], want[32];
        snprintf(name, sizeof name, "r%d", r);
        snprintf(want, sizeof want, "data%d", r);
        int fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0 || write(fd, want, strlen(want)) < 0) {
            perror(name);
            return 1;
        }
        close(fd);

        /* ready: each child says it is at the line; gate: held shut until all
         * have, then closed, which releases every read at once. */
        int ready[2], gate[2];
        if (pipe(ready) != 0 || pipe(gate) != 0) {
            perror("pipe");
            return 1;
        }
        pid_t pid[MAXPROCS];
        int started = 0;
        for (int k = 0; k < procs; k++) {
            pid[k] = fork();
            if (pid[k] < 0) {
                perror("fork");
                break;
            }
            if (pid[k] == 0) {
                char ln[64], b = 0;
                snprintf(ln, sizeof ln, "%s.%d", name, k);
                close(ready[0]);
                close(gate[1]);
                if (write(ready[1], "x", 1) != 1)
                    _exit(3);
                if (read(gate[0], &b, 1) < 0)
                    _exit(3);
                _exit(link(name, ln) == 0 ? 0 : 1);
            }
            started++;
        }
        close(ready[1]);
        close(gate[0]);
        char b;
        for (int k = 0; k < started; k++)
            if (read(ready[0], &b, 1) != 1)
                break;
        close(ready[0]);
        close(gate[1]); /* released */

        int linked = 0;
        char ok[MAXPROCS] = {0};
        for (int k = 0; k < started; k++) {
            int status = 0;
            if (waitpid(pid[k], &status, 0) < 0 || !WIFEXITED(status) ||
                WEXITSTATUS(status) > 1)
                broken++;
            else if (WEXITSTATUS(status) == 1)
                linkfail++;
            else {
                ok[k] = 1;
                linked++;
            }
        }
        if (started != procs)
            broken++;

        judge(name, want, linked + 1, &unreadable, &badcount);
        for (int k = 0; k < started; k++) {
            if (!ok[k])
                continue;
            char ln[64];
            snprintf(ln, sizeof ln, "%s.%d", name, k);
            judge(ln, want, linked + 1, &unreadable, &badcount);
        }
    }
    printf("l2srace rounds=%d procs=%d linkfail=%d unreadable=%d badcount=%d "
           "broken=%d\n",
           rounds, procs, linkfail, unreadable, badcount, broken);
    return 0;
}
