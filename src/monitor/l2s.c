/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* link2symlink backing-file scheme (see include/cng/l2s.h). Freestanding: raw
 * syscalls + the cng runtime string helpers only, so it is safe to run inside
 * the SIGSYS handler. Every path here is an already-resolved host path. */
#include "cng/l2s.h"
#include "cng/monitor.h"
#include "cng/path.h"
#include "cng/pin.h"
#include "cng/rt.h"
#include "cng/syscall.h"
#include "cng/uapi.h"

#include <asm-generic/errno.h>

int cng_g_l2s = 0;
int cng_g_l2s_force = 0;

#define L2S_PREFIX     ".l2s."
#define L2S_PREFIX_LEN 5

/* Failure-path diagnostics (CNG_DEBUG=1). */
#define L2S_LOG(...)                                                          \
    do {                                                                      \
        if (cng_g_debug)                                                      \
            cng_dprintf(2, __VA_ARGS__);                                      \
    } while (0)

/* aarch64 struct stat field offsets (see dispatch.c). */
#define ST_INO_OFF   8
#define ST_MODE_OFF  16
#define ST_NLINK_OFF 20
#define ST_SIZE      128
/* struct statx field offsets. */
#define STX_MASK_OFF  0
#define STX_NLINK_OFF 16
#define STX_MODE_OFF  28
#define STX_SIZE      256

#define S_IFMT_  0170000
#define S_IFLNK_ 0120000
#define S_IFREG_ 0100000
#define S_IFDIR_ 0040000

/* ---- syscall wrappers (host paths) -------------------------------------- */

/* Every path here is a host path derived from a guest name, so each is
 * handed to the kernel pinned (cng/pin.h): against the directory the walk
 * reached, never as a string for the kernel to resolve again. */
static long l2s_lstat(const char *p, void *st) {
    return cng_pin_fstatat(p, st, CNG_AT_SYMLINK_NOFOLLOW);
}
static long l2s_statf(const char *p, void *st) { /* follow */
    return cng_pin_fstatat(p, st, 0);
}
static long l2s_readlink(const char *p, char *b, size_t n) {
    return cng_pin_readlink(p, b, n);
}
static long l2s_symlink(const char *target, const char *linkpath) {
    return cng_pin_symlink(target, linkpath);
}
static long l2s_rename(const char *o, const char *n) {
    return cng_pin_rename(o, n);
}
static long l2s_unlink(const char *p) { return cng_pin_unlink(p, 0); }
static void l2s_touch(const char *p) {
    long fd = cng_pin_open(p, CNG_O_WRONLY | CNG_O_CREAT | CNG_O_CLOEXEC, 0600);
    if (fd >= 0)
        sys_close((int)fd);
}

static unsigned st_mode(const void *st) {
    return *(const unsigned *)((const char *)st + ST_MODE_OFF);
}
static int is_lnk(const void *st) { return (st_mode(st) & S_IFMT_) == S_IFLNK_; }
static int is_reg(const void *st) { return (st_mode(st) & S_IFMT_) == S_IFREG_; }
static int is_dir(const void *st) { return (st_mode(st) & S_IFMT_) == S_IFDIR_; }

/* ---- name parsing / formatting ------------------------------------------ */

/* Parse a run of decimal digits, setting *end past it: 0 for no digits, 1 for
 * a run whose value is in *out, 2 for one whose value does not fit in 64 bits
 * (*out untouched). The value used to be accumulated modulo 2^64, so a name
 * spelling ino + 2^64 parsed as ino. */
static int parse_u64(const char *p, unsigned long long *out, const char **end) {
    unsigned long long v = 0;
    const char *s = p;
    int wide = 0;
    while (*p >= '0' && *p <= '9') {
        unsigned d = (unsigned)(*p - '0');
        if (v > (~0ULL - d) / 10)
            wide = 1;
        else
            v = v * 10 + d;
        p++;
    }
    if (p == s)
        return 0;
    if (end)
        *end = p;
    if (wide)
        return 2;
    if (out)
        *out = v;
    return 1;
}

/* A number field of the names below. The grammar — what cng_l2s_hidden hides
 * and refuses — is any digit run, however long, and a caller asking only that
 * passes no `out`; one that wants the number gets it only if there is one. */
static int parse_field(const char *p, unsigned long long *out,
                       const char **end) {
    int r = parse_u64(p, out, end);
    return r == 1 || (r == 2 && !out);
}

/* ".l2s.<ino>" exactly (data backing file). */
static int parse_data(const char *name, unsigned long long *ino) {
    if (strncmp(name, L2S_PREFIX, L2S_PREFIX_LEN))
        return 0;
    const char *end;
    if (!parse_field(name + L2S_PREFIX_LEN, ino, &end))
        return 0;
    return *end == '\0';
}

/* ".l2s.<ino>.<count>" (marker). */
static int parse_marker(const char *name, unsigned long long *ino,
                        unsigned long *count) {
    if (strncmp(name, L2S_PREFIX, L2S_PREFIX_LEN))
        return 0;
    const char *end;
    unsigned long long v, c;
    int want = ino || count;
    if (!parse_field(name + L2S_PREFIX_LEN, want ? &v : 0, &end) ||
        *end != '.')
        return 0;
    if (!parse_field(end + 1, want ? &c : 0, &end) || *end != '\0')
        return 0;
    if (ino)
        *ino = v;
    if (count)
        *count = (unsigned long)c;
    return 1;
}

int cng_l2s_hidden(const char *name) {
    return parse_data(name, 0) || parse_marker(name, 0, 0);
}

static const char *l2s_basename(const char *path) {
    const char *s = strrchr(path, '/');
    return s ? s + 1 : path;
}

/* Directory portion of `path` into `dir` ("/" for a root child). */
static void l2s_dirname(const char *path, char *dir, size_t sz) {
    const char *s = strrchr(path, '/');
    if (!s || s == path) {
        cng_strlcpy(dir, "/", sz);
        return;
    }
    size_t dl = (size_t)(s - path);
    if (dl >= sz)
        dl = sz - 1;
    memcpy(dir, path, dl);
    dir[dl] = '\0';
}

/* Append an unsigned decimal, zero-padded to at least `width`, at *pp — storing
 * only what fits before `end`, but advancing *pp by the whole width either way.
 * That advance is what makes the caller's `p > end` test see an overflow: with
 * *pp stopped at `end` instead, a name whose digits did not fit came back
 * shortened and *valid*, so ".l2s.<ino>" silently became another group's
 * backing file rather than -ENAMETOOLONG. */
static void put_u64(char **pp, char *end, unsigned long long v, int width) {
    char tmp[24];
    int n = 0;
    do {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    } while (v);
    while (n < width)
        tmp[n++] = '0';
    char *p = *pp;
    while (n > 0) {
        if (p < end)
            *p = tmp[n - 1];
        n--;
        p++;
    }
    *pp = p;
}

/* ".l2s.<ino>" exactly as build_name writes it: the digits of the number and
 * nothing else — no leading zero, no run a parse would wrap. parse_data takes
 * any digit run, which is the right grammar for the names that are hidden and
 * refused, but not for the ones followed: ".l2s.07" is not ".l2s.7", and a
 * link spelling one must not be taken for a link to the other. */
static int parse_data_exact(const char *name, unsigned long long *ino) {
    unsigned long long v;
    if (!parse_data(name, &v))
        return 0;
    char tmp[24], *p = tmp;
    put_u64(&p, tmp + sizeof tmp - 1, v, 1);
    *p = '\0';
    if (strcmp(tmp, name + L2S_PREFIX_LEN) != 0)
        return 0;
    if (ino)
        *ino = v;
    return 1;
}

/* ".l2s.<ino>.<count>" exactly as build_name writes it: the inode with no
 * leading zero, the count zero-padded to four digits and no wider — the one
 * marker name a group has. find_marker used to take any name of the grammar
 * whose number came out equal, and the numbers came out equal for spellings
 * no marker of ours ever had: ".l2s.<ino + 2^64>.<n>" (the parse wrapped),
 * ".l2s.<ino>.5" or ".l2s.0<ino>.0005". A tree carrying one — a rootfs from
 * elsewhere; the guest cannot make such a name — had its count read from the
 * stray, which the next update then failed to rename (it renames the
 * canonical name), or which outvoted the real marker, whichever the directory
 * listed first. */
static int parse_marker_exact(const char *name, unsigned long long *ino,
                              unsigned long *count) {
    unsigned long long v;
    unsigned long c;
    if (!parse_marker(name, &v, &c))
        return 0;
    char tmp[48], *p = tmp, *end = tmp + sizeof tmp - 1;
    put_u64(&p, end, v, 1);
    if (p < end)
        *p++ = '.';
    put_u64(&p, end, (unsigned long long)c, 4);
    if (p > end)
        return 0;
    *p = '\0';
    if (strcmp(tmp, name + L2S_PREFIX_LEN) != 0)
        return 0;
    if (ino)
        *ino = v;
    if (count)
        *count = c;
    return 1;
}

/* "<dir>/.l2s.<ino>" (count < 0) or "<dir>/.l2s.<ino>.<count>" into out.
 * Returns 0 or -ENAMETOOLONG. */
static int build_name(char *out, size_t sz, const char *dir,
                      unsigned long long ino, long count) {
    char *p = out, *end = out + sz - 1;
    size_t dl = strlen(dir);
    int need_sep = !(dl && dir[dl - 1] == '/');
    p += cng_strlcpy(p, dir, (size_t)(end - p) + 1);
    if (p > end)
        return -ENAMETOOLONG;
    if (need_sep && p < end)
        *p++ = '/';
    p += cng_strlcpy(p, L2S_PREFIX, (size_t)(end - p) + 1);
    if (p >= end)
        return -ENAMETOOLONG;
    put_u64(&p, end, ino, 1);
    if (count >= 0) {
        if (p < end)
            *p++ = '.';
        put_u64(&p, end, (unsigned long long)count, 4);
    }
    if (p > end)
        return -ENAMETOOLONG;
    *p = '\0';
    return 0;
}

/* ---- directory scan for the marker -------------------------------------- */

/* linux_dirent64: d_ino(8) d_off(8) d_reclen(2 @16) d_type(1 @18) name(@19). */
static int find_marker(const char *dir, unsigned long long ino,
                       unsigned long *count) {
    long fd = cng_pin_open(dir, CNG_O_RDONLY | CNG_O_DIRECTORY | CNG_O_CLOEXEC,
                           0);
    if (fd < 0)
        return -1;
    char buf[4096];
    int found = -1;
    for (;;) {
        long n = CNG_SYS(__NR_getdents64, (int)fd, buf, sizeof buf, 0, 0, 0);
        if (n <= 0)
            break;
        long o = 0;
        while (o + 19 <= n) {
            unsigned short reclen;
            memcpy(&reclen, buf + o + 16, 2);
            if (reclen == 0 || o + reclen > n)
                break;
            const char *nm = buf + o + 19;
            unsigned long long dino;
            unsigned long dc;
            if (parse_marker_exact(nm, &dino, &dc) && dino == ino) {
                *count = dc;
                found = 0;
                break;
            }
            o += reclen;
        }
        if (found == 0)
            break;
    }
    sys_close((int)fd);
    return found;
}

/* ---- marker locking ----------------------------------------------------- */

static int l2s_store_dir(char *out, size_t sz);

/* Serialize the marker's read-modify-write (find + rename/unlink) across
 * processes sharing the rootfs, and across threads of one: an exclusive flock,
 * held for the update. Returns the locked fd, or -1.
 *
 * The lock used to be taken on the data file, opened for reading, and a data
 * file that could not be opened that way — mode 0200, mode 0000, both of which
 * a package can ship — left the update running unlocked, so two links or
 * unlinks of the group at once could leave st_nlink wrong or a backing file
 * behind. The lock is now a file of our own in the store, ".l2s/.lock" under
 * the rootfs, created 0600 in a directory we made 0700: openable by us
 * whatever mode the group's own files carry, and one lock per rootfs is the
 * right scope, since that is what the store is. The directory of the data file
 * (and, should that not open, the file itself) stands in only where the store
 * cannot be had at all — a rootfs whose root nothing can be created in, so that
 * a group lives beside its first name instead. `data` need not exist: the first
 * link of a file takes this lock before its data file does, with the name that
 * file is about to get, and the directory is the one thing that name and the
 * group it becomes have in common — which is why the directory is tried before
 * the file, whose lock the first link could not have taken. Proceeding unlocked
 * is the last resort and is logged, since it is the one outcome the scheme's
 * counts cannot survive. */
static long l2s_lock(const char *data) {
    char lk[CNG_PATH_MAX];
    long fd = -1;
    if (l2s_store_dir(lk, sizeof lk) == 0) {
        size_t n = strlen(lk);
        if (n + 7 < sizeof lk) {
            memcpy(lk + n, "/.lock", 7);
            fd = cng_pin_open(lk, CNG_O_RDWR | CNG_O_CREAT | CNG_O_CLOEXEC,
                              0600);
        }
    }
    if (fd < 0) {
        l2s_dirname(data, lk, sizeof lk);
        fd = cng_pin_open(lk, CNG_O_RDONLY | CNG_O_DIRECTORY | CNG_O_CLOEXEC,
                          0);
    }
    if (fd < 0)
        fd = cng_pin_open(data, CNG_O_RDONLY | CNG_O_CLOEXEC, 0);
    if (fd < 0)
        fd = cng_pin_open(data, CNG_O_WRONLY | CNG_O_CLOEXEC, 0);
    if (fd < 0) {
        L2S_LOG("[cng] l2s: no lock to be had for %s (%ld): unlocked update\n",
                data, fd);
        return -1;
    }
    long r;
    do {
        r = CNG_SYS(__NR_flock, (int)fd, 2 /* LOCK_EX */, 0, 0, 0, 0);
    } while (r == -EINTR);
    if (r < 0) {
        L2S_LOG("[cng] l2s: flock for %s refused (%ld): unlocked update\n",
                data, r);
        sys_close((int)fd);
        return -1;
    }
    return fd;
}

static void l2s_unlock(long fd) {
    if (fd >= 0)
        sys_close((int)fd); /* closing drops the flock */
}

/* ---- central store ------------------------------------------------------ */

/* Host path of the per-rootfs object store "<rootfs>/.l2s", created on demand
 * (0700). New link groups keep their data + marker here, and every name is a
 * symlink carrying the data file's absolute host path — so links span
 * directories and survive renames of any name or parent directory. The guest
 * never sees the store (getdents hides it, the path guard denies it).
 * Returns 0 or -errno. */
static int l2s_store_dir(char *out, size_t sz) {
    size_t n = cng_g_fs ? cng_fs_rootfs(out, sz) : cng_strlcpy(out, "", sz);
    if (n + 6 >= sz)
        return -ENAMETOOLONG;
    cng_strlcpy(out + n, "/.l2s", sz - n);
    long r = cng_pin_mkdir(out, 0700);
    if (r < 0 && r != -EEXIST)
        return (int)r;
    char st[ST_SIZE];
    if (l2s_lstat(out, st) < 0 || !is_dir(st))
        return -ENOTDIR; /* a plain file squats on the name: store unusable */
    return 0;
}

int cng_l2s_deny(long dirfd, const char *gp) {
    if (!gp || !gp[0])
        return 0;
    /* Backing data/marker names do not exist for the guest, wherever they
     * are named from. */
    if (cng_l2s_hidden(l2s_basename(gp)))
        return 1;
    /* The store dir itself: deny "/.l2s" and everything under it. Only for
     * absolute/cwd-relative paths — a ".l2s" entry elsewhere in the tree
     * stays usable, and a dirfd-relative walk can only reach the store
     * through ".." (accepted, documented). */
    if ((gp[0] == '/' || (int)dirfd == CNG_AT_FDCWD) && cng_g_fs) {
        char canon[CNG_PATH_MAX];
        if (cng_fs_abscanon(cng_g_fs, gp, canon, sizeof canon) == 0 &&
            !strncmp(canon, "/.l2s", 5) &&
            (canon[5] == '\0' || canon[5] == '/'))
            return 1;
    }
    return 0;
}

/* ---- which links are ours ------------------------------------------------
 *
 * A link is recognized by its target, and a target is text: the kernel keeps
 * whatever symlinkat was given, and the guest calls symlinkat too. Taken on
 * its word — any target whose last component parsed as ".l2s.<digits>" —
 * that text named the file every no-follow call was then redirected to: a
 * guest's `ln -s /elsewhere/on/the/host/.l2s.1 x` made lstat of x describe a
 * host file outside the rootfs, chown and utimensat change it, an O_NOFOLLOW
 * open read and write it, and unlink delete it — another rootfs's store is
 * exactly such a place. So a target is only ours where it names a data file
 * the emulation could have written, which is one of:
 *
 *  - a bare ".l2s.<ino>": the legacy same-directory link, its data beside it;
 *  - an absolute path, in canonical form, to a data file in a place of the
 *    guest's own (l2s_owned): this rootfs's store, a legacy group joined from
 *    another directory, a group in a bind;
 *  - an absolute path into some other "<dir>/.l2s" store, which is what a
 *    link carries after its rootfs tree was moved or copied: it self-heals
 *    onto this rootfs's store under the same name, and the file it named is
 *    never looked at.
 *
 * and the data file has to be there, a regular file. Everything else is an
 * ordinary symlink, whatever its last component says. The guest can no longer
 * write such a target at all (the symlinkat refusal in dispatch.c); this is
 * what keeps a tree that already holds one — from before that refusal, from
 * the host, from another tool — from being read the old way. */

/* The view chroot-ng was started with: run.c's, never written after it is
 * published. A guest chroot narrows the view, and a group linked before it
 * keeps its data where the wider view put it. 0 in the unit harness. */
static const struct cng_fs *g_home;

void cng_l2s_home(const struct cng_fs *fs) { g_home = fs; }

/* A place of the guest's own: somewhere the view names (the rootfs, a bind,
 * the /dev/shm stand-in — cng_host_dir_guest), or somewhere the view it was
 * started with named. `p` is canonical, so a prefix is a containment. */
static int l2s_owned(const char *p) {
    if (!cng_g_fs)
        return 1; /* no view at all: the host root is the rootfs */
    char g[CNG_PATH_MAX];
    if (cng_host_dir_guest(p, g, sizeof g) == 0)
        return 1;
    return g_home && cng_fs_untranslate(g_home, p, g, sizeof g) == 0;
}

/* Absolute, and no empty, "." or ".." component, no trailing slash: the form
 * of every target this file writes (the store path and the walk's host paths
 * both are), and the only one whose prefix says where it leads. */
static int l2s_canonical(const char *p) {
    if (p[0] != '/')
        return 0;
    for (const char *c = p + 1;;) {
        const char *e = c;
        while (*e && *e != '/')
            e++;
        size_t n = (size_t)(e - c);
        if (n == 0 || (n == 1 && c[0] == '.') ||
            (n == 2 && c[0] == '.' && c[1] == '.'))
            return 0;
        if (!*e)
            return 1;
        c = e + 1;
    }
}

/* "<dir>/.l2s/.l2s.<ino>": a data file in some rootfs's store. */
static int l2s_store_shaped(const char *p) {
    const char *b = l2s_basename(p);
    return b - p >= 6 && !strncmp(b - 6, "/.l2s/", 6);
}

/* The data file the link at `host` names by `tgt`, into `data`: 1 (ours), 0
 * (an ordinary symlink), or -ENAMETOOLONG. *heal is set when the target is a
 * stale store path and `data` is where this rootfs's store has it: the link
 * should be repointed. */
static int l2s_locate(const char *host, const char *tgt, char *data,
                      size_t dsz, int *heal) {
    char st[ST_SIZE];
    const char *b = l2s_basename(tgt);
    *heal = 0;
    if (!parse_data_exact(b, 0))
        return 0;
    if (tgt[0] != '/') {
        if (b != tgt)
            return 0; /* a relative target of ours is the bare name */
        char dir[CNG_PATH_MAX];
        l2s_dirname(host, dir, sizeof dir);
        size_t dl = strlen(dir);
        int sep = !(dl && dir[dl - 1] == '/');
        if (dl + (size_t)sep + strlen(b) >= dsz)
            return -ENAMETOOLONG;
        memcpy(data, dir, dl);
        if (sep)
            data[dl++] = '/';
        cng_strlcpy(data + dl, b, dsz - dl);
        return l2s_lstat(data, st) == 0 && is_reg(st);
    }
    if (!l2s_canonical(tgt))
        return 0;
    if (l2s_owned(tgt)) {
        if (cng_strlcpy(data, tgt, dsz) >= dsz)
            return -ENAMETOOLONG;
        if (l2s_lstat(data, st) == 0 && is_reg(st))
            return 1;
    }
    if (!l2s_store_shaped(tgt))
        return 0;
    char store[CNG_PATH_MAX];
    if (l2s_store_dir(store, sizeof store) != 0)
        return 0;
    size_t sl = strlen(store);
    if (sl + 1 + strlen(b) >= dsz)
        return -ENAMETOOLONG;
    memcpy(data, store, sl);
    data[sl] = '/';
    cng_strlcpy(data + sl + 1, b, dsz - sl - 1);
    if (!strcmp(data, tgt) || l2s_lstat(data, st) != 0 || !is_reg(st))
        return 0; /* dangling: just an ordinary symlink */
    *heal = 1;
    return 1;
}

/* ---- proot's groups ------------------------------------------------------
 *
 * A rootfs installed through proot (proot-distro's) holds its hardlinks in
 * proot's link2symlink scheme, not the one above:
 *
 *   member       any name of the group: a symlink holding an absolute HOST path,
 *                <rootfs>/.l2s/.l2s.<name><NNNN>   (the indirection)
 *   indirection  a symlink in the l2s directory holding the host path of
 *                <rootfs>/.l2s/.l2s.<name><NNNN>.<CCCC>   (the data file)
 *   data         the real file, beside the indirection. CCCC is the live link
 *                count: a name added or removed renames it, and the
 *                indirection is re-pointed (which is why members name the
 *                indirection, whose name never changes).
 *
 * <name> is the file's base name and may be digits, so a proot name can have
 * the shape of one of ours (".l2s.<ino>" is "<name><NNNN>" whenever the inode
 * has five digits or more). The two are told apart by what they ARE, not by
 * their spelling: ours is a regular file, proot's indirection a symlink.
 * New groups are still made in our scheme; these are read, presented and kept
 * as proot keeps them, so a rootfs can move between proot and chroot-ng.
 *
 * The symlinks are the guest's to write, so a member is one only if the WHOLE
 * chain checks out: the text is a canonical absolute path to a ".l2s." name
 * that names a place of this rootfs (a path under it, or the store of a
 * rootfs it was moved from, which is read as this one's), resolved as a guest
 * path — through the containment walk, so binds and a symlinked l2s directory
 * work and a ".." cannot climb out — to a symlink; whose own text is in the
 * same directory, names "<ind>.<NNNN>"; which is a regular file there.
 * Anything else is an ordinary symlink. Nothing the text says is ever opened
 * as a string: every name after the walk is a bare name in the directory it
 * reached. */

#define PR_NAME_MAX  200  /* longest indirection basename */
#define PR_MAX_COUNT 9999 /* four digits */

static size_t pr_prefix_len(const char *name) {
    static const char *const pre[] = {".l2s.", ".proot.l2s."};
    for (unsigned i = 0; i < 2; i++) {
        size_t n = strlen(pre[i]);
        if (!strncmp(name, pre[i], n))
            return n;
    }
    return 0;
}

static int pr_four_digits(const char *s) {
    for (int i = 0; i < 4; i++)
        if (s[i] < '0' || s[i] > '9')
            return 0;
    return 1;
}

static unsigned long pr_count_of(const char *s) {
    unsigned long c = 0;
    for (int i = 0; i < 4; i++)
        c = c * 10 + (unsigned long)(s[i] - '0');
    return c;
}

/* "<prefix><name><NNNN>", a name of at least one character. */
static int pr_is_ind(const char *name) {
    size_t pl = pr_prefix_len(name), n = strlen(name);
    return pl && n <= PR_NAME_MAX && n >= pl + 1 + 4 &&
           pr_four_digits(name + n - 4);
}

/* "<indirection>.<NNNN>". */
static int pr_is_data(const char *name, unsigned long *count) {
    size_t n = strlen(name);
    if (n < 6 || n - 5 > PR_NAME_MAX || name[n - 5] != '.' ||
        !pr_four_digits(name + n - 4))
        return 0;
    char ind[PR_NAME_MAX + 1];
    memcpy(ind, name, n - 5);
    ind[n - 5] = '\0';
    if (!pr_is_ind(ind))
        return 0;
    if (count)
        *count = pr_count_of(name + n - 4);
    return 1;
}

/* Is `dn` exactly "<ind>.<NNNN>"? */
static int pr_data_of(const char *dn, const char *ind, unsigned long *count) {
    size_t il = strlen(ind);
    if (strncmp(dn, ind, il) || dn[il] != '.' || !pr_four_digits(dn + il + 1) ||
        dn[il + 5])
        return 0;
    if (count)
        *count = pr_count_of(dn + il + 1);
    return 1;
}

/* Join a directory (the part of `path` before its last '/') and a name. */
static int pr_sibling(const char *path, const char *name, char *out,
                      size_t sz) {
    const char *b = l2s_basename(path);
    size_t dl = (size_t)(b - path), nl = strlen(name);
    if (dl + nl >= sz)
        return -ENAMETOOLONG;
    memcpy(out, path, dl);
    memcpy(out + dl, name, nl + 1);
    return 0;
}

/* The shape of a proot target — the text a guest may not write (see
 * cng_l2s_text_denied): absolute, canonical, ending in an indirection's or a
 * data file's name. */
static int pr_shaped(const char *tgt) {
    const char *b = l2s_basename(tgt);
    return tgt[0] == '/' && (pr_is_ind(b) || pr_is_data(b, 0)) &&
           l2s_canonical(tgt);
}

/* The guest path a proot target names: under this rootfs as it stands, or the
 * store of the rootfs it was moved from (proot recorded host paths), which is
 * this one's. 1 or 0. */
static int pr_guest(const char *tgt, char *g, size_t sz) {
    if (!cng_g_fs || !pr_shaped(tgt))
        return 0;
    if (cng_host_dir_guest(tgt, g, sz) == 0)
        return 1;
    if (!l2s_store_shaped(tgt))
        return 0;
    size_t n = cng_strlcpy(g, "/.l2s/", sz);
    if (n >= sz)
        return 0;
    return cng_strlcpy(g + n, l2s_basename(tgt), sz - n) < sz - n;
}

/* The member whose text is `tgt`. 1: ours — `data` is the data file's host
 * path, *count the live count, `indh` the indirection's host path. 0: an
 * ordinary symlink. 2: shaped like a member and the data file named is not
 * there — another process is between the two renames of a count change, or
 * one was killed there. */
static int pr_locate(const char *tgt, char *data, size_t dsz,
                     unsigned long *count, char *indh, size_t isz) {
    char g[CNG_PATH_MAX], st[ST_SIZE], t2[CNG_PATH_MAX];
    const char *ind = l2s_basename(tgt);
    if (!pr_is_ind(ind) || !pr_guest(tgt, g, sizeof g))
        return 0;
    if (cng_resolve(g, 0, indh, isz) != 0 || strcmp(l2s_basename(indh), ind))
        return 0;
    if (l2s_lstat(indh, st) < 0 || !is_lnk(st))
        return 0;
    long n = l2s_readlink(indh, t2, sizeof t2 - 1);
    if (n < 0)
        return 0;
    t2[n] = '\0';
    const char *tb = l2s_basename(t2);
    size_t dl = (size_t)(ind - tgt);
    unsigned long c;
    /* Beside the indirection, as text, and named by it. */
    if (t2[0] != '/' || (size_t)(tb - t2) != dl || strncmp(t2, tgt, dl) ||
        !pr_data_of(tb, ind, &c))
        return 0;
    if (pr_sibling(indh, tb, data, dsz) < 0)
        return 0;
    long ls = l2s_lstat(data, st);
    if (ls == -ENOENT)
        return 2;
    if (ls < 0 || !is_reg(st))
        return 0;
    *count = c;
    return 1;
}

/* The data file reached by its own name (a walk that followed a member ends
 * there): it is one if the indirection beside it is a symlink naming it.
 * Fills the indirection's host path and the count. */
static int pr_data_group(const char *host, char *indh, size_t isz,
                         unsigned long *count) {
    char st[ST_SIZE], t2[CNG_PATH_MAX], ind[PR_NAME_MAX + 1];
    const char *b = l2s_basename(host);
    unsigned long c;
    if (!l2s_canonical(host) || !l2s_owned(host) || !pr_is_data(b, &c))
        return 0;
    size_t il = strlen(b) - 5;
    memcpy(ind, b, il);
    ind[il] = '\0';
    if (pr_sibling(host, ind, indh, isz) < 0 || l2s_lstat(host, st) < 0 ||
        !is_reg(st) || l2s_lstat(indh, st) < 0 || !is_lnk(st))
        return 0;
    long n = l2s_readlink(indh, t2, sizeof t2 - 1);
    if (n < 0)
        return 0;
    t2[n] = '\0';
    if (t2[0] != '/' || strcmp(l2s_basename(t2), b))
        return 0;
    *count = c;
    return 1;
}

/* The one regular file "<ind>.<NNNN>" in the indirection's directory: 1 (name
 * in `out`), 0 (none: the group is gone), -1 (more than one: not guessed at).
 * The data file is only ever renamed, so there is one. */
static int pr_scan_data(const char *indh, char *out, size_t sz) {
    char dir[CNG_PATH_MAX], path[CNG_PATH_MAX], buf[4096], st[ST_SIZE];
    const char *ind = l2s_basename(indh);
    l2s_dirname(indh, dir, sizeof dir);
    long fd = cng_pin_open(dir, CNG_O_RDONLY | CNG_O_DIRECTORY | CNG_O_CLOEXEC,
                           0);
    if (fd < 0)
        return 0;
    int found = 0;
    for (;;) {
        long n = CNG_SYS(__NR_getdents64, (int)fd, buf, sizeof buf, 0, 0, 0);
        if (n <= 0)
            break;
        for (long o = 0; o + 19 <= n;) {
            unsigned short reclen;
            memcpy(&reclen, buf + o + 16, 2);
            if (reclen == 0 || o + reclen > n)
                break;
            const char *nm = buf + o + 19;
            if (pr_data_of(nm, ind, 0) && pr_sibling(indh, nm, path, sizeof path) == 0 &&
                l2s_lstat(path, st) == 0 && is_reg(st)) {
                if (found++) {
                    sys_close((int)fd);
                    return -1;
                }
                cng_strlcpy(out, nm, sz);
            }
            o += reclen;
        }
    }
    sys_close((int)fd);
    return found;
}

static unsigned pr_seq;

/* Point the indirection at data file `dname`: a symlink made under a name of
 * its own and renamed over the old, so the indirection is never absent. `t2`
 * is its present text, whose directory the new text keeps. */
static int pr_repoint(const char *indh, const char *t2, const char *dname) {
    char tmp[CNG_PATH_MAX], tgt[CNG_PATH_MAX], suffix[48], *p = suffix;
    const char *tb = l2s_basename(t2);
    size_t dl = (size_t)(tb - t2), nl = strlen(dname);
    if (dl + nl >= sizeof tgt)
        return -ENAMETOOLONG;
    memcpy(tgt, t2, dl);
    memcpy(tgt + dl, dname, nl + 1);
    *p++ = '.';
    *p++ = 't';
    put_u64(&p, suffix + sizeof suffix - 2, (unsigned long long)sys_gettid(), 1);
    *p++ = '.';
    put_u64(&p, suffix + sizeof suffix - 1,
            __atomic_fetch_add(&pr_seq, 1, __ATOMIC_RELAXED), 1);
    *p = '\0';
    size_t tl = cng_strlcpy(tmp, indh, sizeof tmp);
    if (tl + strlen(suffix) >= sizeof tmp)
        return -ENAMETOOLONG;
    memcpy(tmp + tl, suffix, strlen(suffix) + 1);
    l2s_unlink(tmp); /* one of ours, left by a process whose id was reused */
    long r = l2s_symlink(tgt, tmp);
    if (r < 0)
        return (int)r;
    r = l2s_rename(tmp, indh);
    if (r < 0)
        l2s_unlink(tmp);
    return (int)r;
}

/* Make a cut chain whole: the indirection names a data file that is not there
 * (a process died between the two renames of a count change), so find the one
 * there is and point at it. 0 or -errno. The caller holds the lock. */
static int pr_repair(const char *indh) {
    char t2[CNG_PATH_MAX], name[PR_NAME_MAX + 8];
    long n = l2s_readlink(indh, t2, sizeof t2 - 1);
    if (n < 0)
        return (int)n;
    t2[n] = '\0';
    int f = pr_scan_data(indh, name, sizeof name);
    if (f < 0)
        return -EIO;
    if (f == 0)
        return -ENOENT;
    return pr_repoint(indh, t2, name);
}

/* Add (+1) or drop (-1) a name of the group whose indirection is `indh`:
 * proot's own steps, rename the data file to its new count and re-point the
 * indirection. The caller holds the lock and has asked `:ro` of the l2s
 * directory. Dropping the last name removes the data and the indirection; a
 * group that is gone has nothing to drop. 0 or -errno. */
static int pr_adjust(const char *indh, int delta) {
    char t2[CNG_PATH_MAX], data[CNG_PATH_MAX], ndata[CNG_PATH_MAX],
        nname[PR_NAME_MAX + 8], st[ST_SIZE];
    const char *ind = l2s_basename(indh);
    unsigned long c = 0;
    for (int pass = 0;; pass++) {
        long n = l2s_readlink(indh, t2, sizeof t2 - 1);
        if (n < 0)
            return delta < 0 ? 0 : (int)n;
        t2[n] = '\0';
        const char *tb = l2s_basename(t2);
        int ok = t2[0] == '/' && pr_data_of(tb, ind, &c) &&
                 pr_sibling(indh, tb, data, sizeof data) == 0 &&
                 l2s_lstat(data, st) == 0 && is_reg(st);
        if (ok)
            break;
        if (pass || pr_repair(indh) < 0)
            return delta < 0 ? 0 : -ENOENT;
    }
    if (!c)
        c = 1; /* 0000 is a group of one name, as proot reads it */
    if (delta < 0 && c <= 1) { /* the last name went */
        l2s_unlink(data);
        l2s_unlink(indh);
        return 0;
    }
    if (delta > 0 && c >= PR_MAX_COUNT)
        return -EMLINK;
    unsigned long nc = delta < 0 ? c - 1 : c + 1;
    char *p = nname;
    size_t il = strlen(ind);
    memcpy(nname, ind, il);
    p += il;
    *p++ = '.';
    put_u64(&p, nname + sizeof nname - 1, nc, 4);
    *p = '\0';
    if (pr_sibling(indh, nname, ndata, sizeof ndata) < 0)
        return -ENAMETOOLONG;
    long r = l2s_rename(data, ndata);
    if (r < 0)
        return (int)r;
    r = pr_repoint(indh, t2, nname);
    if (r < 0) {
        l2s_rename(ndata, data); /* put the count back */
        return (int)r;
    }
    return 0;
}

/* The indirection of the group whose data file is `data`. */
static int l2s_resolve_ex(const char *host, char *data, size_t dsz,
                          unsigned long *count, int locked, char *indh,
                          size_t isz);

static int pr_ind_of(const char *data, char *indh, size_t isz) {
    const char *b = l2s_basename(data);
    char ind[PR_NAME_MAX + 1];
    if (!pr_is_data(b, 0))
        return -EINVAL;
    size_t il = strlen(b) - 5;
    memcpy(ind, b, il);
    ind[il] = '\0';
    return pr_sibling(data, ind, indh, isz);
}

int cng_l2s_member_like(const char *host) {
    char data[CNG_PATH_MAX];
    int r = l2s_resolve_ex(host, data, sizeof data, 0, 0, 0, 0);
    return r == 1 || r == 2;
}

int cng_l2s_text_denied(const char *tgt) {
    return cng_l2s_hidden(l2s_basename(tgt)) || pr_shaped(tgt);
}

int cng_l2s_untranslate_target(const char *tgt, char *out, size_t sz) {
    const char *b = l2s_basename(tgt);
    if (tgt[0] != '/' ||
        !(parse_data_exact(b, 0) || pr_is_ind(b) || pr_is_data(b, 0)) ||
        !l2s_canonical(tgt))
        return 0;
    if (cng_g_fs && cng_host_dir_guest(tgt, out, sz) == 0)
        return 1;
    /* A stale store path (the rootfs tree was moved or copied): the store
     * sits at a fixed guest location, so the basename alone reconstructs it,
     * as l2s_locate's self-heal does. Anything else is re-rooted like the
     * absolute target of any other symlink. */
    if (!l2s_store_shaped(tgt))
        return 0;
    size_t n = cng_strlcpy(out, "/.l2s/", sz);
    if (n >= sz)
        return 0;
    cng_strlcpy(out + n, b, sz - n);
    return 1;
}

/* ---- core --------------------------------------------------------------- */

/* The resolver proper. 1: `host` is a link of a group (ours or proot's), with
 * `data` and `count` filled; 0: not; -errno. 2: a proot link whose chain is cut
 * (see pr_locate) and stays cut once the lock is looked through: `indh` is the
 * indirection, for a caller that is about to change the group and will repair
 * it. With `locked` the caller holds the lock, so it is not waited for. */
static int l2s_resolve_ex(const char *host, char *data, size_t dsz,
                          unsigned long *count, int locked, char *indh,
                          size_t isz) {
    char st[ST_SIZE];
    long r = l2s_lstat(host, st);
    if (r < 0)
        return (int)r;
    if (!is_lnk(st))
        return 0;

    char tgt[CNG_PATH_MAX];
    long n = l2s_readlink(host, tgt, sizeof tgt - 1);
    if (n < 0)
        return (int)n;
    tgt[n] = '\0';

    int heal;
    int k = l2s_locate(host, tgt, data, dsz, &heal);
    if (k == 0) {
        /* Not one of ours: proot's, perhaps. What tells them apart is the
         * type of what the text names, and ours was asked first. */
        char ih[CNG_PATH_MAX];
        if (!indh) {
            indh = ih;
            isz = sizeof ih;
        }
        unsigned long c = 0;
        int pr = pr_locate(tgt, data, dsz, &c, indh, isz);
        if (pr == 2 && !locked) {
            /* A count change is two renames; with the lock held none is in
             * progress (it is every change's), so what is seen is the state,
             * not the middle of one. */
            long lk = l2s_lock(indh);
            pr = pr_locate(tgt, data, dsz, &c, indh, isz);
            l2s_unlock(lk);
        }
        if (pr == 1 && count)
            *count = c;
        return pr;
    }
    if (k != 1)
        return k;
    if (heal) { /* repoint the stale link at its data (best effort) */
        l2s_unlink(host);
        l2s_symlink(data, host);
    }
    if (count) {
        unsigned long long ino;
        unsigned long c = 0;
        char dir[CNG_PATH_MAX];
        parse_data(l2s_basename(data), &ino);
        l2s_dirname(data, dir, sizeof dir);
        if (find_marker(dir, ino, &c) != 0)
            c = 0;
        *count = c;
    }
    return 1;
}

/* If `host` is one of our l2s symlinks, fill data+count. 1/0/-errno. */
int cng_l2s_resolve(const char *host, char *data, size_t dsz,
                    unsigned long *count) {
    int r = l2s_resolve_ex(host, data, dsz, count, 0, 0, 0);
    return r == 2 ? 0 : r;
}

/* Map `host` to its backing file: our symlink (NOFOLLOW) or the data file
 * itself (a FOLLOW resolution already landed on it). 1/0/-errno. */
static int l2s_target(const char *host, char *data, size_t dsz,
                      unsigned long *count) {
    int isl = cng_l2s_resolve(host, data, dsz, count);
    if (isl != 0)
        return isl;
    unsigned long long ino;
    { /* proot's data file, reached by a walk that followed one of its members */
        char ih[CNG_PATH_MAX];
        unsigned long c = 0;
        if (pr_data_group(host, ih, sizeof ih, &c)) {
            if (cng_strlcpy(data, host, dsz) >= dsz)
                return -ENAMETOOLONG;
            if (count)
                *count = c;
            return 1;
        }
    }
    if (parse_data_exact(l2s_basename(host), &ino) && l2s_canonical(host) &&
        l2s_owned(host)) {
        char dir[CNG_PATH_MAX];
        l2s_dirname(host, dir, sizeof dir);
        if (build_name(data, dsz, dir, ino, -1) < 0)
            return -ENAMETOOLONG;
        if (count) {
            unsigned long c = 0;
            if (find_marker(dir, ino, &c) != 0)
                c = 0;
            *count = c;
        }
        return 1;
    }
    return 0;
}

/* Copy the contents of `src` (opened, follows /proc/self/fd/N) into a new
 * regular file `dst`. Used when src has no named regular inode to symlink to
 * (e.g. /proc/self/fd/N naming an O_TMPFILE), or the link spans directories.
 * The open must not wait for anything: a FIFO opened for reading blocks until
 * a writer turns up, and one swapped in for the file after it was judged
 * regular would leave the guest's call hanging for good. O_NONBLOCK makes the
 * open return, and the fstat below then refuses what is not a regular file. */
static int l2s_materialize(const char *src, const char *dst) {
    long in = cng_pin_open(
        src, CNG_O_RDONLY | CNG_O_NONBLOCK | CNG_O_NOCTTY | CNG_O_CLOEXEC, 0);
    if (in < 0)
        return (int)in;
    /* A real hardlink shares the source's mode; the copy must too (apk
     * publishes its database files this way — 0644, not 0755). */
    char st[ST_SIZE];
    unsigned mode = 0644;
    if (CNG_SYS(__NR_fstat, (int)in, st, 0, 0, 0, 0) == 0) {
        if (!is_reg(st)) {
            sys_close((int)in);
            return -EPERM; /* link(2) on a directory etc. */
        }
        mode = st_mode(st) & 07777;
    }
    long out = cng_pin_open(dst,
                            CNG_O_WRONLY | CNG_O_CREAT | CNG_O_EXCL |
                                CNG_O_CLOEXEC,
                            (int)mode);
    if (out < 0) {
        sys_close((int)in);
        return (int)out;
    }
    char buf[8192];
    long rc = 0, n;
    while ((n = sys_read((int)in, buf, sizeof buf)) > 0) {
        long off = 0;
        while (off < n) {
            long w = sys_write((int)out, buf + off, (size_t)(n - off));
            if (w < 0) {
                rc = w;
                break;
            }
            off += w;
        }
        if (rc)
            break;
    }
    if (n < 0 && rc == 0)
        rc = n;
    if (rc == 0) /* the open mode went through umask; the link's does not */
        CNG_SYS(__NR_fchmod, (int)out, mode, 0, 0, 0, 0);
    sys_close((int)in);
    sys_close((int)out);
    if (rc != 0)
        l2s_unlink(dst);
    return (int)rc;
}

/* ---- link --------------------------------------------------------------- */

/* What the source of a link is, to the emulation. */
enum {
    LSRC_GROUP = 1, /* a name of a group in either format, or its data file */
    LSRC_FILE,      /* a regular file of the guest's own: its first link */
    LSRC_SYMLINK,   /* an ordinary symlink of the guest's own */
    LSRC_COPY,      /* nothing of the guest's to point at: linked by copy */
    LSRC_CUT,       /* proot's link whose chain is cut: settled under the lock */
};

/* Classify `src`: one of the above, or -errno. For a group, `data` is the data
 * file's path, *count the live count (0 if the marker is lost) and *ino the
 * group's number; for a first link *ino is the file's own inode.
 *
 * `own`: a place of the guest's own. A source outside every one — the file
 * behind a descriptor it was handed, linked by AT_EMPTY_PATH — is never
 * renamed into the store or given a marker beside it: that would move a file,
 * and write a directory, that no name of the guest's reaches. Its contents are
 * copied instead, as for a file with no name at all.
 *
 * What the answer is about is a moment, so a caller that is going to act on a
 * group, or make one, asks again once it holds the lock (cng_l2s_link). */
static int l2s_link_source(const char *src, int own, int locked, char *data,
                           size_t dsz, unsigned long *count,
                           unsigned long long *ino) {
    char st[ST_SIZE];
    *count = 0;
    /* The name is looked at once, and what it is decides what is asked next:
     * only a symlink can be a name of a group, so only a symlink is asked
     * (cng_l2s_resolve looks again, and a name that was a regular file when
     * asked and a group's link by the time it was looked at was taken for an
     * ordinary symlink, whose text the copy below refuses). A symlink that is
     * not a group's does not become one, nor a group's one an ordinary
     * symlink, so the answer for a symlink holds. */
    if (l2s_lstat(src, st) < 0) {
        L2S_LOG("[cng] l2s: src %s missing\n", src);
        return -ENOENT;
    }
    if (is_lnk(st)) {
        char indh[CNG_PATH_MAX];
        int isl = l2s_resolve_ex(src, data, dsz, count, locked, indh,
                                 sizeof indh);
        if (isl == 2) {
            /* Shaped like a link of a proot group and the group's data is not
             * where its indirection says. Linked as the ordinary symlink it
             * looks like, it would be a name nothing counted, and the unlink
             * of it a count nobody raised — the data deleted from under the
             * names that were left. So it is made whole first, or refused. */
            if (!locked)
                return LSRC_CUT;
            if (pr_repair(indh) < 0)
                return -ENOENT;
            isl = l2s_resolve_ex(src, data, dsz, count, locked, indh,
                                 sizeof indh);
            if (isl == 2)
                return -ENOENT;
        }
        if (isl < 0) {
            L2S_LOG("[cng] l2s: src probe %s -> %d\n", src, isl);
            return isl;
        }
        if (isl == 1) {
            if (!parse_data(l2s_basename(data), ino))
                *ino = 0; /* proot's: the count is in the data file's name */
            return LSRC_GROUP;
        }
        return own ? LSRC_SYMLINK : LSRC_COPY; /* /proc/self/fd/N: a copy */
    }
    if (!own)
        return LSRC_COPY;
    /* AT_SYMLINK_FOLLOW may have resolved src straight onto the data file. */
    if (is_reg(st) && parse_data_exact(l2s_basename(src), ino)) {
        char dir[CNG_PATH_MAX];
        if (cng_strlcpy(data, src, dsz) >= dsz)
            return -ENAMETOOLONG;
        l2s_dirname(src, dir, sizeof dir);
        if (find_marker(dir, *ino, count) != 0)
            *count = 0;
        return LSRC_GROUP;
    }
    if (is_reg(st)) { /* proot's data file, reached by a following walk */
        char ih[CNG_PATH_MAX];
        unsigned long pc;
        if (pr_data_group(src, ih, sizeof ih, &pc)) {
            if (cng_strlcpy(data, src, dsz) >= dsz)
                return -ENAMETOOLONG;
            *count = pc;
            *ino = 0;
            return LSRC_GROUP;
        }
    }
    if (!is_reg(st))
        return -EPERM; /* a directory, FIFO, device or socket: nothing here
                        * can stand for a second name of one, and opening it
                        * to copy it could block for good (a FIFO) */
    memcpy(ino, st + ST_INO_OFF, sizeof *ino);
    return LSRC_FILE;
}

/* link(2) of an ordinary symlink makes a second name of the symlink itself,
 * which a second symlink with the same text is: the text is resolved from
 * where the name sits, as a kernel resolves it, and nothing it names is
 * opened. Copying what it names was this fallback's answer for anything that
 * was not a regular file — an ELOOP, since the open does not follow a last
 * component, and had it followed one, the host's file where the text is an
 * absolute path of the guest's.
 *
 * Only the text is the emulation's concern. One whose last component is in
 * the ".l2s." grammar is not copied: a link of ours is recognized by its
 * target (see l2s_locate), the guest may not write such a text (symlinkat),
 * and carried into the directory of a group's data, a copy of one planted
 * from outside would become a member of a group it was never counted into. */
static int l2s_link_symlink(const char *src, const char *dst) {
    char tgt[CNG_PATH_MAX];
    long n = l2s_readlink(src, tgt, sizeof tgt - 1);
    if (n < 0)
        return (int)n;
    tgt[n] = '\0';
    if (cng_l2s_hidden(l2s_basename(tgt))) {
        L2S_LOG("[cng] l2s: symlink %s names the machinery (%s)\n", src, tgt);
        return -EPERM;
    }
    return (int)l2s_symlink(tgt, dst);
}

/* Another name for an existing group (either format): bump the marker beside
 * the data, then point dst at it — a same-directory relative target when dst
 * sits beside the data (the legacy look), the absolute host path otherwise
 * (how names in other directories join a group). The caller holds the lock,
 * and `count` was read under it. */
static int l2s_link_group(const char *data, unsigned long long ino,
                          unsigned long count, const char *dst,
                          const char *ddir) {
    char sdir[CNG_PATH_MAX], newm[CNG_PATH_MAX], oldm[CNG_PATH_MAX];
    l2s_dirname(data, sdir, sizeof sdir);
    unsigned long nc = (count ? count : 1) + 1;
    if (build_name(newm, sizeof newm, sdir, ino, (long)nc) < 0)
        return -ENAMETOOLONG;
    int bumped = 0;
    if (count && build_name(oldm, sizeof oldm, sdir, ino, (long)count) == 0)
        bumped = (l2s_rename(oldm, newm) == 0);
    if (!bumped)
        l2s_touch(newm); /* marker lost: recreate at the new count */
    long sr = strcmp(sdir, ddir) == 0 ? l2s_symlink(l2s_basename(data), dst)
                                      : l2s_symlink(data, dst);
    if (sr < 0) { /* roll the bump back */
        L2S_LOG("[cng] l2s: group dst symlink %s -> %d\n", dst, (int)sr);
        if (bumped)
            l2s_rename(newm, oldm);
        else
            l2s_unlink(newm);
        return (int)sr;
    }
    return 0;
}

/* Another name for a group proot made: the count is raised first and the name
 * made after, so a failure leaves a count too high, never too low. The new
 * name carries the text of the others (the indirection's host path as proot
 * recorded it). The caller holds the lock. */
static int l2s_link_pr(const char *src, const char *data, const char *dst) {
    char indh[CNG_PATH_MAX], t1[CNG_PATH_MAX], t2[CNG_PATH_MAX], st[ST_SIZE];
    /* A new name is a write into the l2s directory, which can be a read-only
     * bind while the names are not: EROFS, as a link onto a read-only mount. */
    if (cng_g_fs && cng_fs_host_ro(cng_g_fs, data))
        return -EROFS;
    if (pr_ind_of(data, indh, sizeof indh) < 0)
        return -EINVAL;
    long n;
    if (l2s_lstat(src, st) == 0 && is_lnk(st)) {
        n = l2s_readlink(src, t1, sizeof t1 - 1);
    } else { /* reached by the data file: the text is rebuilt from the chain */
        n = l2s_readlink(indh, t2, sizeof t2 - 1);
        if (n >= 0) {
            t2[n] = '\0';
            const char *tb = l2s_basename(t2);
            const char *ib = l2s_basename(indh);
            size_t dl = (size_t)(tb - t2);
            if (dl + strlen(ib) >= sizeof t1)
                return -ENAMETOOLONG;
            memcpy(t1, t2, dl);
            memcpy(t1 + dl, ib, strlen(ib) + 1);
            n = (long)strlen(t1);
        }
    }
    if (n < 0)
        return (int)n;
    t1[n] = '\0';
    int r = pr_adjust(indh, +1);
    if (r < 0)
        return r;
    long sr = l2s_symlink(t1, dst);
    if (sr < 0) {
        L2S_LOG("[cng] l2s: proot group dst symlink %s -> %d\n", dst, (int)sr);
        pr_adjust(indh, -1); /* the name was never made */
        return (int)sr;
    }
    return 0;
}

/* Returned by l2s_link_first for a file that can be linked only by copying. */
#define L2S_COPY 1

/* The first link of a regular file: it becomes the data of a new group and
 * both names symlinks to it. The caller holds the lock, and has just seen `src`
 * to be that regular file, of inode `ino` — which is what keeps this from
 * moving a file already moved: a rename of a name that has meanwhile become a
 * link of this group would put the link itself where the data is, a symlink
 * to itself. Returns 0, -errno, or L2S_COPY. */
static int l2s_link_first(const char *src, const char *dst,
                          unsigned long long ino, const char *ddir) {
    char data[CNG_PATH_MAX], sdir[CNG_PATH_MAX];

    /* Prefer the central store: the group's names then carry the data file's
     * absolute host path, so they work across directories and keep working
     * when a name or its directory is renamed. The rename also pins <ino>
     * against reuse for the group's lifetime. */
    char store[CNG_PATH_MAX];
    long mv = -1;
    int sdr = l2s_store_dir(store, sizeof store);
    if (sdr == 0) {
        if (build_name(data, sizeof data, store, ino, -1) < 0)
            return -ENAMETOOLONG;
        /* The rename replaces what stands on the name, and in a store that
         * proot has used a name can: its indirection ".l2s.<name><NNNN>" is
         * ".l2s.<ino>" for a file called "12" and a four-digit counter. A
         * name taken is a store that cannot hold this group. */
        char tst[ST_SIZE];
        mv = l2s_lstat(data, tst) == -ENOENT ? l2s_rename(src, data) : -EEXIST;
    }
    if (mv != 0)
        L2S_LOG("[cng] l2s: store unavailable (dir=%d mv=%d), per-dir "
                "fallback\n",
                sdr, (int)mv);
    if (mv == 0) {
        long sr = l2s_symlink(data, src);
        if (sr < 0) {
            L2S_LOG("[cng] l2s: src symlink %s -> %d\n", src, (int)sr);
            l2s_rename(data, src); /* rollback */
            return (int)sr;
        }
        char newm[CNG_PATH_MAX];
        int have_m = (build_name(newm, sizeof newm, store, ino, 2) == 0);
        if (have_m)
            l2s_touch(newm);
        sr = l2s_symlink(data, dst);
        if (sr < 0) { /* full rollback */
            L2S_LOG("[cng] l2s: dst symlink %s -> %d\n", dst, (int)sr);
            if (have_m)
                l2s_unlink(newm);
            l2s_unlink(src);
            l2s_rename(data, src);
            return (int)sr;
        }
        return 0;
    }

    /* Store unusable, or the rename refused (-EXDEV: src on a bind mount from
     * another filesystem): per-directory scheme, as before. Cross-directory
     * then still degrades to an independent copy. */
    l2s_dirname(src, sdir, sizeof sdir);
    if (strcmp(sdir, ddir) != 0)
        return L2S_COPY;
    if (build_name(data, sizeof data, sdir, ino, -1) < 0)
        return -ENAMETOOLONG;
    if ((mv = l2s_rename(src, data)) < 0) {
        L2S_LOG("[cng] l2s: per-dir rename %s -> %d\n", src, (int)mv);
        return (int)mv;
    }
    long sr = l2s_symlink(l2s_basename(data), src);
    if (sr < 0) {
        L2S_LOG("[cng] l2s: per-dir src symlink %s -> %d\n", src, (int)sr);
        l2s_rename(data, src); /* rollback */
        return (int)sr;
    }
    char newm[CNG_PATH_MAX];
    int have_m = (build_name(newm, sizeof newm, sdir, ino, 2) == 0);
    if (have_m)
        l2s_touch(newm);
    sr = l2s_symlink(l2s_basename(data), dst);
    if (sr < 0) { /* full rollback */
        if (have_m)
            l2s_unlink(newm);
        l2s_unlink(src);
        l2s_rename(data, src);
        return (int)sr;
    }
    return 0;
}

int cng_l2s_link(const char *src, const char *dst) {
    char st[ST_SIZE];
    if (l2s_lstat(dst, st) == 0)
        return -EEXIST; /* link(2): dst must not exist */

    char data[CNG_PATH_MAX], ddir[CNG_PATH_MAX];
    unsigned long count;
    unsigned long long ino = 0;
    l2s_dirname(dst, ddir, sizeof ddir);
    /* The host's /proc is a place of the guest's, and its symlinks are magic
     * links, meant to be followed — the descriptor behind /proc/self/fd/N is
     * how an O_TMPFILE, or any file the guest has no name for, is linked —
     * not symlinks of the guest's own to copy the text of. */
    int own = l2s_canonical(src) && l2s_owned(src) &&
              !(!strncmp(src, "/proc", 5) && (src[5] == '\0' || src[5] == '/'));

    int kind = l2s_link_source(src, own, 0, data, sizeof data, &count, &ino);
    long lk = -1;
    if (kind == LSRC_GROUP || kind == LSRC_FILE || kind == LSRC_CUT ||
        kind == -ENOENT) {
        /* The group's state — the marker, the data's place in the store — is
         * read, changed and written back, so it is changed under the lock; and
         * the source is judged again once the lock is held, since the answer
         * above is only the lock's to confirm. The first link took no lock:
         * two processes making it at once both saw a plain file, and the
         * second's rename moved the first's new symlink onto the data file,
         * which was left a symlink to itself with the contents gone. Under the
         * lock the second finds the group the first made and joins it. An
         * ENOENT is confirmed too: between a first link's rename of the file
         * into the store and the symlink it leaves in its place there is no
         * such name, which no kernel ever answers for a name that was there
         * before and is there after. The lock is the group's directory's for
         * the stand-in (l2s_lock): a file's, for one about to become one. */
        char hint[CNG_PATH_MAX];
        cng_strlcpy(hint, kind == LSRC_GROUP ? data : src, sizeof hint);
        lk = l2s_lock(hint);
        kind = l2s_link_source(src, own, 1, data, sizeof data, &count, &ino);
    }

    int r;
    switch (kind) {
    case LSRC_GROUP:
        r = parse_data(l2s_basename(data), &ino)
                ? l2s_link_group(data, ino, count, dst, ddir)
                : l2s_link_pr(src, data, dst);
        break;
    case LSRC_FILE:
        r = l2s_link_first(src, dst, ino, ddir);
        break;
    case LSRC_SYMLINK:
        r = l2s_link_symlink(src, dst);
        break;
    case LSRC_COPY:
        r = L2S_COPY;
        break;
    default:
        r = kind;
        break;
    }
    l2s_unlock(lk);
    /* A copy can be as long as the file is, and the lock is the whole rootfs's:
     * it is made once the lock is let go. It touches no group. */
    if (r == L2S_COPY)
        r = l2s_materialize(src, dst);
    return r;
}

int cng_l2s_rename_prep(const char *srch, char *absdata, size_t sz) {
    char st[ST_SIZE];
    if (l2s_lstat(srch, st) != 0 || !is_lnk(st))
        return 0;
    char tgt[CNG_PATH_MAX];
    long n = l2s_readlink(srch, tgt, sizeof tgt - 1);
    if (n < 0)
        return 0;
    tgt[n] = '\0';
    if (tgt[0] == '/')
        return 0; /* absolute targets survive any move */
    int heal;
    return l2s_locate(srch, tgt, absdata, sz, &heal) == 1;
}

void cng_l2s_rename_fixup(const char *dsth, const char *absdata) {
    char ddir[CNG_PATH_MAX], sdir[CNG_PATH_MAX];
    l2s_dirname(dsth, ddir, sizeof ddir);
    l2s_dirname(absdata, sdir, sizeof sdir);
    if (strcmp(ddir, sdir) == 0)
        return; /* still beside the data: the relative target stays valid */
    l2s_unlink(dsth);
    l2s_symlink(absdata, dsth);
}

void cng_l2s_decref(const char *data, unsigned long count) {
    unsigned long long ino;
    if (!parse_data(l2s_basename(data), &ino)) {
        /* proot's: the count is the data file's name. Best effort by design —
         * the name's own removal is the call's result and stands, and a count
         * left high is a file left behind where a lie to the guest would be
         * worse. */
        char indh[CNG_PATH_MAX];
        if (pr_ind_of(data, indh, sizeof indh) == 0) {
            long lk = l2s_lock(data);
            pr_adjust(indh, -1);
            l2s_unlock(lk);
        }
        return;
    }
    char dir[CNG_PATH_MAX], m[CNG_PATH_MAX], newm[CNG_PATH_MAX];
    l2s_dirname(data, dir, sizeof dir);
    long lk = l2s_lock(data);
    if (lk >= 0) {
        unsigned long c;
        if (find_marker(dir, ino, &c) == 0)
            count = c; /* fresher than the caller's pre-unlink read */
    }
    if (count <= 1) { /* last reference */
        l2s_unlink(data);
        if (build_name(m, sizeof m, dir, ino, (long)(count ? count : 1)) == 0)
            l2s_unlink(m);
        l2s_unlock(lk);
        return;
    }
    if (build_name(m, sizeof m, dir, ino, (long)count) == 0 &&
        build_name(newm, sizeof newm, dir, ino, (long)(count - 1)) == 0)
        l2s_rename(m, newm);
    l2s_unlock(lk);
}

/* A proot group's data file changes its NAME with every count change, so a
 * stat of the name a resolve just gave can find it renamed under it. The
 * resolve is asked again — it sees the new name — a few times; nothing in the
 * group has gone, and answering ENOENT would, for the link routing, pass a
 * member for an ordinary symlink. */
#define PR_LOOKS 8

int cng_l2s_stat(const char *host, void *statbuf) {
    char data[CNG_PATH_MAX];
    unsigned long count = 0;
    long s;
    for (int look = 0;; look++) {
        int r = l2s_target(host, data, sizeof data, &count);
        if (r != 1)
            return r;
        s = l2s_statf(data, statbuf);
        if (s == -ENOENT && look < PR_LOOKS &&
            !parse_data(l2s_basename(data), 0))
            continue;
        break;
    }
    if (s < 0)
        return (int)s;
    *(unsigned *)((char *)statbuf + ST_NLINK_OFF) = count ? count : 1;
    return 1;
}

int cng_l2s_statx(const char *host, void *statxbuf, unsigned mask,
                  unsigned flags) {
    char data[CNG_PATH_MAX];
    unsigned long count = 0;
    long s;
    /* The data path is never a symlink: force a follow so the guest's
     * NOFOLLOW cannot expose the emulation. Sync flags pass through. */
    flags &= ~(unsigned)(CNG_AT_SYMLINK_NOFOLLOW | CNG_AT_EMPTY_PATH);
    for (int look = 0;; look++) {
        int r = l2s_target(host, data, sizeof data, &count);
        if (r != 1)
            return r;
        s = cng_pin_statx(data, (int)flags, mask, statxbuf);
        if (s == -ENOENT && look < PR_LOOKS &&
            !parse_data(l2s_basename(data), 0))
            continue;
        break;
    }
    if (s < 0)
        return (int)s;
    *(unsigned *)((char *)statxbuf + STX_NLINK_OFF) = count ? count : 1;
    *(unsigned *)((char *)statxbuf + STX_MASK_OFF) |= CNG_STATX_NLINK;
    return 1;
}

/* If /proc/self/fd/<fd> names a data file, yield the group's live count.
 * Returns 1 (*count filled, floored to 1) or 0. */
static int l2s_fd_count(long fd, unsigned long *count) {
    char link[64], *p = link;
    char *end = link + sizeof link - 1;
    p += cng_strlcpy(p, "/proc/self/fd/", (size_t)(end - p) + 1);
    /* int arg: the x-register's top half may be dirty (glibc). */
    put_u64(&p, end, (unsigned long long)(unsigned)(int)fd, 1);
    *p = '\0';
    char path[CNG_PATH_MAX];
    long n = l2s_readlink(link, path, sizeof path - 1);
    if (n < 0)
        return 0;
    path[n] = '\0';
    /* Where the kernel says the file is, which is only a data file of ours
     * in a place of the guest's own (see l2s_locate). */
    unsigned long long ino;
    {
        char ih[CNG_PATH_MAX];
        unsigned long pc;
        if (pr_data_group(path, ih, sizeof ih, &pc)) {
            *count = pc ? pc : 1;
            return 1;
        }
    }
    if (!parse_data_exact(l2s_basename(path), &ino) || !l2s_canonical(path) ||
        !l2s_owned(path))
        return 0;
    char dir[CNG_PATH_MAX];
    unsigned long c = 0;
    l2s_dirname(path, dir, sizeof dir);
    if (find_marker(dir, ino, &c) != 0)
        return 0;
    *count = c ? c : 1;
    return 1;
}

/* The host path of the directory behind an open fd, for the one place a
 * listing has to fall back to the path-based machinery. */
static int l2s_fd_dir(long fd, char *out, size_t sz) {
    char link[64], *p = link;
    char *end = link + sizeof link - 1;
    p += cng_strlcpy(p, "/proc/self/fd/", (size_t)(end - p) + 1);
    put_u64(&p, end, (unsigned long long)(unsigned)(int)fd, 1);
    *p = '\0';
    long n = l2s_readlink(link, out, sz - 1);
    if (n <= 0)
        return -1;
    out[n] = '\0';
    return 0;
}

int cng_l2s_dirent(long dirfd, const char *name, unsigned long long *ino,
                   unsigned *type) {
    /* One readlink tells an ordinary symlink from ours: the target of ours
     * is a data file's name, absolute (the store, or a legacy group joined
     * from another directory) or bare (a legacy same-directory link). A name
     * that is not a symlink at all answers EINVAL here, which is what makes
     * this cheap enough to ask about a DT_UNKNOWN record too. */
    char tgt[CNG_PATH_MAX];
    long n = sys_readlinkat((int)dirfd, name, tgt, sizeof tgt - 1);
    if (n <= 0)
        return 0;
    tgt[n] = '\0';
    const char *b = l2s_basename(tgt);
    /* proot's member: its text names an indirection, not a data file, and the
     * chain is judged by the same walk a stat of the name makes. */
    int prm = pr_shaped(tgt) && pr_is_ind(b);
    if (!prm && (!parse_data_exact(b, 0) || (tgt[0] != '/' && b != tgt)))
        return 0;
    /* What stat(2) of the name answers is the data file — a follow lands on
     * it — so the record carries that inode and type. The target is asked
     * about directly rather than followed by the kernel: a data file is never
     * a symlink, and the link is the guest's to have pointed anywhere — which
     * is why an absolute one is asked about only where l2s_locate would take
     * it as it stands, in a place of the guest's own. */
    char st[ST_SIZE];
    long sr = -1;
    if (prm)
        sr = -1; /* straight to the walk below */
    else if (tgt[0] != '/')
        sr = CNG_SYS(__NR_newfstatat, (int)dirfd, tgt, st,
                     CNG_AT_SYMLINK_NOFOLLOW, 0, 0);
    else if (l2s_canonical(tgt) && l2s_owned(tgt))
        sr = cng_pin_fstatat(tgt, st, CNG_AT_SYMLINK_NOFOLLOW);
    if (sr < 0 || !is_reg(st)) {
        if (tgt[0] != '/')
            return 0; /* a bare name with no data beside it: not ours */
        /* Not a data file where it says: an absolute target whose rootfs tree
         * was moved or copied, which cng_l2s_stat self-heals onto the current
         * store, or no link of ours at all — and a listing must say what the
         * stat after it will. */
        char host[CNG_PATH_MAX];
        size_t dl;
        if (l2s_fd_dir(dirfd, host, sizeof host) < 0 ||
            (dl = strlen(host)) + 1 + strlen(name) >= sizeof host)
            return 0;
        if (dl && host[dl - 1] != '/')
            host[dl++] = '/';
        cng_strlcpy(host + dl, name, sizeof host - dl);
        if (cng_l2s_stat(host, st) != 1)
            return 0; /* still dangling: what the kernel said stands */
    }
    *ino = *(unsigned long long *)(st + ST_INO_OFF);
    *type = (st_mode(st) & S_IFMT_) >> 12; /* DT_* is S_IFMT >> 12 */
    return 1;
}

void cng_l2s_fix_fd(long fd, void *statbuf) {
    unsigned long c;
    if (l2s_fd_count(fd, &c))
        *(unsigned *)((char *)statbuf + ST_NLINK_OFF) = (unsigned)c;
}

void cng_l2s_fix_fd_statx(long fd, void *statxbuf) {
    unsigned long c;
    if (l2s_fd_count(fd, &c)) {
        *(unsigned *)((char *)statxbuf + STX_NLINK_OFF) = (unsigned)c;
        *(unsigned *)((char *)statxbuf + STX_MASK_OFF) |= CNG_STATX_NLINK;
    }
}
