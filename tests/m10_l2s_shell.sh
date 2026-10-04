# M10: link2symlink guest-shell fidelity (sourced by tests/run.sh).
#
# Differential against arm64chroot running REAL hardlinks: the oracle binary
# has l2s compiled out and this host's filesystem allows link(2), so the same
# shell script runs once with genuine hardlinks (oracle) and once with the
# emulation forced on (CNG_L2S_FORCE routes every linkat through l2s). Stdout
# and exit status must match byte-for-byte — any visible difference means the
# emulation is distinguishable from real hardlinks in a guest shell.
#
# Rules: scenarios are self-contained; raw inode numbers are never printed
# (compare with `[ a = b ] && echo same-ino`); busybox `find` has no
# -samefile (GNU-only — exercised in the Debian leg).
#
# The oracle is a host-native program, not an AArch64 one, so this whole
# milestone only runs where a matching build of it exists (tests/lib.sh checks
# its machine against the host's and drops it otherwise). Locations come from
# tests/lib.sh; M10_ORACLE/M10_ALPINE/M10_DEBIAN still override per-milestone.
echo "== M10: l2s shell (differential vs arm64chroot real hardlinks) =="

M10_ORACLE="${M10_ORACLE:-$CNG_ORACLE}"
M10_ALPINE="${M10_ALPINE:-$CNG_ALPINE}"
M10_DEBIAN="${M10_DEBIAN:-$CNG_DEBIAN}"

CNG_L2S_FORCE=1
export CNG_L2S_FORCE   # chroot-ng only; the oracle ignores it

m10_ready=0
if [ -n "$M10_ORACLE" ] && [ -x "$M10_ORACLE" ] &&
    [ -n "$M10_ALPINE" ] && [ -x "$M10_ALPINE/bin/busybox" ]; then
    # Sanity: the oracle must produce real hardlinks (l2s compiled out).
    SAN=$(mktemp -d)
    cp -a "$M10_ALPINE/." "$SAN"
    san=$("$M10_ORACLE" "$SAN" /bin/sh -c \
        'cd /tmp; echo x>a; ln a b; stat -c %h a' 2>/dev/null)
    rm -rf "$SAN"
    if [ "$san" = "2" ]; then
        m10_ready=1
    else
        skip "oracle does not produce real hardlinks (got '$san')"
    fi
else
    skip "differential l2s legs: no host-native oracle or no alpine rootfs"
fi

# l2s_diff <desc> <script>: run <script> under both, compare stdout + rc.
l2s_diff() {
    RO=$(mktemp -d); REM=$(mktemp -d)
    cp -a "$M10_ALPINE/." "$RO"; cp -a "$M10_ALPINE/." "$REM"
    out_o=$("$M10_ORACLE" "$RO" /bin/sh -c "$2" 2>/dev/null); rc_o=$?
    out_e=$(run -R -l "$REM" /bin/sh -c "$2" 2>/dev/null); rc_e=$?
    if [ "$out_o" = "$out_e" ] && [ "$rc_o" = "$rc_e" ]; then
        pass=$((pass + 1)); echo "  ok   m10 $1"
    else
        fail=$((fail + 1)); echo "  FAIL m10 $1"
        echo "    oracle rc=$rc_o: $(printf %s "$out_o" | head -c 300)"
        echo "    chroot rc=$rc_e: $(printf %s "$out_e" | head -c 300)"
    fi
    rm -rf "$RO" "$REM"
}

if [ "$m10_ready" -eq 1 ]; then
    l2s_diff "ln basics: nlink, shared inode, content" \
        'cd /tmp; mkdir d; cd d; echo hi>a; ln a b; stat -c %h a b;
         [ "$(stat -c %i a)" = "$(stat -c %i b)" ] && echo same-ino; cat b'

    l2s_diff "cross-directory ln" \
        'cd /tmp; mkdir -p d/s; cd d; echo hi>a; ln a s/c; stat -c %h a s/c;
         [ "$(stat -c %i a)" = "$(stat -c %i s/c)" ] && echo same-ino; cat s/c'

    l2s_diff "hiding: ls -a in link dir and at /" \
        'cd /tmp; mkdir d; cd d; echo hi>a; ln a b; ls -a; ls -a /'

    l2s_diff "readlink on a hardlink fails" \
        'cd /tmp; echo hi>a; ln a b; readlink b; echo rc=$?'

    l2s_diff "write-through: append via one name, read via other" \
        'cd /tmp; echo hi>a; ln a b; echo more >> a; cat b; stat -c %h b'

    l2s_diff "mv a link cross-directory" \
        'cd /tmp; mkdir d; cd d; echo hi>a; ln a b; mv b /tmp/b2;
         cat /tmp/b2; stat -c %h /tmp/b2;
         [ "$(stat -c %i a)" = "$(stat -c %i /tmp/b2)" ] && echo same-ino'

    l2s_diff "rm one name drops nlink" \
        'cd /tmp; echo hi>a; ln a b; rm b; stat -c %h a; ls'

    l2s_diff "rm all names, rmdir succeeds" \
        'cd /tmp; mkdir d; cd d; echo hi>a; ln a b; rm a b; cd ..;
         rmdir d; echo rc=$?; ls'

    l2s_diff "rm -rf a tree holding link groups" \
        'cd /tmp; mkdir -p t/x t/y; echo hi>t/x/a; ln t/x/a t/x/b;
         ln t/x/a t/y/c; rm -rf t; echo rc=$?; ls -a'

    l2s_diff "double ln refuses with EEXIST" \
        'cd /tmp; echo hi>a; ln a b; ln a b 2>&1; echo rc=$?'

    l2s_diff "tar round-trip restores the hardlink" \
        'cd /tmp; mkdir d; echo hi>d/a; ln d/a d/b; tar cf t.tar d;
         rm -rf d; tar xf t.tar; stat -c %h d/a d/b;
         [ "$(stat -c %i d/a)" = "$(stat -c %i d/b)" ] && echo same-ino;
         cat d/b'

    l2s_diff "binary content through a link (cmp)" \
        'cd /tmp; cp /bin/busybox f1; ln f1 f2; cmp f1 f2 && echo cmp-ok;
         stat -c %h f2'

    # link(2) of an ordinary symlink is a second name of the symlink itself.
    # The fallback copied what it pointed at, which was an ELOOP (the open does
    # not follow a last component); it makes a second symlink of the same text
    # now, and opens nothing the text names. Link counts of the symlinks are
    # not printed: the emulation's two symlinks are not one inode.
    l2s_diff "ln of an ordinary symlink: relative, absolute, dangling, up-and-over" \
        'cd /tmp; echo hi>f; ln -s f sl; ln sl sl2; readlink sl2; cat sl2;
         echo abs>g; ln -s /tmp/g as; ln as as2; readlink as2; cat as2;
         ln -s nowhere dg; ln dg dg2; readlink dg2; mkdir d; ln -s ../f d/s;
         ln d/s s2; readlink s2;
         [ -L sl2 ] && [ -L as2 ] && [ -L dg2 ] && [ -L s2 ] && echo all-symlinks;
         rm sl; cat sl2; rm sl2 as2; ls'

    # rename(2) of one name of a file onto another name of it does nothing:
    # both stay. On a group it replaced the destination and lowered the count.
    l2s_diff "mv between two names of one file does nothing" \
        'cd /tmp; echo hi>a; ln a b; mv a b; echo rc=$?; ls; stat -c %h a b;
         cat a b'
    l2s_diff "mv onto a name of another file lowers that file's count" \
        'cd /tmp; echo x>a; ln a b; echo y>c; ln c d; mv c b; echo rc=$?; ls;
         stat -c %h a b d; cat a b d'

    # A group whose data file cannot be opened. The marker update used to be
    # serialized by an flock on the data file itself, opened for reading, so a
    # mode 0000 or 0200 file — which packages do ship — ran the update
    # unlocked, and two links or unlinks of the group at once could leave
    # st_nlink wrong or a backing file behind. The lock is a file of our own
    # in the store now; the group's own modes are irrelevant to it.
    l2s_diff "ln and rm of an unreadable and a write-only file" \
        'cd /tmp; echo hi>a; chmod 000 a; ln a b; ln b c; stat -c "%h %a" a b c;
         rm b; stat -c %h a c; echo w>w; chmod 200 w; ln w w2; rm w;
         stat -c "%h %a" w2; chmod 644 w2; cat w2'
    # ...and the emulator says so itself: an update it had to run unlocked is
    # logged, and there must be none.
    REM=$(mktemp -d); cp -a "$M10_ALPINE/." "$REM"
    err=$(CNG_DEBUG=1 run -R -l "$REM" /bin/sh -c \
        'cd /tmp; echo hi>a; chmod 000 a; ln a b; ln b c; rm b; rm c' 2>&1 >/dev/null)
    check_absent "m10 the marker update of an unreadable group was locked" \
        "unlocked update" "$err"
    rm -rf "$REM"

    # Persistence: links made in one session must look identical in the
    # next (fresh process, same rootfs) — the on-disk store alone carries
    # the state.
    RO=$(mktemp -d); REM=$(mktemp -d)
    cp -a "$M10_ALPINE/." "$RO"; cp -a "$M10_ALPINE/." "$REM"
    s1='cd /tmp; echo hi>a; ln a b; stat -c %h a'
    s2='cd /tmp; stat -c %h a b;
        [ "$(stat -c %i a)" = "$(stat -c %i b)" ] && echo same-ino; cat b;
        readlink b; echo rc=$?; ls -a'
    o1=$("$M10_ORACLE" "$RO" /bin/sh -c "$s1" 2>/dev/null)
    o2=$("$M10_ORACLE" "$RO" /bin/sh -c "$s2" 2>/dev/null); rc_o=$?
    e1=$(run -R -l "$REM" /bin/sh -c "$s1" 2>/dev/null)
    e2=$(run -R -l "$REM" /bin/sh -c "$s2" 2>/dev/null); rc_e=$?
    if [ "$o1" = "$e1" ] && [ "$o2" = "$e2" ] && [ "$rc_o" = "$rc_e" ]; then
        pass=$((pass + 1)); echo "  ok   m10 persistence across sessions"
    else
        fail=$((fail + 1)); echo "  FAIL m10 persistence across sessions"
        echo "    oracle: [$o1|$o2] rc=$rc_o"
        echo "    chroot: [$e1|$e2] rc=$rc_e"
    fi
    rm -rf "$RO" "$REM"

    # A rootfs copied with `cp -a` is a tree of its own: real hardlinks come
    # out of the copy as groups of the copy's. The emulated ones keep their
    # text, which names the ORIGINAL's store, and a link was taken for what
    # its text named — so the copy's `rm` of both names deleted the
    # original's data, and the original's names were left dangling. A tree
    # of busybox and its loader is enough, and saves copying the whole image
    # four times.
    RO=$(mktemp -d); REM=$(mktemp -d)
    for _r in "$RO/r" "$REM/r"; do
        mkdir -p "$_r/bin" "$_r/lib" "$_r/tmp"
        cp "$M10_ALPINE/bin/busybox" "$_r/bin/busybox"
        ln -s busybox "$_r/bin/sh"
        cp "$M10_ALPINE/lib/ld-musl-aarch64.so.1" "$_r/lib/"
    done
    s1='cd /tmp; echo orig > a; busybox ln a b; busybox stat -c %h a'
    s2='cd /tmp; echo copy >> a; busybox cat b; busybox stat -c %h a b;
        busybox rm a b; busybox ls -a'
    s3='cd /tmp; busybox cat a; busybox stat -c %h a b'
    o1=$("$M10_ORACLE" "$RO/r" /bin/sh -c "$s1" 2>/dev/null)
    e1=$(run -R -l "$REM/r" /bin/sh -c "$s1" 2>/dev/null)
    cp -a "$RO/r" "$RO/c"; cp -a "$REM/r" "$REM/c"
    o2=$("$M10_ORACLE" "$RO/c" /bin/sh -c "$s2" 2>/dev/null)
    e2=$(run -R -l "$REM/c" /bin/sh -c "$s2" 2>/dev/null)
    o3=$("$M10_ORACLE" "$RO/r" /bin/sh -c "$s3" 2>/dev/null); rc_o=$?
    e3=$(run -R -l "$REM/r" /bin/sh -c "$s3" 2>/dev/null); rc_e=$?
    if [ "$o1|$o2|$o3" = "$e1|$e2|$e3" ] && [ "$rc_o" = "$rc_e" ] &&
        [ -n "$o3" ]; then
        pass=$((pass + 1)); echo "  ok   m10 a copied rootfs leaves the original's groups alone"
    else
        fail=$((fail + 1)); echo "  FAIL m10 a copied rootfs leaves the original's groups alone"
        echo "    oracle: [$o1|$o2|$o3] rc=$rc_o"
        echo "    chroot: [$e1|$e2|$e3] rc=$rc_e"
    fi
    rm -rf "$RO" "$REM"
fi

# The dirents themselves. Every leg above goes through busybox, which stats
# each entry it lists, so a record that lies about a link — the kernel's is the
# symlink's own: DT_LNK, the link's inode — never showed. GNU ls -F, find
# -type f and ls -i read the record instead. A compiled guest reads the
# directory raw and prints each entry's d_type and whether d_ino is what stat()
# and lstat() of the same name answer; with real hardlinks a link is "REG
# same same", and the emulation has to print the same line. The links are
# made in three shapes: beside the file, cross-directory (the group joined
# through the store), and after the tree is moved, which leaves the links'
# absolute targets stale until the first stat heals them — a listing must
# say what that stat will.
if [ "$m10_ready" -eq 1 ] && guest_xlate_ready "l2s raw-dirent leg" &&
    guest_cc_report "$CNG_TMP/dents" tests/guests/dents.c; then
    RO=$(mktemp -d); REM=$(mktemp -d)
    cp -a "$M10_ALPINE/." "$RO"; cp -a "$M10_ALPINE/." "$REM"
    cp "$CNG_TMP/dents" "$RO/bin/dents"; cp "$CNG_TMP/dents" "$REM/bin/dents"
    s1='cd /tmp; mkdir d d/sub; cd d; echo hi>a; ln a b; ln -s a s; ln a sub/c;
        /bin/dents . | sort; /bin/dents sub | sort'
    s2='cd /tmp/d; /bin/dents . | sort; /bin/dents sub | sort; stat -c %h a b sub/c'
    o1=$("$M10_ORACLE" "$RO" /bin/sh -c "$s1" 2>/dev/null)
    e1=$(run -R -l "$REM" /bin/sh -c "$s1" 2>/dev/null)
    mv "$RO" "$RO.moved"; mv "$REM" "$REM.moved"
    RO="$RO.moved"; REM="$REM.moved"
    o2=$("$M10_ORACLE" "$RO" /bin/sh -c "$s2" 2>/dev/null); rc_o=$?
    e2=$(run -R -l "$REM" /bin/sh -c "$s2" 2>/dev/null); rc_e=$?
    if [ "$o1" = "$e1" ] && [ "$o2" = "$e2" ] && [ "$rc_o" = "$rc_e" ] &&
        [ -n "$o1" ]; then
        pass=$((pass + 1)); echo "  ok   m10 raw dirents: d_type/d_ino of the links"
    else
        fail=$((fail + 1)); echo "  FAIL m10 raw dirents: d_type/d_ino of the links"
        echo "    oracle rc=$rc_o: $(printf %s "$o1|$o2" | head -c 600)"
        echo "    chroot rc=$rc_e: $(printf %s "$e1|$e2" | head -c 600)"
    fi
    rm -rf "$RO" "$REM"
fi

# Debian leg: glibc + GNU coreutils/findutils (`find -samefile`, GNU stat).
# Gated on a smoke test proving translation is live — a dynamic-glibc guest
# under -R + qemu can silently run untranslated (ld.so-loaded libc.so has no
# rewritten svc sites), which would read the HOST's /etc, not the guest's.
if [ "$m10_ready" -eq 1 ] && [ -n "$M10_DEBIAN" ] && [ -x "$M10_DEBIAN/bin/ls" ]; then
    RD=$(mktemp -d)
    cp -a "$M10_DEBIAN/." "$RD"
    smoke=$(run -R -l "$RD" /bin/sh -c 'head -1 /etc/os-release' 2>/dev/null)
    case "$smoke" in
    *[Dd]ebian*)
        RDO=$(mktemp -d)
        cp -a "$M10_DEBIAN/." "$RDO"
        ds='cd /tmp; mkdir d; cd d; echo hi>a; ln a b; stat -c %h a b;
            [ "$(stat -c %i a)" = "$(stat -c %i b)" ] && echo same-ino;
            find . -samefile a | sort; cat b'
        out_o=$("$M10_ORACLE" "$RDO" /bin/sh -c "$ds" 2>/dev/null); rc_o=$?
        out_e=$(run -R -l "$RD" /bin/sh -c "$ds" 2>/dev/null); rc_e=$?
        if [ "$out_o" = "$out_e" ] && [ "$rc_o" = "$rc_e" ]; then
            pass=$((pass + 1)); echo "  ok   m10 debian: GNU stat + find -samefile"
        else
            fail=$((fail + 1)); echo "  FAIL m10 debian: GNU stat + find -samefile"
            echo "    oracle rc=$rc_o: $(printf %s "$out_o" | head -c 300)"
            echo "    chroot rc=$rc_e: $(printf %s "$out_e" | head -c 300)"
        fi
        rm -rf "$RDO"
        ;;
    *)
        skip "debian glibc guest not translating under -R (got '$smoke')"
        ;;
    esac
    rm -rf "$RD"
elif [ "$m10_ready" -eq 1 ]; then
    skip "debian leg: no debian rootfs"
fi

# Legs that need no oracle: an Alpine rootfs, and for the race a guest compiler.
if [ -n "$M10_ALPINE" ] && [ -x "$M10_ALPINE/bin/busybox" ]; then
    # A FIFO cannot stand behind a symlink as a regular file does, so the
    # emulation cannot link one — but it must say so. The fallback copied what
    # it could not point at by opening the source, and the open of a FIFO for
    # reading waits for a writer: `ln fifo fifo2` never returned.
    REM=$(mktemp -d); cp -a "$M10_ALPINE/." "$REM"
    out=$(run_t 120 -R -l "$REM" /bin/sh -c \
        'cd /tmp; mkfifo p; ln p p2 2>&1; echo rc=$?; ls' 2>&1)
    rc=$?
    check "m10 ln of a FIFO returns instead of waiting for a writer" 0 "$rc"
    check_contains "m10 ...and is refused as a link the emulation cannot make" \
        "rc=1" "$out"
    rm -rf "$REM"
fi

# The first link of a file, made by many processes at once. It took no lock:
# a second process saw the plain file the first was moving into the store, and
# its rename put the first's new symlink on the data file, which was then a
# symlink to itself — "Symbolic link loop" from every name, the contents gone.
# 16 processes are released together against each of 40 fresh files; every
# link must succeed, every name read the contents, and st_nlink be the number
# of names. Again with a plain file on the store's name, which leaves each group
# beside its first name and the lock to the directory.
if [ -n "$M10_ALPINE" ] && [ -x "$M10_ALPINE/bin/busybox" ] &&
    guest_xlate_ready "l2s first-link race leg" &&
    guest_cc_report "$CNG_TMP/l2srace" tests/guests/l2srace.c; then
    for _mode in store per-dir; do
        REM=$(mktemp -d); cp -a "$M10_ALPINE/." "$REM"
        cp "$CNG_TMP/l2srace" "$REM/bin/l2srace"
        [ "$_mode" = per-dir ] && : >"$REM/.l2s"
        out=$(run_t 300 -R -l "$REM" /bin/sh -c 'cd /tmp; /bin/l2srace 40 16' 2>&1)
        check_contains "m10 16 processes' first link of one file ($_mode)" \
            "l2srace rounds=40 procs=16 linkfail=0 unreadable=0 badcount=0 broken=0" \
            "$out"
        rm -rf "$REM"
    done
fi

unset CNG_L2S_FORCE
