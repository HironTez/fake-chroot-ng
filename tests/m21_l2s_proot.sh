# M21: proot's link2symlink groups (sourced by tests/run.sh).
#
# A rootfs installed through proot (proot-distro's) holds its hardlinks as
# proot wrote them: every name is a symlink holding an absolute HOST path to an
# indirection symlink in the l2s directory ("<rootfs>/.l2s/.l2s.<name><NNNN>"),
# which names the data file beside it ("….<CCCC>"), whose last four digits are
# the live link count. chroot-ng follows those, presents each name as the one
# regular file a hardlink is, and keeps proot's own bookkeeping as names come
# and go, so a rootfs can move between proot and chroot-ng (-l).
#
# Two kinds of row, both against a layout this file lays down BY HAND exactly
# as proot's does (recorded on a device: ".l2s.a0001" -> ".l2s.a0001.0002",
# member text <rootfs>/.l2s/.l2s.a0001):
#
#  1. DIFFERENTIAL, tests/guests/l2sproot.c: the same program run over real
#     hardlinks on a real kernel printed tests/guests/l2sproot.expect; chroot-ng
#     must print the same bytes over proot's layout. Then the host side: the l2s
#     directory must hold what proot itself would leave.
#  2. HOSTILE, tests/guests/l2sprobe.c: the symlinks of a rootfs are the guest's
#     -- or an image's -- to write. Layouts that claim to be groups they are
#     not, point out of the rootfs, loop, or sit over a read-only l2s directory.
#     The answers must be an ordinary symlink's, and the CANARIES (files outside
#     the rootfs, or on a read-only bind) byte for byte what they were.
echo "== M21: proot's link2symlink groups =="

l2sp_row() { # name expected got
    if [ "$2" = "$3" ]; then
        pass=$((pass + 1))
        echo "  ok   m21 $1"
    else
        fail=$((fail + 1))
        echo "  FAIL m21 $1"
        printf '%s\n' "$2" >"$CNG_TMP/l2sp.exp"
        printf '%s\n' "$3" >"$CNG_TMP/l2sp.got"
        diff "$CNG_TMP/l2sp.exp" "$CNG_TMP/l2sp.got" | head -12 | sed 's/^/       /'
    fi
}

l2sp_verdict() { # name ok(1|0) note
    if [ "$2" = 1 ]; then
        pass=$((pass + 1))
        echo "  ok   m21 $1"
    else
        fail=$((fail + 1))
        echo "  FAIL m21 $1 ($3)"
    fi
}

# The l2s directory as proot would read it: chroot-ng's store lock file is its
# own and proot never looks at it.
l2sp_ls() { ls -A "$1" | grep -v '^\.lock$' | sort | tr '\n' ' '; }

l2sp_run() { run_t 120 -R -l "$@" 2>/dev/null; }

# The rootfs W/r with the probe at /bin/p, and the host paths proot recorded.
l2sp_newroot() {
    W=$(mktemp -d)
    R=$W/r
    mkdir -p "$R/bin" "$R/.l2s" "$W/out" || return 1
    cp "$CNG_TMP/l2sprobe" "$R/bin/p" || return 1
    P=$(cd "$R" && pwd -P)
    WP=$(cd "$W" && pwd -P)
}

# A group the way proot makes it: <dir>/.l2s.<name>0001 -> <dirhost>/.l2s.<name>0001.<CCCC>.
l2sp_group() { # dir hostdir name count content
    printf '%s' "$5" >"$1/.l2s.${3}0001.$(printf %04d "$4")"
    ln -s "$2/.l2s.${3}0001.$(printf %04d "$4")" "$1/.l2s.${3}0001"
}

# A tree's identity -- names, kinds, sizes, link texts, every byte.
l2sp_snap() {
    (cd "$1" && find . -printf '%p %y %s %l\n' | sort | md5sum | cut -c1-16
        find . -type f -print0 | sort -z | xargs -0 cat 2>/dev/null | md5sum | cut -c1-16)
}

# The groups the differential guest works on (see l2sproot.c).
l2sp_layout() { # rootfs guest-binary
    _R=$1
    _b=$2
    mkdir -p "$_R/.l2s" "$_R/g" "$_R/h" "$_R/bin2" "$_R/bin"
    cp "$_b" "$_R/bin/t"
    _P=$(cd "$_R" && pwd -P)
    printf 'hello\n' >"$_R/.l2s/.l2s.a0001.0003"
    ln -s "$_P/.l2s/.l2s.a0001.0003" "$_R/.l2s/.l2s.a0001"
    for _n in g/a g/b h/c; do ln -s "$_P/.l2s/.l2s.a0001" "$_R/$_n"; done
    printf 'plain\n' >"$_R/g/plain"
    printf 'p2\n' >"$_R/h/p2"
    printf 'xx\n' >"$_R/.l2s/.l2s.x10001.0002"
    ln -s "$_P/.l2s/.l2s.x10001.0002" "$_R/.l2s/.l2s.x10001"
    for _n in x1 x2; do ln -s "$_P/.l2s/.l2s.x10001" "$_R/$_n"; done
    cp "$_b" "$_R/.l2s/.l2s.t10001.0002"
    chmod 755 "$_R/.l2s/.l2s.t10001.0002"
    ln -s "$_P/.l2s/.l2s.t10001.0002" "$_R/.l2s/.l2s.t10001"
    for _n in bin2/t1 bin2/t2; do ln -s "$_P/.l2s/.l2s.t10001" "$_R/$_n"; done
    chmod 644 "$_R/.l2s/.l2s.a0001.0003" "$_R/.l2s/.l2s.x10001.0002"
}

if guest_xlate_ready "M21 proot groups" &&
    guest_cc_report "$CNG_TMP/l2sproot" tests/guests/l2sproot.c &&
    guest_cc_report "$CNG_TMP/l2sprobe" tests/guests/l2sprobe.c; then

    # ---- 1. the differential row, and the host's side of it ----
    W=$(mktemp -d)
    R=$W/r
    mkdir -p "$R"
    l2sp_layout "$R" "$CNG_TMP/l2sproot"
    P=$(cd "$R" && pwd -P)
    got=$(l2sp_run "$R" /bin/t proot)
    l2sp_row "the guest's view over proot's layout is a kernel's over real hardlinks" \
        "$(cat tests/guests/l2sproot.expect)" "$got"
    # What proot would find afterwards: group a at count 2 (data renamed, the
    # indirection re-pointed), group x1 gone (its last name was removed), group
    # t1 untouched, no temporary left, every member's text as it was.
    ok=1
    [ "$(l2sp_ls "$R/.l2s")" = ".l2s.a0001 .l2s.a0001.0002 .l2s.t10001 .l2s.t10001.0002 " ] || ok=0
    [ "$(readlink "$R/.l2s/.l2s.a0001")" = "$P/.l2s/.l2s.a0001.0002" ] || ok=0
    for _n in x2 g/z; do [ "$(readlink "$R/$_n")" = "$P/.l2s/.l2s.a0001" ] || ok=0; done
    for _n in bin2/t1 bin2/t2; do [ "$(readlink "$R/$_n")" = "$P/.l2s/.l2s.t10001" ] || ok=0; done
    [ "$(cat "$R/.l2s/.l2s.a0001.0002")" = hello ] || ok=0
    l2sp_verdict "the l2s directory is left as proot's own would leave it" "$ok" \
        "$(l2sp_ls "$R/.l2s")"
    rm -rf "$W"
    # The same with the rootfs named through a symlink: the recorded host path is
    # the real one, and it must be found from either spelling.
    W=$(mktemp -d)
    mkdir -p "$W/real"
    l2sp_layout "$W/real" "$CNG_TMP/l2sproot"
    ln -s real "$W/via"
    got=$(l2sp_run "$W/via" /bin/t proot)
    l2sp_row "the rootfs named through a symlink" \
        "$(cat tests/guests/l2sproot.expect)" "$got"
    rm -rf "$W"
    # The same group, moved: `cp -a` of the rootfs leaves the recorded host path
    # naming the ORIGINAL's store. The copy reads its own.
    W=$(mktemp -d)
    mkdir -p "$W/orig"
    l2sp_layout "$W/orig" "$CNG_TMP/l2sproot"
    cp -a "$W/orig" "$W/copy"
    got=$(l2sp_run "$W/copy" /bin/t proot)
    l2sp_row "a copied rootfs reads its own store" \
        "$(cat tests/guests/l2sproot.expect)" "$got"
    l2sp_verdict "...and leaves the original's alone" \
        "$([ "$(l2sp_ls "$W/orig/.l2s")" = ".l2s.a0001 .l2s.a0001.0003 .l2s.t10001 .l2s.t10001.0002 .l2s.x10001 .l2s.x10001.0002 " ] && echo 1 || echo 0)" \
        "$(l2sp_ls "$W/orig/.l2s")"
    rm -rf "$W"

    # ---- 2. hostile layouts ----
    # A target climbing out of the rootfs with '..' towards a VALID group outside.
    l2sp_newroot
    l2sp_group "$W/out" "$WP/out" k 2 'SECRET
'
    ln -s "$P/.l2s/../../out/.l2s.k0001" "$R/m"
    before=$(l2sp_snap "$W/out")
    got=$(l2sp_run "$R" /bin/p lstat /m stat /m cat /m onf /m utime /m link /m /m2 lstat /m2 unlink /m unlink /m2)
    l2sp_row "a target climbing out with '..' reaches nothing" \
        "$(printf '%s\n' 'lstat /m: lnk' 'stat /m: errno=2' 'cat /m: errno=2' 'onf /m: failed errno=40' 'utime /m: 0 errno=0' 'link /m2: 0 errno=0' 'lstat /m2: lnk' 'unlink /m: 0 errno=0' 'unlink /m2: 0 errno=0')" "$got"
    l2sp_verdict "...and the group outside is untouched" \
        "$([ "$before" = "$(l2sp_snap "$W/out")" ] && echo 1 || echo 0)" "canary changed"
    rm -rf "$W"
    # The host path of a SIBLING whose name merely starts with the rootfs's own.
    l2sp_newroot
    mkdir -p "$W/r2/.l2s" "$R/2/.l2s"
    l2sp_group "$W/r2/.l2s" "$WP/r2/.l2s" k 2 'SECRET
'
    l2sp_group "$R/2/.l2s" "$P/2/.l2s" k 2 'INSIDE
'
    ln -s "$WP/r2/.l2s/.l2s.k0001" "$R/m"
    before=$(l2sp_snap "$W/r2")
    got=$(l2sp_run "$R" /bin/p lstat /m cat /m link /m /m2 unlink /m unlink /m2)
    l2sp_row "a sibling directory sharing the rootfs's name as a prefix is not the rootfs" \
        "$(printf '%s\n' 'lstat /m: lnk' 'cat /m: errno=2' 'link /m2: 0 errno=0' 'unlink /m: 0 errno=0' 'unlink /m2: 0 errno=0')" "$got"
    l2sp_verdict "...and that sibling is untouched" \
        "$([ "$before" = "$(l2sp_snap "$W/r2")" ] && echo 1 || echo 0)" "canary changed"
    rm -rf "$W"
    # The host path of a valid group outside the rootfs, spelled in full.
    l2sp_newroot
    l2sp_group "$W/out" "$WP/out" k 2 'SECRET
'
    ln -s "$WP/out/.l2s.k0001" "$R/m"
    before=$(l2sp_snap "$W/out")
    got=$(l2sp_run "$R" /bin/p lstat /m cat /m link /m /m2 unlink /m unlink /m2)
    l2sp_row "the host path of a valid group outside the rootfs reaches nothing" \
        "$(printf '%s\n' 'lstat /m: lnk' 'cat /m: errno=2' 'link /m2: 0 errno=0' 'unlink /m: 0 errno=0' 'unlink /m2: 0 errno=0')" "$got"
    l2sp_verdict "...and the group outside is untouched" \
        "$([ "$before" = "$(l2sp_snap "$W/out")" ] && echo 1 || echo 0)" "canary changed"
    rm -rf "$W"
    # An absolute host path that is NOT an l2s name keeps meaning what it did.
    l2sp_newroot
    mkdir "$R/etc"
    echo real >"$R/etc/real"
    ln -s "$P/etc/real" "$R/m"
    got=$(l2sp_run "$R" /bin/p lstat /m stat /m cat /m readlink /m | sed "s|$P|<R>|g")
    l2sp_row "a host-absolute symlink that is not an l2s name is left alone" \
        "$(printf '%s\n' 'lstat /m: lnk' 'stat /m: errno=2' 'cat /m: errno=2' 'readlink /m: <R>/etc/real')" "$got"
    rm -rf "$W"
    # Chains that do not check out are ordinary symlinks.
    l2sp_newroot
    ln -s "$P/.l2s/.l2s.n0001" "$R/m_noind"
    mkdir "$R/.l2s/.l2s.d0001.0002"
    ln -s "$P/.l2s/.l2s.d0001.0002" "$R/.l2s/.l2s.d0001"
    ln -s "$P/.l2s/.l2s.d0001" "$R/m_dir"
    mkdir "$R/other"
    printf 'OTHER\n' >"$R/other/.l2s.o0001.0002"
    ln -s "$P/other/.l2s.o0001.0002" "$R/.l2s/.l2s.o0001"
    ln -s "$P/.l2s/.l2s.o0001" "$R/m_otherdir"
    printf 'ZZ\n' >"$R/.l2s/.l2s.zzzz0001.0002"
    ln -s "$P/.l2s/.l2s.zzzz0001.0002" "$R/.l2s/.l2s.q0001"
    ln -s "$P/.l2s/.l2s.q0001" "$R/m_mismatch"
    printf 'FILE\n' >"$R/.l2s/.l2s.e0001"
    ln -s "$P/.l2s/.l2s.e0001" "$R/m_notlink"
    got=$(l2sp_run "$R" /bin/p lstat /m_noind stat /m_noind cat /m_noind lstat /m_dir stat /m_dir cat /m_dir \
        lstat /m_otherdir stat /m_otherdir cat /m_otherdir lstat /m_mismatch stat /m_mismatch cat /m_mismatch \
        lstat /m_notlink stat /m_notlink cat /m_notlink | sed "s|$P|<R>|g")
    l2sp_row "chains that do not check out are ordinary symlinks" \
        "$(printf '%s\n' 'lstat /m_noind: lnk' 'stat /m_noind: errno=2' 'cat /m_noind: errno=2' 'lstat /m_dir: lnk' 'stat /m_dir: dir nlink=0' 'cat /m_dir: errno=21' 'lstat /m_otherdir: lnk' 'stat /m_otherdir: reg nlink=1 size=6' 'cat /m_otherdir: OTHER|' 'lstat /m_mismatch: lnk' 'stat /m_mismatch: reg nlink=1 size=3' 'cat /m_mismatch: ZZ|' 'lstat /m_notlink: lnk' 'stat /m_notlink: reg nlink=1 size=5' 'cat /m_notlink: FILE|')" "$got"
    rm -rf "$W"
    # A loop: the data name is the indirection itself.
    l2sp_newroot
    ln -s "$P/.l2s/.l2s.c0001.0002" "$R/.l2s/.l2s.c0001"
    ln -s "$P/.l2s/.l2s.c0001" "$R/.l2s/.l2s.c0001.0002"
    ln -s "$P/.l2s/.l2s.c0001" "$R/m"
    got=$(l2sp_run "$R" /bin/p lstat /m cat /m onf /m unlink /m)
    l2sp_row "a loop ends in ELOOP, not in a hang" \
        "$(printf '%s\n' 'lstat /m: lnk' 'cat /m: errno=40' 'onf /m: failed errno=40' 'unlink /m: 0 errno=0')" "$got"
    rm -rf "$W"
    # Counts at the ends: 0000 reads as one name; 9999 takes no more (EMLINK).
    l2sp_newroot
    l2sp_group "$R/.l2s" "$P/.l2s" f 0 'F0
'
    ln -s "$P/.l2s/.l2s.f0001" "$R/m_zero"
    l2sp_group "$R/.l2s" "$P/.l2s" g 9999 'G9
'
    ln -s "$P/.l2s/.l2s.g0001" "$R/m_max"
    got=$(l2sp_run "$R" /bin/p lstat /m_zero link /m_zero /m_zero2 lstat /m_zero2 unlink /m_zero unlink /m_zero2 lstat /m_max link /m_max /m_max2 lstat /m_max)
    l2sp_row "count 0000 is one name, count 9999 takes no more" \
        "$(printf '%s\n' 'lstat /m_zero: reg nlink=1 size=3' 'link /m_zero2: 0 errno=0' 'lstat /m_zero2: reg nlink=2 size=3' 'unlink /m_zero: 0 errno=0' 'unlink /m_zero2: 0 errno=0' 'lstat /m_max: reg nlink=9999 size=3' 'link /m_max2: -1 errno=31' 'lstat /m_max: reg nlink=9999 size=3')" "$got"
    ok=1
    [ -z "$(l2sp_ls "$R/.l2s" | grep '\.l2s\.f0001')" ] || ok=0
    [ -e "$R/.l2s/.l2s.g0001.9999" ] || ok=0
    [ ! -e "$R/m_max2" ] || ok=0
    l2sp_verdict "...the emptied group is gone, the full one is as it was" "$ok" \
        "$(l2sp_ls "$R/.l2s")"
    rm -rf "$W"
    # The l2s directory on a READ-ONLY bind, the names in the writable rootfs: a
    # new name is EROFS, a stamp on the data is EROFS, and a removed name still
    # goes with its count left alone (the count is a write into a :ro mount).
    l2sp_newroot
    rm -rf "$R/.l2s"
    mkdir "$R/.l2s" "$W/ldir" "$R/g"
    l2sp_group "$W/ldir" "$P/.l2s" a 3 'ROGROUP
'
    for _n in x y z; do ln -s "$P/.l2s/.l2s.a0001" "$R/g/$_n"; done
    echo hello >"$R/g/plain"
    before=$(l2sp_snap "$W/ldir")
    got=$(l2sp_run -b "$WP/ldir:/.l2s:ro" "$R" /bin/p lstat /g/x cat /g/x link /g/x /g/new utime /g/x onf /g/x unlink /g/y rename /g/plain /g/z lstat /g/x)
    l2sp_row "the l2s directory on a read-only bind" \
        "$(printf '%s\n' 'lstat /g/x: reg nlink=3 size=8' 'cat /g/x: ROGROUP|' 'link /g/new: -1 errno=18' 'utime /g/x: -1 errno=30' 'onf /g/x: ok errno=0' 'unlink /g/y: 0 errno=0' 'rename /g/z: 0 errno=0' 'lstat /g/x: reg nlink=3 size=8')" "$got"
    l2sp_verdict "...and the read-only directory is byte for byte what it was" \
        "$([ "$before" = "$(l2sp_snap "$W/ldir")" ] && echo 1 || echo 0)" "written through a :ro bind"
    l2sp_verdict "...and no name was made" \
        "$([ ! -L "$R/g/new" ] && [ -L "$R/g/x" ] && [ ! -L "$R/g/y" ] && echo 1 || echo 0)" \
        "$(ls "$R/g" | tr '\n' ' ')"
    rm -rf "$W"
    # The same on a writable bind: the count follows the names.
    l2sp_newroot
    rm -rf "$R/.l2s"
    mkdir "$R/.l2s" "$W/ldir" "$R/g"
    l2sp_group "$W/ldir" "$P/.l2s" a 3 'RWGROUP
'
    for _n in x y z; do ln -s "$P/.l2s/.l2s.a0001" "$R/g/$_n"; done
    got=$(l2sp_run -b "$WP/ldir:/.l2s" "$R" /bin/p lstat /g/x link /g/x /g/new lstat /g/x unlink /g/y unlink /g/z lstat /g/x)
    l2sp_row "the l2s directory on a writable bind" \
        "$(printf '%s\n' 'lstat /g/x: reg nlink=3 size=8' 'link /g/new: 0 errno=0' 'lstat /g/x: reg nlink=4 size=8' 'unlink /g/y: 0 errno=0' 'unlink /g/z: 0 errno=0' 'lstat /g/x: reg nlink=2 size=8')" "$got"
    l2sp_verdict "...and the data file carries the count" \
        "$([ -f "$W/ldir/.l2s.a0001.0002" ] && echo 1 || echo 0)" "$(l2sp_ls "$W/ldir")"
    rm -rf "$W"
    # The l2s directory is a symlink INSIDE the rootfs: resolved like any path.
    l2sp_newroot
    rm -rf "$R/.l2s"
    mkdir "$R/real"
    ln -s real "$R/.l2s"
    l2sp_group "$R/real" "$P/.l2s" a 2 'VIA-LINK
'
    for _n in m1 m2; do ln -s "$P/.l2s/.l2s.a0001" "$R/$_n"; done
    got=$(l2sp_run "$R" /bin/p lstat /m1 cat /m1 link /m1 /m3 lstat /m1 unlink /m3 unlink /m2 lstat /m1)
    l2sp_row "the l2s directory is a symlink inside the rootfs" \
        "$(printf '%s\n' 'lstat /m1: reg nlink=2 size=9' 'cat /m1: VIA-LINK|' 'link /m3: 0 errno=0' 'lstat /m1: reg nlink=3 size=9' 'unlink /m3: 0 errno=0' 'unlink /m2: 0 errno=0' 'lstat /m1: reg nlink=1 size=9')" "$got"
    rm -rf "$W"
    # ... and a symlink to an absolute path OUTSIDE it, where the group is: the
    # absolute path is the guest's, re-rooted, so there is nothing there.
    l2sp_newroot
    rm -rf "$R/.l2s"
    l2sp_group "$W/out" "$WP/out" a 2 'OUT
'
    ln -s "$WP/out" "$R/.l2s"
    ln -s "$P/.l2s/.l2s.a0001" "$R/m1"
    before=$(l2sp_snap "$W/out")
    got=$(l2sp_run "$R" /bin/p lstat /m1 cat /m1 link /m1 /m2 unlink /m1 unlink /m2)
    l2sp_row "the l2s directory is a symlink to a host path outside" \
        "$(printf '%s\n' 'lstat /m1: lnk' 'cat /m1: errno=2' 'link /m2: 0 errno=0' 'unlink /m1: 0 errno=0' 'unlink /m2: 0 errno=0')" "$got"
    l2sp_verdict "...and the group outside is untouched" \
        "$([ "$before" = "$(l2sp_snap "$W/out")" ] && echo 1 || echo 0)" "canary changed"
    rm -rf "$W"
    # A chain cut by a killed process: the data renamed, the indirection naming a
    # file that is gone. The next change finds the one data file there is, makes
    # the chain whole, and goes on from its count.
    l2sp_newroot
    mkdir "$R/g"
    l2sp_group "$R/.l2s" "$P/.l2s" a 2 'CUT
'
    mv "$R/.l2s/.l2s.a0001.0002" "$R/.l2s/.l2s.a0001.0003"
    for _n in x y; do ln -s "$P/.l2s/.l2s.a0001" "$R/g/$_n"; done
    got=$(l2sp_run "$R" /bin/p lstat /g/x link /g/x /g/new lstat /g/x lstat /g/new)
    l2sp_row "a chain cut by a killed process is made whole by the next change" \
        "$(printf '%s\n' 'lstat /g/x: lnk' 'link /g/new: 0 errno=0' 'lstat /g/x: reg nlink=4 size=4' 'lstat /g/new: reg nlink=4 size=4')" "$got"
    l2sp_verdict "...leaving one data file and an indirection that names it" \
        "$([ "$(l2sp_ls "$R/.l2s")" = ".l2s.a0001 .l2s.a0001.0004 " ] &&
            [ "$(readlink "$R/.l2s/.l2s.a0001")" = "$P/.l2s/.l2s.a0001.0004" ] && echo 1 || echo 0)" \
        "$(l2sp_ls "$R/.l2s")"
    rm -rf "$W"
    # A guest cannot write a text that would be taken for a member: counted into
    # a group it was never counted into, its unlink would delete the data from
    # under the names that were left. A relative one is not recognized at all.
    l2sp_newroot
    mkdir "$R/g"
    l2sp_group "$R/.l2s" "$P/.l2s" a 2 'KEEP
'
    for _n in x y; do ln -s "$P/.l2s/.l2s.a0001" "$R/g/$_n"; done
    got=$(l2sp_run "$R" /bin/p symlink "$P/.l2s/.l2s.a0001" /g/evil symlink /.l2s/.l2s.a0001 /g/evil2 \
        symlink .l2s.a0001 /g/rel lstat /g/evil lstat /g/rel lstat /g/x)
    l2sp_row "a guest may not write a link that would pass for a member" \
        "$(printf '%s\n' 'symlink /g/evil: -1 errno=2' 'symlink /g/evil2: -1 errno=2' 'symlink /g/rel: 0 errno=0' 'lstat /g/evil: errno=2' 'lstat /g/rel: lnk' 'lstat /g/x: reg nlink=2 size=5')" "$got"
    rm -rf "$W"
    # A group of a file called "1234" is ".l2s.12340001" -> ".l2s.12340001.0002",
    # which spells our own data file for inode 12340001 and our own marker for
    # it. What tells them apart is what they are: ours is a regular file,
    # proot's indirection a symlink. The names are proot's and are kept so.
    l2sp_newroot
    mkdir "$R/g"
    l2sp_group "$R/.l2s" "$P/.l2s" 1234 2 'NUMERIC
'
    for _n in x y; do ln -s "$P/.l2s/.l2s.12340001" "$R/g/$_n"; done
    got=$(l2sp_run "$R" /bin/p lstat /g/x readlink /g/x link /g/x /g/z lstat /g/y unlink /g/x unlink /g/z lstat /g/y cat /g/y)
    l2sp_row "a proot group named by digits is proot's" \
        "$(printf '%s\n' 'lstat /g/x: reg nlink=2 size=8' 'readlink /g/x: errno=22' 'link /g/z: 0 errno=0' 'lstat /g/y: reg nlink=3 size=8' 'unlink /g/x: 0 errno=0' 'unlink /g/z: 0 errno=0' 'lstat /g/y: reg nlink=1 size=8' 'cat /g/y: NUMERIC|')" "$got"
    l2sp_verdict "...and its files are what proot wrote" \
        "$([ "$(l2sp_ls "$R/.l2s")" = ".l2s.12340001 .l2s.12340001.0001 " ] && echo 1 || echo 0)" \
        "$(l2sp_ls "$R/.l2s")"
    rm -rf "$W"
    # Several processes adding and removing names of one group at once: the
    # count stays exact and the data is never deleted from under a name.
    ok=1
    out=
    for _i in 1 2 3; do
        l2sp_newroot
        mkdir "$R/g"
        l2sp_group "$R/.l2s" "$P/.l2s" a 2 'STRESS
'
        for _m in x y; do ln -s "$P/.l2s/.l2s.a0001" "$R/g/$_m"; done
        got=$(l2sp_run "$R" /bin/p stress /g/x 100 6 lstat /g/x lstat /g/y)
        [ "$got" = "$(printf '%s\n' 'stress /g/x: 0 children failed' 'lstat /g/x: reg nlink=2 size=7' 'lstat /g/y: reg nlink=2 size=7')" ] || {
            ok=0
            out=$got
        }
        [ "$(l2sp_ls "$R/.l2s")" = ".l2s.a0001 .l2s.a0001.0002 " ] || {
            ok=0
            out="$out $(l2sp_ls "$R/.l2s")"
        }
        rm -rf "$W"
    done
    l2sp_verdict "six processes adding and removing names keep the count exact" "$ok" "$out"
fi
