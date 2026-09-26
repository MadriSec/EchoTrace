#!/usr/bin/env bash
#
# Recreate the SONAME symlinks that extraction drops.
#
# docker cp copies symlink TARGETS, not the symlinks themselves, so a library
# arrives only under its versioned filename while every ELF that depends on it
# records the soname:
#
#   libtcnative DT_NEEDED:  libssl.so.1.1        <- what SysPart looks for
#   extracted on disk:      libssl.so.1.1.1zh    <- the only thing present
#
# SysPart resolves DT_NEEDED entries by soname against USER_LIBRARY_PATH. When
# the name is absent it cannot load the dependency, produces an empty call
# graph, and still exits 0 -- so the library silently contributes no syscalls.
#
# Existing files and links are never replaced, so this is safe to re-run.
# extract_runtime_and_jar_libs.sh calls it automatically; run it by hand for
# mirrors extracted before that step existed.
#
# Usage:
#   IMG_NAME=tomcat_9.0.120-jdk8-corretto-al2 ./scripts/relink_sonames.sh
#   ./scripts/relink_sonames.sh /path/to/LIBS_dir
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [ "$#" -ge 1 ]; then
    TARGET_DIR="$1"
elif [ -n "${LIBS_DIR:-}" ]; then
    TARGET_DIR="$LIBS_DIR"
elif [ -n "${IMG_NAME:-}" ]; then
    TARGET_DIR="${PROJECT_ROOT}/LIBS_${IMG_NAME}"
else
    echo "ERROR: provide a directory, or set IMG_NAME or LIBS_DIR" >&2
    echo "  IMG_NAME=tomcat_9.0.120-jdk8-corretto-al2 $0" >&2
    echo "  $0 /path/to/LIBS_dir" >&2
    exit 1
fi

if [ ! -d "$TARGET_DIR" ]; then
    echo "ERROR: not a directory: $TARGET_DIR" >&2
    exit 1
fi

echo "============================================================"
echo " Restoring SONAME symlinks"
echo "============================================================"
echo "LIB directory: $TARGET_DIR"

CREATED=0
SKIPPED=0
while IFS= read -r lib; do
    # `|| true` matters: pipefail plus a non-ELF file in the mirror (ld.so.cache
    # is the usual one) would otherwise abort the whole run via set -e.
    #
    # LC_ALL=C matters just as much: readelf translates its output, and a French
    # system prints "Bibliotheque soname<U+00A0>: [name]" with a non-breaking
    # space before the colon. The pattern below expects an ordinary space, finds
    # nothing, and every library is skipped -- reported as "Created 0 symlink(s),
    # 0 already present", which reads like a mirror that needs no work.
    soname="$(LC_ALL=C readelf -d "$lib" 2>/dev/null | sed -n 's/.*soname *: *\[\(.*\)\].*/\1/p' || true)"
    [ -n "$soname" ] || continue
    lib_dir="$(dirname "$lib")"
    lib_base="$(basename "$lib")"
    # The file is already named after its soname: nothing to link.
    [ "$soname" = "$lib_base" ] && continue
    if [ -e "$lib_dir/$soname" ] || [ -L "$lib_dir/$soname" ]; then
        SKIPPED=$((SKIPPED + 1))
        continue
    fi
    if ln -s "$lib_base" "$lib_dir/$soname" 2>/dev/null; then
        echo "  $soname -> $lib_base"
        CREATED=$((CREATED + 1))
    else
        echo "  WARNING: could not link $lib_dir/$soname" >&2
    fi
done < <(find "$TARGET_DIR" -type f -name "*.so*" 2>/dev/null)

echo "Created $CREATED symlink(s), $SKIPPED already present"

# Report links whose target vanished; these break dependency resolution just as
# a missing link does, and are invisible without an explicit check.
BROKEN=0
while IFS= read -r link; do
    if [ ! -e "$link" ]; then
        echo "  BROKEN: $link -> $(readlink "$link")" >&2
        BROKEN=$((BROKEN + 1))
    fi
done < <(find "$TARGET_DIR" -type l -name "*.so*" 2>/dev/null)
[ "$BROKEN" -gt 0 ] && echo "WARNING: $BROKEN dangling symlink(s)" >&2

# Note: verify with the loader, not ldd. ldd searches /lib, /usr/lib and
# ld.so.cache -- never this directory -- so it reports these dependencies as
# missing even when they resolve correctly, and substitutes host libraries of
# the wrong version for the ones it does find:
#
#   LD_LIBRARY_PATH="$TARGET_DIR" /lib64/ld-linux-x86-64.so.2 --list <lib>
#
# Never export LD_LIBRARY_PATH to this directory: the container's glibc
# replaces the host's and breaks unrelated binaries.
exit 0
