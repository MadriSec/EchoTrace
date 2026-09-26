#!/usr/bin/env bash
#
# Extract shared libraries from a directory of JARs into a LIBS folder.
#
# Modes:
#   1 (default) - Extract ALL .so / .so.* files found in JARs
#                 (no arch/OS filtering, no ELF validation).
#   2           - Filtered extraction:
#                 only .so / .so.* files matching the current CPU architecture,
#                 skipping non-Linux OS artifacts, with ELF validation.
#
# Inputs (positional, optional):
#   1) SRC  - Directory containing JARs to scan (default: JARFILES)
#   2) DEST - Output directory to place extracted .so files (default: LIBS)
#
# Environment:
#   EXTRACT_MODE=1|2   (default: 1)
#
# Usage:
#   ./extract_libs_jars.sh
#   ./extract_libs_jars.sh /path/to/JARFILES /path/to/LIBS
#   EXTRACT_MODE=2 ./extract_libs_jars.sh
#
# Exit behavior:
#   - Stops on error due to `set -euo pipefail`
#   - Non-critical steps use `|| true` where appropriate
#
set -euo pipefail

# -----------------------------
# Mode selection
# -----------------------------
MODE="${EXTRACT_MODE:-2}"
if [[ "$MODE" != "1" && "$MODE" != "2" ]]; then
  echo "ERROR: EXTRACT_MODE must be 1 or 2 (got: $MODE)" >&2
  exit 1
fi

# -----------------------------
# Path setup
# -----------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DEFAULT="${SCRIPT_DIR}/JARFILES"
DEST_DEFAULT="${SCRIPT_DIR}/LIBS"

# Prefer image-scoped vars, then regular vars, then defaults
SRC="${1:-${JARFILES_IMAGE:-${JARFILES_DIR:-$SRC_DEFAULT}}}"
DEST="${2:-${LIBS_IMAGE:-${LIBS_DIR:-$DEST_DEFAULT}}}"

TMP_DIR="$DEST/.tmp"

mkdir -p "$DEST" "$TMP_DIR"

# -----------------------------
# Input validation
# -----------------------------
if [[ ! -d "$SRC" ]]; then
  echo "ERROR: Source directory does not exist: $SRC" >&2
  echo "Usage: $0 [JAR_DIR] [LIBS_DIR]" >&2
  echo "Or set: JARFILES_IMAGE, JARFILES_DIR, LIBS_IMAGE, or LIBS_DIR" >&2
  exit 1
fi

JAR_COUNT=$(find "$SRC" -maxdepth 1 -type f -name "*.jar" 2>/dev/null | wc -l)
if [[ "$JAR_COUNT" -eq 0 ]]; then
  echo "WARNING: No JAR files found in: $SRC" >&2
  echo "This script is typically run from final_tool.sh with image-scoped directories." >&2
  echo "If running standalone, ensure JARFILES_IMAGE or JARFILES_DIR points to a directory with JARs." >&2
  exit 0
fi

echo "Scanning $JAR_COUNT JAR file(s) in: $SRC"
echo "Extracting to: $DEST"
if [[ "$MODE" == "1" ]]; then
  echo "Mode: 1 (extract all .so / .so.* files)"
else
  echo "Mode: 2 (filtered by arch / Linux OS / ELF validation)"
fi
echo

# -----------------------------
# Architecture filter patterns
# -----------------------------
case "$(uname -m)" in
  x86_64|amd64)
    ARCH_RE='x86_64|x86-64|amd64|linux-x86_64|linux-x86-64'
    FILE_ARCH_RE='x86-64|x86_64|AMD x86-64'
    ;;
  aarch64|arm64)
    ARCH_RE='aarch64|aarch_64|arm64|linux-aarch64|linux-aarch_64'
    FILE_ARCH_RE='aarch64|arm64|ARM aarch64'
    ;;
  ppc64le)
    ARCH_RE='ppc64le'
    FILE_ARCH_RE='ppc64le|PowerPC64'
    ;;
  *)
    ARCH_RE='x86_64|x86-64|amd64'
    FILE_ARCH_RE='x86-64|x86_64|AMD x86-64'
    ;;
esac

# Ignore entries clearly intended for other operating systems
BAD_OS_RE='darwin|osx|mac|win|windows|sunos|solaris|freebsd|openbsd|netbsd|aix|dragonfly|android'

# -----------------------------
# libc detection
# -----------------------------
LIBC_KIND="glibc"
if ldd --version 2>&1 | grep -qi musl; then
  LIBC_KIND="musl"
fi

# -----------------------------
# Helpers
# -----------------------------

# Returns 0 only if the file looks runnable on this system.
verify_so() {
  local f="$1"

  # Must be ELF for our architecture
  if ! file -b "$f" | grep -qiE "ELF .*(${FILE_ARCH_RE})"; then
    return 1
  fi

  # Reject obvious non-Linux deps early
  if objdump -p "$f" 2>/dev/null | grep -qiE 'NEEDED.*(libc\.so\.7|libthr\.so\.3|libdl\.so\.1)'; then
    return 1
  fi

  if [[ "$LIBC_KIND" == "glibc" ]]; then
    # Reject musl-linked binaries on glibc systems
    if objdump -p "$f" 2>/dev/null | grep -qiE 'NEEDED.*libc\.musl|INTERP.*/ld-musl-'; then
      return 1
    fi
    return 0
  else
    # On musl, reject glibc loader hints when present
    if objdump -p "$f" 2>/dev/null | grep -qiE 'INTERP.*/ld-linux|NEEDED.*libc\.so\.6'; then
      return 1
    fi
    return 0
  fi
}

make_unique_tmp_out() {
  local base="$1"
  local jar_basename="$2"
  local out="$TMP_DIR/$base"

  if [[ -e "$out" ]]; then
    local stem suffix
    stem="${base%%.so*}"
    suffix="${base#${stem}}"
    out="$TMP_DIR/${stem}_${jar_basename}${suffix}"
  fi

  echo "$out"
}

extract_entry() {
  local jar_abs="$1"
  local entry="$2"
  local out="$3"

  local temp_extract_dir
  temp_extract_dir="$(mktemp -d)"

  if (cd "$temp_extract_dir" && jar xf "$jar_abs" "$entry" 2>/dev/null); then
    if [[ -f "$temp_extract_dir/$entry" ]]; then
      mkdir -p "$(dirname "$out")"
      cp "$temp_extract_dir/$entry" "$out"
      rm -rf "$temp_extract_dir"
      return 0
    fi
  fi

  rm -rf "$temp_extract_dir"
  return 1
}

move_to_dest_root() {
  local f="$1"
  local target="$DEST/$(basename "$f")"

  if [[ -e "$target" ]]; then
    mv -f "$f" "$target"
  else
    mv -f "$f" "$target"
  fi
}

# -----------------------------
# Extraction pass
# -----------------------------
shopt -s nullglob

extracted_tmp=0
ok=0
skipped=0

for jar in "$SRC"/*.jar; do
  echo "==> Scanning: $jar"

  if [[ "$jar" = /* ]]; then
    JAR_ABS="$jar"
  else
    JAR_ABS="$(cd "$(dirname "$jar")" && pwd)/$(basename "$jar")"
  fi

  jar_name="$(basename "$jar")"
  jar_name_lc="${jar_name,,}"
  jar_base_noext="$(basename "$jar" .jar)"

  # Some JARs encode architecture in the JAR filename itself
  jar_has_arch=false
  if [[ "$jar_name_lc" =~ ($ARCH_RE) ]]; then
    jar_has_arch=true
  fi

  while IFS= read -r entry; do
    # Accept .so and .so.* entries
    [[ "$entry" =~ \.so($|\.) ]] || continue

    if [[ "$MODE" == "2" ]]; then
      base_name="$(basename "$entry")"
      entry_lc="${entry,,}"
      base_name_lc="${base_name,,}"

      # Require architecture match in path, basename, or JAR filename
      if [[ ! "$entry_lc" =~ ($ARCH_RE) ]] && \
         [[ ! "$base_name_lc" =~ ($ARCH_RE) ]] && \
         [[ "$jar_has_arch" != true ]]; then
        continue
      fi

      # Skip entries clearly meant for non-Linux OSes
      [[ ! "$entry_lc" =~ ($BAD_OS_RE) ]] || continue
    fi

    base="$(basename "$entry")"
    out="$(make_unique_tmp_out "$base" "$jar_base_noext")"

    if extract_entry "$JAR_ABS" "$entry" "$out"; then
      echo "    extracted: $entry -> $(basename "$out")"
      ((extracted_tmp++)) || true
    else
      echo "    (could not extract: $entry)" >&2
      ((skipped++)) || true
    fi
  done < <(jar -tf "$JAR_ABS" 2>/dev/null || true)
done

# -----------------------------
# Finalize
# -----------------------------
for f in "$TMP_DIR"/*.so*; do
  [[ -e "$f" ]] || continue

  if [[ "$MODE" == "1" ]]; then
    move_to_dest_root "$f"
    ((ok++)) || true
  else
    if verify_so "$f"; then
      move_to_dest_root "$f"
      ((ok++)) || true
    else
      rm -f "$f"
      ((skipped++)) || true
    fi
  fi
done

rmdir "$TMP_DIR" 2>/dev/null || true

echo
echo "Libraries are in: $DEST"
echo "TEMP_EXTRACTED: $extracted_tmp"
echo "OK: $ok   SKIPPED: $skipped"
