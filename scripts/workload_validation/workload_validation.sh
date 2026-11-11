#!/usr/bin/env bash
#############################################################################
# workload_validation.sh - compare SysJava seccomp policies against the
# syscalls containers actually make under a real workload (the
# docker-library/official-images smoke tests).
#
# For every subject in subjects.conf, sequentially, and every test:
#   workload  run the test WITHOUT any seccomp policy while bpftrace counts
#             every syscall made by the container under test, then diff:
#               missing = observed - policy   (needed, not found by SysJava)
#               used    = observed & policy
#               unused  = policy - observed   (allowed, not exercised)
#             with each policy syscall attributed to its SysJava source.
#   enforce   run the same test under the SysJava policy: does it still pass?
#
# Run as root (bpftrace needs it), keeping your PATH for jq/python3:
#   sudo env "PATH=$PATH" scripts/workload_validation/workload_validation.sh            # all
#   sudo env "PATH=$PATH" scripts/workload_validation/workload_validation.sh cassandra  # some
#
# Environment:
#   PHASES=workload,enforce   phases to run
#   TEST_TIMEOUT=1200         per-test timeout (s)
#   OI_REF=<commit>           pin docker-library/official-images (recorded in meta.txt)
#   CONF=<file>               subjects file (default: subjects.conf next to this script)
#   OUT=<dir>                 output dir (default: workload_validation_runs/<timestamp>)
#
# Requires: x86_64 Linux, root, docker, bpftrace, jq, git, python3, timeout.
#############################################################################
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
CONF="${CONF:-$HERE/subjects.conf}"
PHASES="${PHASES:-workload,enforce}"
TEST_TIMEOUT="${TEST_TIMEOUT:-1200}"
OI_DIR="${OI_DIR:-$ROOT/.cache/official-images}"
OI_REF="${OI_REF:-}"
OUT="${OUT:-$ROOT/workload_validation_runs/$(date +%Y%m%d-%H%M%S)}"
PY="${PYTHON:-python3}"
WV="$HERE/wv.py"
RUNTIME_LIST="$ROOT/runc.txt"

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }
has_phase() { [[ ",$PHASES," == *",$1,"* ]]; }

# ------------------------------------------------------------------ preflight
[[ $EUID -eq 0 ]] || die "run as root: sudo env \"PATH=\$PATH\" $0 $*"
[[ "$(uname -m)" == x86_64 ]] || die "the policies are x86_64; run this on an x86_64 Linux host"
for t in docker jq git timeout bpftrace "$PY"; do
  command -v "$t" >/dev/null || die "missing tool: $t"
done
REAL_DOCKER="$(command -v docker)"
"$REAL_DOCKER" info >/dev/null 2>&1 || die "cannot reach the Docker daemon"
[[ -f "$CONF" ]] || die "subjects file not found: $CONF"

# Containers under test are placed in their own cgroup parent so the trace can
# tell them apart from clients (cqlsh, curl, ...) and from everything else.
if [[ "$("$REAL_DOCKER" info --format '{{.CgroupDriver}}')" == systemd ]]; then
  CG_PARENT="wv.slice"; CG_MATCH="/wv.slice/"
else
  CG_PARENT="/wv"; CG_MATCH="/wv/"
fi

# bpftrace >= 0.20 spells tracepoint arguments args.id, older versions args->id
BT_VER="$(bpftrace --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1)"
if [[ "$(printf '%s\n' "0.20" "$BT_VER" | sort -V | head -1)" == "0.20" ]]; then ARG=args.id; else ARG='args->id'; fi
# Count syscalls per (cgroup, syscall nr) in the kernel. Print each cgroup's path
# and the first process making each syscall once (cheap). Skip runc's own setup
# code (comm "runc:[...]"), which runs before the seccomp filter is installed.
BT_PROG='
BEGIN { printf("READY\n"); }
tracepoint:raw_syscalls:sys_enter /strncmp(comm, "runc:[", 6) != 0/ {
  @n[cgroup, '"$ARG"'] = count();
  if (@cg[cgroup] == 0) { @cg[cgroup] = 1; printf("CG %llu %s\n", cgroup, cgroup_path(cgroup)); }
  if (@first[cgroup, '"$ARG"'] == 0) { @first[cgroup, '"$ARG"'] = 1; printf("FIRST %llu %d %s\n", cgroup, '"$ARG"', comm); }
}
END { clear(@cg); clear(@first); }'

mkdir -p "$OUT/bin"
TRACE_PID=""
cleanup() {
  [[ -n $TRACE_PID ]] && kill -INT "$TRACE_PID" 2>/dev/null
  # hand results back to the invoking user
  if [[ -n "${SUDO_UID:-}" ]]; then
    chown -R "$SUDO_UID:$SUDO_GID" "$OUT" 2>/dev/null
    [[ -d "$OI_DIR" ]] && chown -R "$SUDO_UID:$SUDO_GID" "$(dirname "$OI_DIR")" 2>/dev/null
  fi
}
trap cleanup EXIT

GIT=(git -c safe.directory='*')
if [[ ! -d "$OI_DIR/.git" ]]; then
  log "cloning docker-library/official-images into $OI_DIR"
  "${GIT[@]}" clone -q https://github.com/docker-library/official-images.git "$OI_DIR" || die "clone failed"
fi
if [[ -n $OI_REF ]]; then
  "${GIT[@]}" -C "$OI_DIR" fetch -q origin && "${GIT[@]}" -C "$OI_DIR" checkout -q "$OI_REF" \
    || die "cannot check out $OI_REF"
fi
OI_COMMIT="$("${GIT[@]}" -C "$OI_DIR" rev-parse HEAD)"

# Docker shim, first on PATH for the test scripts: adds the cgroup parent (and,
# in the enforce phase, the seccomp policy) to the `docker run` that starts the
# container under test. Every other docker call passes through unchanged.
cat > "$OUT/bin/docker" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == run && -n "${WV_MODE:-}" ]]; then
  detached=0
  for a in "${@:2}"; do [[ "$a" == -d || "$a" == --detach ]] && detached=1; done
  if [[ "$WV_MODE" == all || $detached == 1 ]]; then
    shift
    extra=(--cgroup-parent "$WV_CGROUP_PARENT")
    [[ -n "${WV_PROFILE:-}" ]] && extra+=(--security-opt "seccomp=$WV_PROFILE")
    echo "$(date +%s) docker run ${extra[*]} $*" >> "$WV_INJECT_LOG"
    if (( detached )); then
      cid="$("$WV_REAL_DOCKER" run "${extra[@]}" "$@")"; rc=$?
      [[ -n "$cid" ]] && { echo "cid $cid" >> "$WV_INJECT_LOG"; echo "$cid"; }
      exit $rc
    fi
    exec "$WV_REAL_DOCKER" run "${extra[@]}" "$@"
  fi
fi
exec "$WV_REAL_DOCKER" "$@"
EOF
chmod +x "$OUT/bin/docker"

{
  echo "date: $(date -Is)"
  echo "host: $(uname -a)"
  echo "docker: $("$REAL_DOCKER" version --format '{{.Server.Version}}')"
  echo "bpftrace: $(bpftrace --version 2>&1)"
  echo "official-images: $OI_COMMIT"
  echo "phases: $PHASES  cgroup_parent: $CG_PARENT"
} > "$OUT/meta.txt"
log "output: $OUT"

# ------------------------------------------------------------------ helpers
trace_start() {  # out_prefix
  # default map limit (4096 keys) is too small for a host-wide trace; a full map drops updates silently
  BPFTRACE_MAX_MAP_KEYS=262144 BPFTRACE_MAP_KEYS_MAX=262144 \
    bpftrace -B line -e "$BT_PROG" < /dev/null > "$1.bpftrace.out" 2> "$1.bpftrace.err" &
  TRACE_PID=$!
  local i
  for (( i = 0; i < 240; i++ )); do
    grep -q '^READY' "$1.bpftrace.out" 2>/dev/null && return 0
    kill -0 "$TRACE_PID" 2>/dev/null || { cat "$1.bpftrace.err" >&2; TRACE_PID=""; die "bpftrace failed to start"; }
    sleep 0.25
  done
  die "bpftrace did not attach within 60s"
}

trace_stop() {
  kill -INT "$TRACE_PID" 2>/dev/null
  wait "$TRACE_PID" 2>/dev/null
  TRACE_PID=""
}

run_test() {  # image test inject_mode profile('' = none) out_prefix -> prints status
  local image=$1 t=$2 mode=$3 profile=$4 pre=$5 tdir="$OI_DIR/test/tests/$2" rc status
  [[ -x "$tdir/run.sh" ]] || { echo missing-test; return; }
  : > "$pre.injected"
  WV_MODE="$mode" WV_PROFILE="$profile" WV_CGROUP_PARENT="$CG_PARENT" WV_INJECT_LOG="$pre.injected" \
    WV_REAL_DOCKER="$REAL_DOCKER" PATH="$OUT/bin:$PATH" \
    timeout "$TEST_TIMEOUT" "$tdir/run.sh" "$image" < /dev/null > "$pre.stdout" 2> "$pre.stderr"
  rc=$?
  # remove containers left behind (e.g. after a timeout)
  awk '$1 == "cid" { print $2 }' "$pre.injected" | xargs -r "$REAL_DOCKER" rm -f >/dev/null 2>&1
  if (( rc == 124 )); then status=timeout
  elif (( rc != 0 )); then status=fail
  elif [[ -f "$tdir/expected-std-out.txt" ]] && ! diff -q "$tdir/expected-std-out.txt" "$pre.stdout" >/dev/null; then
    status=fail-output
  else status=pass; fi
  grep -q 'docker run' "$pre.injected" || status="$status(container-not-found!)"
  echo "$status"
}

# ------------------------------------------------------------------ main loop
SUMMARY="$OUT/summary.tsv"
printf 'subject\ttest\tworkload_run\tenforce_run\tn_policy\tn_observed\tn_used\tn_missing\tn_unused\tpct_policy_used\tmissing\tinvalid_policy_names\n' > "$SUMMARY"
skip_row() { printf '%s\t%s\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\n' "$1" "$2" >> "$SUMMARY"; }

while read -r -u 3 subject image policy_rel mode tests _; do
  [[ -z "${subject:-}" || "$subject" == \#* ]] && continue
  if (( $# )) && [[ " $* " != *" $subject "* ]]; then continue; fi
  log "==================== $subject ($image)"

  policy="$policy_rel"; [[ "$policy" == /* ]] || policy="$ROOT/$policy"
  if [[ ! -f "$policy" ]] || ! jq -e '.defaultAction' "$policy" >/dev/null 2>&1; then
    log "SKIP $subject: policy missing or invalid: $policy"; skip_row "$subject" "SKIPPED(no policy)"; continue
  fi
  if ! "$REAL_DOCKER" image inspect "$image" >/dev/null 2>&1; then
    log "pulling $image"
    "$REAL_DOCKER" pull -q --platform linux/amd64 "$image" >/dev/null \
      || { log "SKIP $subject: cannot pull $image"; skip_row "$subject" "SKIPPED(no image)"; continue; }
  fi
  # SysJava per-source syscall files live under results/<subject_dir>/
  sources_dir="$(dirname "$(dirname "$(dirname "$policy")")")"

  sd="$OUT/$subject"; mkdir -p "$sd"
  cp "$policy" "$sd/policy.json"
  {
    echo "image: $image"
    echo "image_id: $("$REAL_DOCKER" image inspect -f '{{.Id}}' "$image")"
    echo "image_digest: $("$REAL_DOCKER" image inspect -f '{{join .RepoDigests " "}}' "$image")"
    echo "policy: $policy"
    echo "policy_sha256: $(sha256sum "$policy" | cut -d' ' -f1)"
    echo "sources_dir: $sources_dir"
    echo "inject: $mode  tests: $tests"
  } > "$sd/meta.txt"

  IFS=',' read -ra test_list <<< "$tests"
  for t in "${test_list[@]}"; do
    wl="-" en="-"
    rm -f "$sd/$t.workload.summary"

    if has_phase workload; then
      log "[$subject] $t: workload run (no policy, tracing)"
      trace_start "$sd/$t.workload"
      wl="$(run_test "$image" "$t" "$mode" "" "$sd/$t.workload")"
      trace_stop
      log "[$subject] $t: workload run -> $wl"
      if "$PY" "$WV" trace --bpftrace "$sd/$t.workload.bpftrace.out" --match "$CG_MATCH" \
           --out "$sd/$t.workload" >&2; then
        "$PY" "$WV" diff --observed "$sd/$t.workload.observed.tsv" --policy "$policy" \
          --sources-dir "$sources_dir" --runtime "$RUNTIME_LIST" --out "$sd/$t.workload" >&2
      fi
    fi

    if has_phase enforce; then
      log "[$subject] $t: enforce run (SysJava policy)"
      en="$(run_test "$image" "$t" "$mode" "$sd/policy.json" "$sd/$t.enforce")"
      log "[$subject] $t: enforce run -> $en"
    fi

    declare -A d=([n_policy]=- [n_observed]=- [n_used]=- [n_missing]=- [n_unused]=- [pct_policy_used]=- [missing]=- [invalid_policy_names]=-)
    if [[ -f "$sd/$t.workload.summary" ]]; then
      while IFS='=' read -r k v; do d[$k]="$v"; done < "$sd/$t.workload.summary"
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$subject" "$t" "$wl" "$en" \
      "${d[n_policy]}" "${d[n_observed]}" "${d[n_used]}" "${d[n_missing]}" "${d[n_unused]}" \
      "${d[pct_policy_used]}" "${d[missing]}" "${d[invalid_policy_names]}" >> "$SUMMARY"
    unset d
  done
done 3< "$CONF"

echo
column -t -s $'\t' "$SUMMARY"
echo
log "done. Per test: <subject>/<test>.workload.diff.tsv (every syscall: missing/used/unused,"
log "count, first process, SysJava source) and .by_source.tsv; logs in *.stdout/*.stderr"
