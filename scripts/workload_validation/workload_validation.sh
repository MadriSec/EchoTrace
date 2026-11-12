#!/usr/bin/env bash
#############################################################################
# workload_validation.sh - compare SysJava seccomp policies against the
# syscalls containers actually make under a real workload (the
# docker-library/official-images smoke tests).
#
# For every subject in subjects.conf, sequentially, and every test:
#   workload  run the test under an allow-all seccomp filter while bpftrace counts
#             every syscall made by the container under test, then diff:
#               missing = observed - policy   (needed, not found by SysJava)
#               used    = observed & policy
#               unused  = policy - observed   (allowed, not exercised)
#             with each policy syscall attributed to its SysJava source.
#             In the same run a second bpftrace records the binaries executed and the
#             native libraries (and jars) opened by the container under test,
#             and these are diffed against SysJava's startup discovery:
#               new = seen under the workload, not at startup
#   enforce   run the same test under the SysJava policy: does it still pass?
#
# Run as root (bpftrace needs it), keeping your PATH for jq/python3:
#   sudo env "PATH=$PATH" scripts/workload_validation/workload_validation.sh            # all
#   sudo env "PATH=$PATH" scripts/workload_validation/workload_validation.sh cassandra  # some
#
# Environment:
#   PHASES=workload,enforce   phases to run
#   TEST_TIMEOUT=1200         per-test timeout (s)
#   ARTIFACTS=1               0 = do not record the binaries/libraries of the workload
#   OI_REF=<commit>           pin docker-library/official-images (recorded in meta.txt)
#   CONF=<file>               subjects file (default: subjects.conf next to this script)
#   SYSJAVA_ROOT=<dir>        SysJava artifact (default: ../SysJava, next to Prototype)
#   SYSJAVA_RESULTS=<dir>     SysJava policies (default: $SYSJAVA_ROOT/2_swat4j_vs_sysjava/sysjava_results)
#   OUT=<dir>                 output dir (default: workload_validation_runs/results)
#
# Output: one folder per subject under $OUT. Re-running a subject replaces only
# that subject's results (and only for the phases that ran). At the end,
# report.py prints the per-subject diff and writes $OUT/report.csv.
#
# Requires: x86_64 Linux, root, docker, bpftrace, jq, git, python3, timeout.
# The binaries/libraries diff needs a kernel with BTF and fentry (bpftrace >= 0.20).
#############################################################################
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
CONF="${CONF:-$HERE/subjects.conf}"
PHASES="${PHASES:-workload,enforce}"
TEST_TIMEOUT="${TEST_TIMEOUT:-1200}"
ARTIFACTS="${ARTIFACTS:-1}"
OI_DIR="${OI_DIR:-$ROOT/.cache/official-images}"
OI_REF="${OI_REF:-}"
OUT="${OUT:-$ROOT/workload_validation_runs/results}"
PY="${PYTHON:-python3}"
WV="$HERE/wv.py"
SYSJAVA_ROOT="${SYSJAVA_ROOT:-$(cd "$ROOT/.." && pwd)/SysJava}"
SYSJAVA_RESULTS="${SYSJAVA_RESULTS:-$SYSJAVA_ROOT/2_swat4j_vs_sysjava/sysjava_results}"
# container-runtime syscall lists SysJava adds to every policy (for source attribution)
RUNTIME_LISTS=()
for f in "$SYSJAVA_ROOT/2_swat4j_vs_sysjava/runc.txt" "$SYSJAVA_ROOT/2_swat4j_vs_sysjava/runc_host_1.3.4_additions.txt"; do
  [[ -f "$f" ]] && RUNTIME_LISTS+=("$f")
done
BUILD_IMAGES="$SYSJAVA_ROOT/docker_images/build_jdk8_images.sh"

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
[[ -d "$SYSJAVA_RESULTS" ]] || die "SysJava results not found: $SYSJAVA_RESULTS (set SYSJAVA_ROOT or SYSJAVA_RESULTS)"

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
# and the first process making each syscall once (cheap).
# Only syscalls made by tasks that already run under a seccomp filter
# (seccomp.mode == 2, SECCOMP_MODE_FILTER) are counted: exactly the syscalls a
# policy is checked against. This excludes runc's container setup, which runs
# before the filter is installed (as "runc:[2:INIT]" or "memfd:runc_cloned").
# The workload run therefore uses ALLOW_ALL_PROFILE, a filter that blocks nothing.
BT_PROG='
BEGIN { printf("READY\n"); }
tracepoint:raw_syscalls:sys_enter /curtask->seccomp.mode == 2/ {
  @n[cgroup, '"$ARG"'] = count();
  if (@cg[cgroup] == 0) { @cg[cgroup] = 1; printf("CG %llu %s\n", cgroup, cgroup_path(cgroup)); }
  if (@first[cgroup, '"$ARG"'] == 0) { @first[cgroup, '"$ARG"'] = 1; printf("FIRST %llu %d %s\n", cgroup, '"$ARG"', comm); }
}
END { clear(@cg); clear(@first); }'

# Binaries and libraries of the workload, for the diff against SysJava's startup
# discovery (which records execve and the opens of .so/.jar files with sysdig).
# A separate bpftrace, so that a failure here cannot affect the syscall trace.
# Same task filter as above (tasks running under a seccomp filter).
#   OPEN  every file opened, once per (cgroup, file, opened-for-exec), with its
#         path as the container sees it. flag 1 = opened to be executed
#         (__FMODE_EXEC: the program, a script's interpreter, the ELF loader).
#   EXEC  every successful exec, with the file name of the program that now
#         runs (for a script: its interpreter, as in startup discovery).
ART_PROG='
BEGIN { printf("READY\n"); }
fentry:security_file_open /curtask->seccomp.mode == 2/ {
  $x = (args.file->f_flags & 0x20) != 0;
  $dev = args.file->f_inode->i_sb->s_dev;
  $ino = args.file->f_inode->i_ino;
  if (@seen[cgroup, $dev, $ino, $x] == 0) {
    @seen[cgroup, $dev, $ino, $x] = 1;
    if (@cg[cgroup] == 0) { @cg[cgroup] = 1; printf("CG %llu %s\n", cgroup, cgroup_path(cgroup)); }
    printf("OPEN %llu %d %s\n", cgroup, $x, path(args.file->f_path));
  }
}
tracepoint:sched:sched_process_exec /curtask->seccomp.mode == 2/ {
  if (@cg[cgroup] == 0) { @cg[cgroup] = 1; printf("CG %llu %s\n", cgroup, cgroup_path(cgroup)); }
  printf("EXEC %llu %s\n", cgroup, str(curtask->mm->exe_file->f_path.dentry->d_name.name));
}
END { clear(@seen); clear(@cg); }'
ART_PID=""

mkdir -p "$OUT/bin"
# Allows every syscall. The single LOG rule only exists so that the runtime
# installs a real filter (an empty allow-all profile could be skipped); LOG
# never blocks, and kexec_load cannot succeed in a container anyway.
ALLOW_ALL_PROFILE="$OUT/allow_all.json"
echo '{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["kexec_load"],"action":"SCMP_ACT_LOG"}]}' \
  > "$ALLOW_ALL_PROFILE"
TRACE_PID=""
cleanup() {
  [[ -n $TRACE_PID ]] && kill -INT "$TRACE_PID" 2>/dev/null
  [[ -n $ART_PID ]] && kill -INT "$ART_PID" 2>/dev/null
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

RUN_META="date: $(date -Is)
host: $(uname -a)
docker: $("$REAL_DOCKER" version --format '{{.Server.Version}}')
bpftrace: $(bpftrace --version 2>&1)
official-images: $OI_COMMIT
phases: $PHASES  cgroup_parent: $CG_PARENT"
log "output: $OUT"

# ------------------------------------------------------------------ helpers
artifacts_start() {  # out_prefix; a failure here only loses the binaries/libraries diff
  ART_PID=""
  [[ "$ARTIFACTS" == 1 ]] || return 0
  BPFTRACE_MAX_MAP_KEYS=262144 BPFTRACE_MAP_KEYS_MAX=262144 BPFTRACE_MAX_STRLEN=200 \
    bpftrace -B line -e "$ART_PROG" < /dev/null > "$1.artifacts.out" 2> "$1.artifacts.err" &
  ART_PID=$!
  local i
  for (( i = 0; i < 240; i++ )); do
    grep -q '^READY' "$1.artifacts.out" 2>/dev/null && return 0
    kill -0 "$ART_PID" 2>/dev/null || break
    sleep 0.25
  done
  log "WARNING: the binaries/libraries capture failed to start; none recorded for this run:"
  cat "$1.artifacts.err" >&2
  kill -INT "$ART_PID" 2>/dev/null; ART_PID=""
  rm -f "$1.artifacts.out"
}

trace_start() {  # out_prefix
  # default map limit (4096 keys) is too small for a host-wide trace; a full map drops updates silently
  BPFTRACE_MAX_MAP_KEYS=262144 BPFTRACE_MAP_KEYS_MAX=262144 \
    bpftrace -B line -e "$BT_PROG" < /dev/null > "$1.bpftrace.out" 2> "$1.bpftrace.err" &
  TRACE_PID=$!
  local i
  for (( i = 0; i < 240; i++ )); do
    grep -q '^READY' "$1.bpftrace.out" 2>/dev/null && { artifacts_start "$1"; return 0; }
    kill -0 "$TRACE_PID" 2>/dev/null || { cat "$1.bpftrace.err" >&2; TRACE_PID=""; die "bpftrace failed to start"; }
    sleep 0.25
  done
  die "bpftrace did not attach within 60s"
}

trace_stop() {
  kill -INT "$TRACE_PID" 2>/dev/null
  wait "$TRACE_PID" 2>/dev/null
  TRACE_PID=""
  if [[ -n $ART_PID ]]; then
    kill -INT "$ART_PID" 2>/dev/null
    wait "$ART_PID" 2>/dev/null
    ART_PID=""
  fi
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
skip() {  # subject reason
  rm -rf "${OUT:?}/$1"; mkdir -p "$OUT/$1"; echo "$2" > "$OUT/$1/skipped.txt"
}

while read -r -u 3 subject image policy_rel mode tests _; do
  [[ -z "${subject:-}" || "$subject" == \#* ]] && continue
  if (( $# )) && [[ " $* " != *" $subject "* ]]; then continue; fi
  log "==================== $subject ($image)"

  policy="$policy_rel"; [[ "$policy" == /* ]] || policy="$SYSJAVA_RESULTS/$policy"
  if [[ ! -f "$policy" ]] || ! jq -e '.defaultAction' "$policy" >/dev/null 2>&1; then
    log "SKIP $subject: policy missing or invalid: $policy"; skip "$subject" "SKIPPED (no policy: $policy_rel)"; continue
  fi
  if ! "$REAL_DOCKER" image inspect "$image" >/dev/null 2>&1; then
    if [[ "$image" == *-jdk8-buster && -f "$BUILD_IMAGES" ]]; then
      # the JDK 8 images are not on Docker Hub; build them exactly as SysJava did
      log "building $image with $BUILD_IMAGES ${image%%:*} (log: $OUT/$subject.build.log)"
      mkdir -p "$OUT"
      bash "$BUILD_IMAGES" "${image%%:*}" > "$OUT/$subject.build.log" 2>&1 \
        || { log "SKIP $subject: build failed"; skip "$subject" "SKIPPED (image build failed, see $subject.build.log)"; continue; }
    else
      log "pulling $image"
      "$REAL_DOCKER" pull -q --platform linux/amd64 "$image" >/dev/null \
        || { log "SKIP $subject: cannot pull $image"; skip "$subject" "SKIPPED (cannot pull $image)"; continue; }
    fi
  fi
  # SysJava per-source syscall files live under results/<subject_dir>/ (any depth)
  # SysJava's per-source syscall files are under the subject's results folder
  if [[ "$policy_rel" == /* ]]; then sources_dir="$(dirname "$policy")"
  else sources_dir="$SYSJAVA_RESULTS/${policy_rel%%/*}"; fi

  sd="$OUT/$subject"; mkdir -p "$sd"; rm -f "$sd/skipped.txt"
  cp "$policy" "$sd/policy.json"
  {
    echo "image: $image"
    echo "image_id: $("$REAL_DOCKER" image inspect -f '{{.Id}}' "$image")"
    echo "image_digest: $("$REAL_DOCKER" image inspect -f '{{join .RepoDigests " "}}' "$image")"
    echo "policy: $policy"
    echo "policy_sha256: $(sha256sum "$policy" | cut -d' ' -f1)"
    echo "sources_dir: $sources_dir"
    [[ -f "$sources_dir/detector_commit.txt" ]] && echo "sysjava_$(cat "$sources_dir/detector_commit.txt")"
    echo "inject: $mode  tests: $tests"
    echo "$RUN_META"
  } > "$sd/meta.txt"

  IFS=',' read -ra test_list <<< "$tests"
  for t in "${test_list[@]}"; do
    if has_phase workload; then
      rm -f "$sd/$t.workload."*
      log "[$subject] $t: workload run (allow-all filter, tracing)"
      trace_start "$sd/$t.workload"
      wl="$(run_test "$image" "$t" "$mode" "$ALLOW_ALL_PROFILE" "$sd/$t.workload")"
      trace_stop
      echo "$wl" > "$sd/$t.workload.status"
      log "[$subject] $t: workload run -> $wl"
      if "$PY" "$WV" trace --bpftrace "$sd/$t.workload.bpftrace.out" --match "$CG_MATCH" \
           --out "$sd/$t.workload" >&2; then
        "$PY" "$WV" diff --observed "$sd/$t.workload.observed.tsv" --policy "$policy" \
          --sources-dir "$sources_dir" --runtime "${RUNTIME_LISTS[@]}" --out "$sd/$t.workload" >&2
      fi
      if [[ -f "$sd/$t.workload.artifacts.out" ]]; then
        "$PY" "$WV" artifacts --capture "$sd/$t.workload.artifacts.out" --match "$CG_MATCH" \
          --sources-dir "$sources_dir" --out "$sd/$t.workload" >&2
      fi
    fi

    if has_phase enforce; then
      rm -f "$sd/$t.enforce."*
      log "[$subject] $t: enforce run (SysJava policy)"
      en="$(run_test "$image" "$t" "$mode" "$sd/policy.json" "$sd/$t.enforce")"
      echo "$en" > "$sd/$t.enforce.status"
      log "[$subject] $t: enforce run -> $en"
    fi
  done
done 3< "$CONF"

echo
"$PY" "$HERE/report.py" "$OUT"
