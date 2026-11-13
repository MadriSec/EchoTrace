# wv_lib.sh - shared by workload_validation.sh (docker-library official tests)
# and workload_validation_ycsb.sh (YCSB). Sourced, not run. It holds everything
# that must be identical for the results to be comparable: the syscall trace,
# the binaries/libraries capture, the allow-all profile, the per-subject setup
# and the post-processing. The caller sets HERE (its own directory) first.

ROOT="$(cd "$HERE/../.." && pwd)"
PHASES="${PHASES:-workload,enforce}"
TEST_TIMEOUT="${TEST_TIMEOUT:-1200}"
ARTIFACTS="${ARTIFACTS:-1}"
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
for t in docker jq timeout bpftrace "$PY" ${WV_EXTRA_TOOLS:-}; do
  command -v "$t" >/dev/null || die "missing tool: $t"
done
REAL_DOCKER="$(command -v docker)"
"$REAL_DOCKER" info >/dev/null 2>&1 || die "cannot reach the Docker daemon"
[[ -f "$CONF" ]] || die "subjects file not found: $CONF"
[[ -d "$SYSJAVA_RESULTS" ]] || die "SysJava results not found: $SYSJAVA_RESULTS (set SYSJAVA_ROOT or SYSJAVA_RESULTS)"

# Containers under test are placed in their own cgroup parent so the trace can
# tell them apart from clients (cqlsh, curl, YCSB, ...) and from everything else.
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

mkdir -p "$OUT"
# Allows every syscall. The single LOG rule only exists so that the runtime
# installs a real filter (an empty allow-all profile could be skipped); LOG
# never blocks, and kexec_load cannot succeed in a container anyway.
ALLOW_ALL_PROFILE="$OUT/allow_all.json"
echo '{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["kexec_load"],"action":"SCMP_ACT_LOG"}]}' \
  > "$ALLOW_ALL_PROFILE"
TRACE_PID=""
wv_cleanup() {
  [[ -n $TRACE_PID ]] && kill -INT "$TRACE_PID" 2>/dev/null
  [[ -n $ART_PID ]] && kill -INT "$ART_PID" 2>/dev/null
  # hand results (and the caches under .cache) back to the invoking user
  if [[ -n "${SUDO_UID:-}" ]]; then
    chown -R "$SUDO_UID:$SUDO_GID" "$OUT" 2>/dev/null
    [[ -d "$ROOT/.cache" ]] && chown -R "$SUDO_UID:$SUDO_GID" "$ROOT/.cache" 2>/dev/null
  fi
}
trap wv_cleanup EXIT

# Recorded in every subject's meta.txt; a driver may append its own lines.
RUN_META="date: $(date -Is)
host: $(uname -a)
docker: $("$REAL_DOCKER" version --format '{{.Server.Version}}')
bpftrace: $(bpftrace --version 2>&1)
phases: $PHASES  cgroup_parent: $CG_PARENT"

# ------------------------------------------------------------------ tracing
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

# ------------------------------------------------------------------ subjects
skip() {  # subject reason
  rm -rf "${OUT:?}/$1"; mkdir -p "$OUT/$1"; echo "$2" > "$OUT/$1/skipped.txt"
}

# prepare_subject subject image policy_rel extra_meta_line
# Checks the policy, makes sure the image exists (building the JDK 8 images),
# creates the subject's results folder and writes meta.txt.
# Sets: policy, sources_dir, sd. Returns non-zero if the subject was skipped.
prepare_subject() {
  local subject=$1 image=$2 policy_rel=$3 extra=$4
  policy="$policy_rel"; [[ "$policy" == /* ]] || policy="$SYSJAVA_RESULTS/$policy"
  if [[ ! -f "$policy" ]] || ! jq -e '.defaultAction' "$policy" >/dev/null 2>&1; then
    log "SKIP $subject: policy missing or invalid: $policy"; skip "$subject" "SKIPPED (no policy: $policy_rel)"; return 1
  fi
  if ! "$REAL_DOCKER" image inspect "$image" >/dev/null 2>&1; then
    if [[ "$image" == *-jdk8-buster && -f "$BUILD_IMAGES" ]]; then
      # the JDK 8 images are not on Docker Hub; build them exactly as SysJava did
      log "building $image with $BUILD_IMAGES ${image%%:*} (log: $OUT/$subject.build.log)"
      bash "$BUILD_IMAGES" "${image%%:*}" > "$OUT/$subject.build.log" 2>&1 \
        || { log "SKIP $subject: build failed"; skip "$subject" "SKIPPED (image build failed, see $subject.build.log)"; return 1; }
    else
      log "pulling $image"
      "$REAL_DOCKER" pull -q --platform linux/amd64 "$image" >/dev/null \
        || { log "SKIP $subject: cannot pull $image"; skip "$subject" "SKIPPED (cannot pull $image)"; return 1; }
    fi
  fi
  # SysJava's per-source syscall files and startup-discovery files are under the
  # subject's results folder
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
    echo "$extra"
    echo "$RUN_META"
  } > "$sd/meta.txt"
}

# postprocess prefix   (prefix = $sd/<test>.workload; uses policy and sources_dir)
# Turns the captures of a workload run into the observed syscalls, their diff
# against the policy, and the binaries/libraries diff against startup discovery.
postprocess() {
  local pre=$1
  if "$PY" "$WV" trace --bpftrace "$pre.bpftrace.out" --match "$CG_MATCH" --out "$pre" >&2; then
    "$PY" "$WV" diff --observed "$pre.observed.tsv" --policy "$policy" \
      --sources-dir "$sources_dir" --runtime "${RUNTIME_LISTS[@]}" --out "$pre" >&2
  fi
  if [[ -f "$pre.artifacts.out" ]]; then
    "$PY" "$WV" artifacts --capture "$pre.artifacts.out" --match "$CG_MATCH" \
      --sources-dir "$sources_dir" --out "$pre" >&2
  fi
}
