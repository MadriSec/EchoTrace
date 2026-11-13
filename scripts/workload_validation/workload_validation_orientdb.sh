#!/usr/bin/env bash
#############################################################################
# workload_validation_orientdb.sh - the workload validation of
# workload_validation.sh for OrientDB, with OrientDB's own Stress Test Tool
# (stresstester, shipped in the image) as the workload.
#
# Two containers of the analyzed image are started for each phase:
#   server   the container under test: started as SysJava analyzed it, traced,
#            and in the enforce phase run under the SysJava policy
#   client   helper: runs the stress tester in remote mode against the server.
#            The tool creates a test database, runs a CRUD workload (creates,
#            reads, updates, deletes) and drops the database.
# Only the server is in the traced cgroup; the client is neither traced nor
# confined (as the clients of the other scripts).
#
#   workload  the server under an allow-all seccomp filter while bpftrace
#             records its syscalls, binaries and libraries; then the diffs
#             against the SysJava policy and against SysJava's startup discovery.
#   enforce   the same with the server under the SysJava policy.
#
# Results go to the same folder and in the same layout as
# workload_validation.sh (subject: orientdb, test: orientdb-stresstester), so
# report.py and table.py cover it.
#
#   sudo env "PATH=$PATH" scripts/workload_validation/workload_validation_orientdb.sh
#
# Environment (plus those of workload_validation.sh: PHASES, ARTIFACTS, OUT, ...):
#   OPS=25000                 operations of each kind (create, read, update, delete)
#   THREADS=4                 concurrent client threads
#   READY_TIMEOUT=300         seconds to wait for the server to start
#   RUN_TIMEOUT=1800          seconds allowed for the stress tester
#   KEEP_FAILED=1             keep the server container of a failed run (for debugging)
#
# Requires: as workload_validation.sh. Nothing is downloaded.
#############################################################################
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF="${CONF:-$HERE/orientdb_subject.conf}"
source "$HERE/wv_lib.sh"   # configuration, preflight, tracing, prepare_subject, postprocess
RUN_ARGS=()
source "$CONF"             # SUBJECT, IMAGE, POLICY, ROOT_PASSWORD, RUN_ARGS, READY_LOG, READY_PORT

OPS="${OPS:-25000}"
THREADS="${THREADS:-4}"
READY_TIMEOUT="${READY_TIMEOUT:-300}"
RUN_TIMEOUT="${RUN_TIMEOUT:-1800}"
TEST=orientdb-stresstester
WORKLOAD="crud:C${OPS}R${OPS}U${OPS}D${OPS}"
SERVER=wv-orientdb-server
CLIENT=wv-orientdb-client
# The tool's launcher if the image has it on the PATH, else its main class from
# the same jars (orientdb-tools-*.jar in /orientdb/lib).
STRESSTESTER='if command -v stresstester.sh >/dev/null 2>&1; then exec stresstester.sh "$@";
else exec java -cp "/orientdb/lib/*" com.orientechnologies.orient.stresstest.OStressTester "$@"; fi'

containers_down() { "$REAL_DOCKER" rm -vf "$CLIENT" "$SERVER" >/dev/null 2>&1; }
KEEP=0
orientdb_cleanup() {
  (( KEEP )) || containers_down
  wv_cleanup
}
trap orientdb_cleanup EXIT

RUN_META+="
stress tester: -m remote -c $THREADS -w $WORKLOAD"
log "output: $OUT"

# ------------------------------------------------------------------ server
wait_ready() {  # container marker port -> 0 when the marker is logged and the port accepts connections
  local c=$1 marker=$2 port=$3 ip deadline=$(( SECONDS + READY_TIMEOUT ))
  while (( SECONDS < deadline )); do
    [[ "$("$REAL_DOCKER" inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" == true ]] || return 1
    ip="$("$REAL_DOCKER" inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$c")"
    if "$REAL_DOCKER" logs "$c" 2>&1 | grep -a -q -F -- "$marker" \
       && "$PY" -c 'import socket,sys; socket.create_connection((sys.argv[1], int(sys.argv[2])), 3).close()' \
            "$ip" "$port" 2>/dev/null; then
      return 0
    fi
    sleep 2
  done
  return 1
}

# run_stress profile out_prefix -> prints the status
# Starts the server under the profile, runs the stress tester, removes both.
run_stress() {
  local profile=$1 pre=$2 status=pass rc ip
  : > "$pre.stdout"; : > "$pre.stderr"
  containers_down

  # the container under test, started as in SysJava's startup discovery
  "$REAL_DOCKER" run -d --name "$SERVER" --cgroup-parent "$CG_PARENT" --security-opt "seccomp=$profile" \
    "${RUN_ARGS[@]}" "$IMAGE" 2>> "$pre.stderr" | sed 's/^/cid /' > "$pre.injected"
  if ! wait_ready "$SERVER" "$READY_LOG" "$READY_PORT"; then
    status="fail(not-ready)"
  else
    ip="$("$REAL_DOCKER" inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$SERVER")"
    echo "### stresstester -m remote --remote-ip $ip --remote-port $READY_PORT -c $THREADS -w $WORKLOAD" >> "$pre.stdout"
    timeout "$RUN_TIMEOUT" "$REAL_DOCKER" run --rm --name "$CLIENT" "$IMAGE" \
      sh -c "$STRESSTESTER" stresstester \
      -m remote --remote-ip "$ip" --remote-port "$READY_PORT" --root-password "$ROOT_PASSWORD" \
      -c "$THREADS" -w "$WORKLOAD" \
      < /dev/null >> "$pre.stdout" 2>> "$pre.stderr"
    rc=$?
    if (( rc == 124 )); then status=timeout
    elif (( rc != 0 )); then status="fail(client)"
    elif ! grep -a -q 'Total execution time' "$pre.stdout" "$pre.stderr"; then
      status="fail(no-result)"
    elif grep -a -q -E 'Exception|Error on ' "$pre.stdout" "$pre.stderr"; then
      status="fail(errors)"
    fi
  fi

  "$REAL_DOCKER" logs "$SERVER" > "$pre.server.log" 2>&1
  if [[ $status != pass && -n "${KEEP_FAILED:-}" ]]; then
    log "keeping the server container of the failed run: $SERVER"
  else
    # removed without a graceful stop, as the official tests do (docker rm -f)
    containers_down
  fi
  echo "$status"
}

# ------------------------------------------------------------------ main
log "==================== $SUBJECT ($IMAGE)"
if prepare_subject "$SUBJECT" "$IMAGE" "$POLICY" \
     "benchmark: OrientDB Stress Test Tool, -m remote -c $THREADS -w $WORKLOAD; run args: ${RUN_ARGS[*]}"; then
  t=$TEST
  if has_phase workload; then
    rm -f "$sd/$t.workload."*
    log "[$SUBJECT] $t: workload run (allow-all filter, tracing)"
    trace_start "$sd/$t.workload"
    wl="$(run_stress "$ALLOW_ALL_PROFILE" "$sd/$t.workload")"
    trace_stop
    # run_stress runs in a subshell: note here that it kept its container
    [[ $wl != pass && -n "${KEEP_FAILED:-}" ]] && KEEP=1
    echo "$wl" > "$sd/$t.workload.status"
    log "[$SUBJECT] $t: workload run -> $wl"
    postprocess "$sd/$t.workload"
  fi

  if has_phase enforce && (( ! KEEP )); then
    rm -f "$sd/$t.enforce."*
    log "[$SUBJECT] $t: enforce run (SysJava policy)"
    en="$(run_stress "$sd/policy.json" "$sd/$t.enforce")"
    [[ $en != pass && -n "${KEEP_FAILED:-}" ]] && KEEP=1
    echo "$en" > "$sd/$t.enforce.status"
    log "[$SUBJECT] $t: enforce run -> $en"
  fi
fi

echo
"$PY" "$HERE/report.py" "$OUT"
