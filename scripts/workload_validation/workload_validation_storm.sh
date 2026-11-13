#!/usr/bin/env bash
#############################################################################
# workload_validation_storm.sh - the workload validation of
# workload_validation.sh for Storm, with a topology of Storm's own benchmark
# module (storm-perf) as the workload.
#
# A small cluster is started for each phase:
#   zookeeper    helper (the sidecar image SysJava's startup discovery used)
#   nimbus       the container under test: started as SysJava analyzed it
#                (`storm nimbus`), traced, and in the enforce phase run under
#                the SysJava policy
#   supervisor   helper, same image: runs the topology's workers
#   client       helper, same image: `storm jar` submits the topology, waits
#                while it runs and prints its metrics, then kills it
# Only nimbus is in the traced cgroup; the helpers are neither traced nor
# confined (as the clients of the other scripts).
#
#   workload  nimbus under an allow-all seccomp filter while bpftrace records
#             its syscalls, binaries and libraries; then the diffs against the
#             SysJava policy and against SysJava's startup discovery.
#   enforce   the same with nimbus under the SysJava policy.
#
# Results go to the same folder and in the same layout as
# workload_validation.sh (subject: storm, test: storm-perf), so report.py and
# table.py cover it.
#
#   sudo env "PATH=$PATH" scripts/workload_validation/workload_validation_storm.sh
#
# Environment (plus those of workload_validation.sh: PHASES, ARTIFACTS, OUT, ...):
#   TOPOLOGY=org.apache.storm.perf.ConstSpoutNullBoltTopo   storm-perf topology class
#   DURATION=180              seconds the topology runs
#   STORM_PERF_JAR=<file>     storm-perf jar (default: the 2.4.0 release from
#                             Maven Central, downloaded once to .cache/storm-perf/)
#   ZK_IMAGE=zookeeper:3.7    ZooKeeper helper image
#   READY_TIMEOUT=300         seconds to wait for ZooKeeper and for nimbus
#   SUPERVISOR_WAIT=30        seconds given to the supervisor to register
#   KEEP_FAILED=1             keep the cluster of a failed run (for debugging)
#
# Requires: as workload_validation.sh, plus network access for the first run
# (ZooKeeper image, storm-perf jar).
#############################################################################
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF="${CONF:-$HERE/storm_subject.conf}"
source "$HERE/wv_lib.sh"   # configuration, preflight, tracing, prepare_subject, postprocess
source "$CONF"             # SUBJECT, IMAGE, POLICY

TOPOLOGY="${TOPOLOGY:-org.apache.storm.perf.ConstSpoutNullBoltTopo}"
DURATION="${DURATION:-180}"
ZK_IMAGE="${ZK_IMAGE:-zookeeper:3.7}"
READY_TIMEOUT="${READY_TIMEOUT:-300}"
SUPERVISOR_WAIT="${SUPERVISOR_WAIT:-30}"
PERF_VERSION=2.4.0
PERF_URL="https://repo1.maven.org/maven2/org/apache/storm/storm-perf/$PERF_VERSION/storm-perf-$PERF_VERSION.jar"
PERF_SHA1=169ed8b2893c49e9c9d4177db240001e5340b21c   # storm-perf-2.4.0.jar.sha1 on Maven Central
STORM_PERF_JAR="${STORM_PERF_JAR:-$ROOT/.cache/storm-perf/storm-perf-$PERF_VERSION.jar}"
TEST=storm-perf

NET=wv-storm-net
ZK=wv-storm-zookeeper
NIMBUS=wv-storm-nimbus
SUPERVISOR=wv-storm-supervisor
CLIENT=wv-storm-client

cluster_down() {
  "$REAL_DOCKER" rm -vf "$CLIENT" "$SUPERVISOR" "$NIMBUS" "$ZK" >/dev/null 2>&1
  "$REAL_DOCKER" network rm "$NET" >/dev/null 2>&1
}
KEEP=0
storm_cleanup() {
  (( KEEP )) || cluster_down
  wv_cleanup
}
trap storm_cleanup EXIT

# ------------------------------------------------------------------ benchmark jar
if [[ ! -f "$STORM_PERF_JAR" ]]; then
  log "downloading $PERF_URL"
  mkdir -p "$(dirname "$STORM_PERF_JAR")"
  "$PY" -c 'import sys,urllib.request; urllib.request.urlretrieve(sys.argv[1], sys.argv[2])' \
    "$PERF_URL" "$STORM_PERF_JAR.part" && mv "$STORM_PERF_JAR.part" "$STORM_PERF_JAR" \
    || die "cannot download the storm-perf jar (set STORM_PERF_JAR to a local copy)"
fi
JAR_SHA1="$(sha1sum "$STORM_PERF_JAR" | cut -d' ' -f1)"
if [[ "$STORM_PERF_JAR" == "$ROOT/.cache/storm-perf/storm-perf-$PERF_VERSION.jar" && "$JAR_SHA1" != "$PERF_SHA1" ]]; then
  die "checksum mismatch for $STORM_PERF_JAR (delete it to download again)"
fi
chmod 644 "$STORM_PERF_JAR"
"$REAL_DOCKER" image inspect "$ZK_IMAGE" >/dev/null 2>&1 \
  || "$REAL_DOCKER" pull -q "$ZK_IMAGE" >/dev/null || die "cannot pull $ZK_IMAGE"

RUN_META+="
storm-perf: $(basename "$STORM_PERF_JAR") sha1 $JAR_SHA1
topology: $TOPOLOGY  duration: ${DURATION}s  zookeeper: $ZK_IMAGE"
log "output: $OUT"

# ------------------------------------------------------------------ cluster
ip_of() {  # container -> its address on the cluster network
  "$REAL_DOCKER" inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$1" 2>/dev/null
}

wait_port() {  # container port -> 0 when the port accepts connections
  local c=$1 port=$2 ip deadline=$(( SECONDS + READY_TIMEOUT ))
  while (( SECONDS < deadline )); do
    [[ "$("$REAL_DOCKER" inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" == true ]] || return 1
    ip="$(ip_of "$c")"
    if [[ -n $ip ]] && "$PY" -c 'import socket,sys; socket.create_connection((sys.argv[1], int(sys.argv[2])), 3).close()' \
         "$ip" "$port" 2>/dev/null; then
      return 0
    fi
    sleep 2
  done
  return 1
}

# run_storm profile out_prefix -> prints the status
# Starts the cluster with nimbus under the profile, runs the topology, removes the cluster.
run_storm() {
  local profile=$1 pre=$2 status=pass rc
  : > "$pre.stdout"; : > "$pre.stderr"
  cluster_down
  "$REAL_DOCKER" network create "$NET" >/dev/null 2>> "$pre.stderr" || { echo "fail(network)"; return; }

  "$REAL_DOCKER" run -d --name "$ZK" --network "$NET" --network-alias zookeeper "$ZK_IMAGE" \
    >/dev/null 2>> "$pre.stderr"
  if ! wait_port "$ZK" 2181; then
    status="fail(zookeeper)"
  else
    # the container under test, started as in SysJava's startup discovery
    "$REAL_DOCKER" run -d --name "$NIMBUS" --cgroup-parent "$CG_PARENT" --security-opt "seccomp=$profile" \
      --network "$NET" --hostname nimbus --network-alias nimbus "$IMAGE" nimbus \
      2>> "$pre.stderr" | sed 's/^/cid /' > "$pre.injected"
    if ! wait_port "$NIMBUS" 6627; then
      status="fail(not-ready)"
    else
      "$REAL_DOCKER" run -d --name "$SUPERVISOR" --network "$NET" --hostname supervisor "$IMAGE" supervisor \
        >/dev/null 2>> "$pre.stderr"
      sleep "$SUPERVISOR_WAIT"
      if [[ "$("$REAL_DOCKER" inspect -f '{{.State.Running}}' "$SUPERVISOR" 2>/dev/null)" != true ]]; then
        status="fail(supervisor)"
      else
        echo "### storm jar /perf/$(basename "$STORM_PERF_JAR") $TOPOLOGY $DURATION" >> "$pre.stdout"
        timeout $(( DURATION + 600 )) "$REAL_DOCKER" run --rm --name "$CLIENT" --network "$NET" \
          -v "$STORM_PERF_JAR:/perf/$(basename "$STORM_PERF_JAR"):ro" "$IMAGE" \
          jar "/perf/$(basename "$STORM_PERF_JAR")" "$TOPOLOGY" "$DURATION" \
          < /dev/null >> "$pre.stdout" 2>> "$pre.stderr"
        rc=$?
        if (( rc == 124 )); then status=timeout
        elif (( rc != 0 )); then status="fail(client)"
        elif ! grep -a -q 'Finished submitting topology' "$pre.stdout" "$pre.stderr"; then
          status="fail(not-submitted)"
        # storm-perf prints one CSV line of metrics a minute:
        #   elapsed,workers,tasks,executors,transferred,transfer rate,...
        # the topology worked if at least one of them reports transferred messages
        # (the client's upload progress bar writes carriage returns and other
        # control characters into the same output: normalise before matching)
        elif ! tr '\r' '\n' < "$pre.stdout" | tr -d '\000' \
               | awk -F, '/^[[:space:]]*[0-9]+,[0-9]+,[0-9]+,[0-9]+,[0-9]+,/ && $5 > 0 { ok = 1 } END { exit !ok }'; then
          status="fail(no-throughput)"
        elif ! grep -a -q 'Killed Topology' "$pre.stdout" "$pre.stderr"; then
          status="fail(not-killed)"
        fi
      fi
    fi
  fi

  # logs are copied out, not read with `docker exec`, which would run a
  # process inside the traced container
  "$REAL_DOCKER" cp "$NIMBUS:/opt/storm/logs/nimbus.log" "$pre.server.log" >/dev/null 2>&1
  "$REAL_DOCKER" logs "$NIMBUS" > "$pre.nimbus.console.log" 2>&1
  "$REAL_DOCKER" cp "$SUPERVISOR:/opt/storm/logs/supervisor.log" "$pre.supervisor.log" >/dev/null 2>&1
  if [[ $status != pass && -n "${KEEP_FAILED:-}" ]]; then
    log "keeping the cluster of the failed run ($NIMBUS, $SUPERVISOR, $ZK on $NET)"
  else
    # removed without a graceful stop, as the official tests do (docker rm -f)
    cluster_down
  fi
  echo "$status"
}

# ------------------------------------------------------------------ main
log "==================== $SUBJECT ($IMAGE)"
if prepare_subject "$SUBJECT" "$IMAGE" "$POLICY" \
     "benchmark: storm-perf $TOPOLOGY ${DURATION}s; under test: nimbus (command: nimbus)"; then
  t=$TEST
  if has_phase workload; then
    rm -rf "$sd/$t.workload."*
    log "[$SUBJECT] $t: workload run (allow-all filter, tracing)"
    trace_start "$sd/$t.workload"
    wl="$(run_storm "$ALLOW_ALL_PROFILE" "$sd/$t.workload")"
    trace_stop
    # run_storm runs in a subshell: note here that it kept its cluster
    [[ $wl != pass && -n "${KEEP_FAILED:-}" ]] && KEEP=1
    echo "$wl" > "$sd/$t.workload.status"
    log "[$SUBJECT] $t: workload run -> $wl"
    postprocess "$sd/$t.workload"
  fi

  if has_phase enforce && (( ! KEEP )); then
    rm -rf "$sd/$t.enforce."*
    log "[$SUBJECT] $t: enforce run (SysJava policy)"
    en="$(run_storm "$sd/policy.json" "$sd/$t.enforce")"
    [[ $en != pass && -n "${KEEP_FAILED:-}" ]] && KEEP=1
    echo "$en" > "$sd/$t.enforce.status"
    log "[$SUBJECT] $t: enforce run -> $en"
  fi
fi

echo
"$PY" "$HERE/report.py" "$OUT"
