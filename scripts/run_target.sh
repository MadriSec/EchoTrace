#!/usr/bin/env bash
# Pull/build the EchoTrace target images and keep one idle, locked-down
# container per image so the extraction scripts can `docker exec` / `docker cp`
# into it without the container ever exiting or restarting.
#
# Usage:
#   ./run_targets.sh up        # pull/build + start all
#   ./run_targets.sh status    # show state / restart count
#   ./run_targets.sh down      # remove all et_* containers
set -uo pipefail

# Folder name (from Results/)  ->  image reference.
# Lines starting with "build:" are built from the repo's DockerFiles/.
TARGETS=(
  "cassandra_3.0.29=cassandra:3.0.29"
  "cassandra_5.0.6-bookworm=cassandra:5.0.6-bookworm"
  "elasticsearch_7.1.0=docker.elastic.co/elasticsearch/elasticsearch:7.1.0"
  "elasticsearch_7.5.2=docker.elastic.co/elasticsearch/elasticsearch:7.5.2"
  "groovy_4.0.0=groovy:4.0.0"
  "groovy_latest=groovy:latest"
  "jetty_9.4.51=jetty:9.4.51"
  "jetty_latest=jetty:latest"
  "jruby_9.4.2.0=jruby:9.4.2.0"
  "jruby_latest=jruby:latest"
  "orientdb_3.2.19=orientdb:3.2.19"
  "orientdb_latest=orientdb:latest"
  "solr_8.7.0=solr:8.7.0"
  "solr_slim=solr:slim"
  "storm_2.4.0=storm:2.4.0"
  "tomcat_7.0=tomcat:7.0"
  # Folder name is truncated in the screenshot - fix the tag to match yours:
  "tomcat_11.0.18-jdk25-temurin=tomcat:11.0.18-jdk25-temurin-noble"
  "zookeeper_3.4.14=zookeeper:3.4.14"
  # Locally built from EchoTrace/DockerFiles:
  "storm-2.4.0-temurin8_latest=build:Dockerfile.storm-2.4.0-temurin8"
  # "local_jruby_9.4.2.0-temurin8=build:<its Dockerfile>"
)

DOCKERFILES_DIR="${DOCKERFILES_DIR:-$HOME/Tutorial/EchoTrace/DockerFiles}"
PREFIX="et_"

ref_for() {  # resolves build: entries to a local tag, building if needed
  local name="$1" spec="$2"
  if [[ "$spec" == build:* ]]; then
    local df="${spec#build:}" tag="echotrace/${name,,}:local"
    if ! docker image inspect "$tag" >/dev/null 2>&1; then
      echo "  building $tag from $df" >&2
      docker build -q -t "$tag" -f "$DOCKERFILES_DIR/$df" "$DOCKERFILES_DIR" >&2 || return 1
    fi
    echo "$tag"
  else
    if ! docker image inspect "$spec" >/dev/null 2>&1; then
      echo "  pulling $spec" >&2
      docker pull -q --platform linux/amd64 "$spec" >&2 || return 1
    fi
    echo "$spec"
  fi
}

up() {
  local failed=()
  for t in "${TARGETS[@]}"; do
    local name="${t%%=*}" spec="${t#*=}" cname="${PREFIX}${t%%=*}"
    echo "== $name"
    local img
    if ! img=$(ref_for "$name" "$spec"); then
      echo "  !! could not get image for $spec"; failed+=("$name"); continue
    fi
    docker rm -f "$cname" >/dev/null 2>&1

    # Idle, sandboxed container:
    #  --entrypoint sleep    bypass the app's entrypoint/CMD (no service starts,
    #                        nothing can crash, so no exit and no restart loop)
    #  --init                tini as PID 1 so `docker stop` is instant
    #  --restart no          never respawn (respawns SIGKILL your docker exec -> 137)
    #  --network none        no network at all
    #  --cap-drop ALL, no-new-privileges, pids/memory/cpu limits
    #  --read-only + tmpfs   image filesystem is immutable; /tmp is writable
    #                        scratch for JrtDumper (raise size if dumps are big)
    if docker run -d --name "$cname" \
        --platform linux/amd64 \
        --entrypoint sleep --init --restart no \
        --network none \
        --cap-drop ALL --security-opt no-new-privileges \
        --pids-limit 512 --memory 4g --memory-swap 4g --cpus 2 \
        --read-only --tmpfs /tmp:rw,exec,size=4g \
        --label echotrace.target="$name" \
        "$img" 2147483647 >/dev/null; then
      echo "  started $cname ($img)"
    else
      echo "  !! failed to start $cname"; failed+=("$name")
    fi
  done
  sleep 3; status
  ((${#failed[@]})) && echo "FAILED: ${failed[*]}"
}

status() {
  docker ps -a --filter "name=^${PREFIX}" \
    --format '{{.Names}}\t{{.Status}}\t{{.Image}}' | sort | column -t -s $'\t'
  echo
  docker ps -a --filter "name=^${PREFIX}" -q | xargs -r docker inspect \
    -f '{{.Name}} running={{.State.Running}} restarts={{.RestartCount}}' \
    | grep -v 'running=true restarts=0' || echo "all running, 0 restarts"
}

down() {
  docker ps -a --filter "name=^${PREFIX}" -q | xargs -r docker rm -f
}

case "${1:-up}" in
  up) up ;; status) status ;; down) down ;;
  *) echo "usage: $0 up|status|down"; exit 1 ;;
esac
