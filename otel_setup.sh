#!/bin/bash
# OpenTelemetry Collector Setup Script (OpenSearch/Elasticsearch compatible)
# Author: Ghazi Mabrouki (patched)
#
# Idempotent:
#   - Resolves backend URL/user/password from:
#       1) OPENSEARCH_URL / OPENSEARCH_USERNAME / OPENSEARCH_PASSWORD
#       2) ES_URL / ES_USER / ES_PASSWORD
#       3) /etc/filebeat/filebeat.yml (output.elasticsearch.*)
#   - Writes /opt/otel/.env, /opt/otel/docker-compose.yml, /opt/otel/otel-collector-config.yaml
#   - Restarts collector and verifies ports.
#   - Best-effort self-test (telemetrygen traces+logs) + index check.
#
# NOTE: otelcol-contrib:0.91.0 does NOT accept metrics_index, so we export logs+traces only.

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

log() { local color=$1; shift; echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${color}$*${NC}"; }
die() { log "${RED}" "Error: $*"; exit 1; }
ok()  { log "${GREEN}" "$*"; }
warn(){ log "${YELLOW}" "Warning: $*"; }

welcome_message() {
  echo -e "${YELLOW}#############################################${NC}"
  echo -e "${YELLOW}##   OpenTelemetry Setup (logs+traces)      ##${NC}"
  echo -e "${YELLOW}##   Direct export to OpenSearch/Elastic    ##${NC}"
  echo -e "${YELLOW}#############################################${NC}"
  echo ""
}

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "Missing command: $1"; }

compose() {
  if command -v docker-compose >/dev/null 2>&1; then
    docker-compose "$@"
  else
    docker compose "$@"
  fi
}

check_docker() {
  require_cmd docker
  if command -v docker-compose >/dev/null 2>&1; then
    ok "Docker and docker-compose are installed."
  elif docker compose version >/dev/null 2>&1; then
    ok "Docker and docker compose plugin are installed."
  else
    die "Docker Compose is missing. Install docker compose (plugin or legacy) then re-run."
  fi
}

OS_URL=""
OS_USERNAME=""
OS_PASSWORD=""

extract_backend_credentials() {
  log "${YELLOW}" "Resolving OpenSearch/Elasticsearch credentials..."

  OS_URL="${OPENSEARCH_URL:-${ES_URL:-}}"
  OS_USERNAME="${OPENSEARCH_USERNAME:-${ES_USER:-}}"
  OS_PASSWORD="${OPENSEARCH_PASSWORD:-${ES_PASSWORD:-}}"

  if [[ -n "${OS_URL}" && -n "${OS_PASSWORD}" ]]; then
    [[ -n "${OS_USERNAME}" ]] || OS_USERNAME="elastic"
    ok "Using environment variables for backend."
    log "${GREEN}" "Backend URL: ${OS_URL}"
    log "${GREEN}" "Backend user: ${OS_USERNAME}"
    return 0
  fi

  [[ -f /etc/filebeat/filebeat.yml ]] || die "No OPENSEARCH_* or ES_* vars provided, and /etc/filebeat/filebeat.yml not found."

  host_line=$(awk '
    $0 ~ /^[[:space:]]*output\.elasticsearch:/ {inout=1}
    inout && $0 ~ /^[[:space:]]*hosts:/ {print; exit}
  ' /etc/filebeat/filebeat.yml || true)

  if [[ -z "${host_line}" ]]; then
    host_line=$(awk '
      $0 ~ /^[[:space:]]*output\.elasticsearch:/ {inout=1}
      inout && $0 ~ /^[[:space:]]*hosts:/ {getline; print; exit}
    ' /etc/filebeat/filebeat.yml || true)
  fi

  first_host=$(echo "${host_line}" | sed -E 's/.*hosts:[[:space:]]*\[?//; s/\]//; s/,.*//; s/"//g; s/'\''//g; s/[[:space:]]//g')
  [[ -n "${first_host}" ]] || die "Could not parse output.elasticsearch.hosts from /etc/filebeat/filebeat.yml. Set OPENSEARCH_URL/OPENSEARCH_PASSWORD."

  if [[ "${first_host}" != http* ]]; then
    first_host="https://${first_host}"
  fi
  if ! echo "${first_host}" | grep -qE ':[0-9]{2,5}'; then
    first_host="${first_host}:9200"
  fi
  OS_URL="${first_host}"

  OS_PASSWORD=$(awk '
    $0 ~ /^[[:space:]]*output\.elasticsearch:/ {inout=1}
    inout && $0 ~ /^[[:space:]]*password:/ {gsub(/"/,"",$2); print $2; exit}
  ' /etc/filebeat/filebeat.yml || true)

  OS_USERNAME=$(awk '
    $0 ~ /^[[:space:]]*output\.elasticsearch:/ {inout=1}
    inout && $0 ~ /^[[:space:]]*username:/ {gsub(/"/,"",$2); print $2; exit}
  ' /etc/filebeat/filebeat.yml || true)

  [[ -n "${OS_PASSWORD}" ]] || die "Could not extract password from Filebeat config. Set OPENSEARCH_PASSWORD."
  [[ -n "${OS_USERNAME}" ]] || OS_USERNAME="elastic"

  ok "Backend credentials extracted successfully from Filebeat."
  log "${GREEN}" "Backend URL: ${OS_URL}"
  log "${GREEN}" "Backend user: ${OS_USERNAME}"
}

backend_healthcheck() {
  log "${YELLOW}" "Checking backend connectivity..."
  require_cmd curl
  curl -sS -k -u "${OS_USERNAME}:${OS_PASSWORD}" "${OS_URL}/" >/dev/null || die "Cannot reach backend at ${OS_URL} (check URL/creds/network)."
  ok "Backend reachable."
}

stop_existing_otel() {
  if docker ps -a --format '{{.Names}}' | grep -qx 'otel-collector'; then
    log "${YELLOW}" "Existing OpenTelemetry collector found. Restarting with updated configuration..."
    if [[ -f /opt/otel/docker-compose.yml ]]; then
      (cd /opt/otel && compose down) >/dev/null 2>&1 || true
    fi
    docker rm -f otel-collector >/dev/null 2>&1 || true
  fi
}

create_otel_config() {
  log "${YELLOW}" "Writing OpenTelemetry configuration under /opt/otel ..."
  mkdir -p /opt/otel

  cat > /opt/otel/.env <<EOF
ES_URL=${OS_URL}
ES_USER=${OS_USERNAME}
ES_PASSWORD=${OS_PASSWORD}
EOF
  chmod 600 /opt/otel/.env || true

  cat > /opt/otel/otel-collector-config.yaml <<'YAML'
extensions:
  health_check:
    endpoint: 0.0.0.0:13133

receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318

processors:
  batch: {}

exporters:
  elasticsearch/logs:
    endpoints: ["${ES_URL}"]
    user: "${ES_USER}"
    password: "${ES_PASSWORD}"
    tls:
      insecure_skip_verify: true
    logs_index: "otel-logs"

  elasticsearch/traces:
    endpoints: ["${ES_URL}"]
    user: "${ES_USER}"
    password: "${ES_PASSWORD}"
    tls:
      insecure_skip_verify: true
    traces_index: "otel-traces"

service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [elasticsearch/logs]
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [elasticsearch/traces]
YAML

  cat > /opt/otel/docker-compose.yml <<'YAML'
services:
  otel-collector:
    image: otel/opentelemetry-collector-contrib:0.91.0
    container_name: otel-collector
    network_mode: "host"
    command: ["--config=/etc/otel-collector-config.yaml"]
    env_file:
      - .env
    volumes:
      - ./otel-collector-config.yaml:/etc/otel-collector-config.yaml:ro
      - /proc:/hostfs/proc:ro
      - /sys:/hostfs/sys:ro
      - /:/rootfs:ro
    restart: unless-stopped
YAML

  ok "OpenTelemetry config updated (/opt/otel)."
}

start_otel() {
  log "${YELLOW}" "Starting OpenTelemetry collector..."
  cd /opt/otel
  # Clean restart (matches the manual fix steps)
  compose down >/dev/null 2>&1 || true
  compose up -d --force-recreate
  sleep 3

  state=$(docker inspect -f '{{.State.Status}}' otel-collector 2>/dev/null || echo "unknown")
  if [[ "${state}" != "running" ]]; then
    docker logs --tail=200 otel-collector || true
    die "otel-collector failed to start."
  fi

  # Quick visibility (matches the manual checks)
  docker logs --tail=80 otel-collector || true
  if command -v ss >/dev/null 2>&1; then
    ss -lntp | egrep ':4317|:4318|:13133' || true
  fi

  ok "OpenTelemetry collector started."
}

verify_runtime() {
  log "${YELLOW}" "Verifying collector ports (4317/4318/13133)..."
  if command -v ss >/dev/null 2>&1; then
    ss -lntp | egrep ':4317|:4318|:13133' || true
  else
    warn "ss not found; skipping socket check."
  fi

  log "${YELLOW}" "Verifying ES_* are present in container env..."
  docker inspect otel-collector --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | egrep '^ES_URL=|^ES_USER=|^ES_PASSWORD=' || true

  ok "Collector runtime checks done."
}

self_test_best_effort() {
  log "${YELLOW}" "Running OTLP self-test (telemetrygen traces+logs) - best effort..."
  if ! docker image inspect ghcr.io/open-telemetry/opentelemetry-collector-contrib/telemetrygen:latest >/dev/null 2>&1; then
    docker pull ghcr.io/open-telemetry/opentelemetry-collector-contrib/telemetrygen:latest >/dev/null 2>&1 || {
      warn "Could not pull telemetrygen image (network?). Skipping self-test."
      return 0
    }
  fi

  docker run --rm --network host ghcr.io/open-telemetry/opentelemetry-collector-contrib/telemetrygen:latest traces \
    --otlp-endpoint 127.0.0.1:4317 --otlp-insecure --rate 3 --duration 3s >/dev/null 2>&1 || {
      warn "telemetrygen traces failed. Skipping."
      return 0
    }

  docker run --rm --network host ghcr.io/open-telemetry/opentelemetry-collector-contrib/telemetrygen:latest logs \
    --otlp-endpoint 127.0.0.1:4317 --otlp-insecure --rate 3 --duration 3s >/dev/null 2>&1 || {
      warn "telemetrygen logs failed. Skipping."
      return 0
    }

  ok "Self-test sent traces/logs."
}

verify_backend_indices() {
  log "${YELLOW}" "Checking backend indices (otel-logs / otel-traces)..."
  require_cmd curl

  sleep 2
  curl -sS -k -u "${OS_USERNAME}:${OS_PASSWORD}" "${OS_URL}/_cat/indices?v" | egrep -i 'otel-logs|otel-traces' || true

  curl -sS -k -u "${OS_USERNAME}:${OS_PASSWORD}" "${OS_URL}/otel-logs/_count?pretty" || true
  curl -sS -k -u "${OS_USERNAME}:${OS_PASSWORD}" "${OS_URL}/otel-traces/_count?pretty" || true

  ok "Done."
}

main() {
  welcome_message
  check_docker
  extract_backend_credentials
  backend_healthcheck
  stop_existing_otel
  create_otel_config
  start_otel
  verify_runtime
  self_test_best_effort
  verify_backend_indices
  ok "OpenTelemetry setup completed."
}

main "$@"
