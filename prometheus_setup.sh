#!/usr/bin/env bash
set -euo pipefail

# Prometheus metrics pipeline for this project:
# node_exporter -> Prometheus -> PromEL (remote_write adapter) -> Elasticsearch
# Creates Kibana data view (index pattern): prometheus-metrics-*
#
# IMPORTANT:
# - This script is non-interactive.
# - By default it PRESERVES existing Metricbeat/OTel (no stop/disable/removal).
#   If you want to avoid duplicates, run with: PRESERVE_EXISTING=false
#   (legacy support: REPLACE_EXISTING=1 will also disable existing agents).

LOG_PREFIX="[prometheus-setup]"
log()  { echo -e "${LOG_PREFIX} $*"; }
warn() { echo -e "${LOG_PREFIX} [WARN] $*" >&2; }
die()  { echo -e "${LOG_PREFIX} [ERROR] $*" >&2; exit 1; }

need_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    die "Run as root (sudo)."
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

ensure_deps() {
  for c in curl git python3 docker ss; do
    have_cmd "$c" || die "$c is required. Install it first."
  done

  # docker compose plugin OR docker-compose legacy
  if docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
  elif have_cmd docker-compose; then
    COMPOSE=(docker-compose)
  else
    die "docker compose is required (either 'docker compose' plugin or 'docker-compose')."
  fi
}

pick_free_port() {
  local start="$1"
  local p
  for p in $(seq "$start" $((start+50))); do
    # If ss prints anything beyond header -> busy
    if ss -lnt "sport = :$p" | awk 'NR>1{exit 1}'; then
      echo "$p"
      return 0
    fi
  done
  return 1
}

strip_quotes() { sed -E 's/^"//; s/"$//' ; }

extract_first_host_from_yaml() {
  local f="$1"

  # inline: hosts: ["https://x:9200", "..."]
  local line
  line=$(grep -E '^[[:space:]]*hosts:[[:space:]]*\[' "$f" 2>/dev/null | head -n1 || true)
  if [[ -n "$line" ]]; then
    echo "$line" \
      | sed -E 's/.*\[(.*)\].*/\1/' \
      | tr ',' '\n' \
      | head -n1 \
      | sed -E "s/^[[:space:]]*//; s/[[:space:]]*$//" \
      | strip_quotes
    return 0
  fi

  # dash list:
  # hosts:
  #   - https://x:9200
  local in_hosts=0
  while IFS= read -r line; do
    if [[ "$line" =~ ^[[:space:]]*hosts:[[:space:]]*$ ]]; then
      in_hosts=1
      continue
    fi
    if [[ $in_hosts -eq 1 ]]; then
      if [[ ! "$line" =~ ^[[:space:]]*-[[:space:]]* ]]; then
        break
      fi
      echo "$line" | sed -E 's/^[[:space:]]*-[[:space:]]*//' | strip_quotes
      return 0
    fi
  done < "$f"

  return 1
}

autodiscover_from_filebeat() {
  local fb="/etc/filebeat/filebeat.yml"
  [[ -f "$fb" ]] || return 1

  if [[ -z "${ES_HOSTS:-}" ]]; then
    local h
    h=$(extract_first_host_from_yaml "$fb" || true)
    [[ -n "$h" ]] && ES_HOSTS="$h"
  fi

  if [[ -z "${ES_USER:-}" ]]; then
    ES_USER=$(grep -E '^[[:space:]]*username:' "$fb" 2>/dev/null | head -n1 | awk -F: '{print $2}' | xargs | strip_quotes || true)
  fi

  if [[ -z "${ES_PASS:-}" ]]; then
    ES_PASS=$(grep -E '^[[:space:]]*password:' "$fb" 2>/dev/null | head -n1 | awk -F: '{print $2}' | xargs | strip_quotes || true)
  fi

  if [[ -z "${ES_PROTO:-}" ]]; then
    ES_PROTO=$(grep -E '^[[:space:]]*protocol:' "$fb" 2>/dev/null | head -n1 | awk -F: '{print $2}' | xargs | strip_quotes || true)
  fi

  if [[ -z "${KIBANA_URL:-}" ]]; then
    # This project defaults to local Kibana
    KIBANA_URL="https://localhost:5601"
  fi

  return 0
}

normalize_url() {
  local host="$1"
  host="$(echo "$host" | xargs)"
  if [[ "$host" =~ ^https?:// ]]; then
    echo "$host"
    return 0
  fi
  local proto="${ES_PROTO:-https}"
  echo "${proto}://${host}"
}

find_es_ca_cert() {
  if [[ -n "${ES_CA_CERT:-}" && -f "${ES_CA_CERT:-}" ]]; then
    echo "$ES_CA_CERT"
    return 0
  fi
  for p in \
    /etc/elasticsearch/certs/http_ca.crt \
    /etc/elasticsearch/certs/ca/ca.crt \
    /usr/share/elasticsearch/config/certs/http_ca.crt \
    /usr/share/elasticsearch/config/certs/ca/ca.crt \
    /etc/ssl/certs/http_ca.crt
  do
    [[ -f "$p" ]] && { echo "$p"; return 0; }
  done
  return 1
}

disable_service_if_exists() {
  local svc="$1"
  if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$svc"; then
    log "Disabling service: $svc"
    systemctl stop "$svc" >/dev/null 2>&1 || true
    systemctl disable "$svc" >/dev/null 2>&1 || true
    systemctl reset-failed "$svc" >/dev/null 2>&1 || true
  fi
}

stop_container_if_exists() {
  local name="$1"
  if docker ps -a --format '{{.Names}}' | grep -qx "$name"; then
    log "Stopping/removing container: $name"
    docker rm -f "$name" >/dev/null 2>&1 || true
  fi
}

write_fixed_promel_dockerfile() {
  local src="$1"
  mkdir -p "$src/scripts"
  cat > "$src/scripts/Dockerfile.fixed" <<'DF'
FROM golang:1.22-bookworm AS builder
WORKDIR /src
COPY . .

ENV DEBIAN_FRONTEND=noninteractive
ENV GOFLAGS=-mod=mod

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates make binutils git \
    && rm -rf /var/lib/apt/lists/*

# PromEL repo often has incomplete go.sum; force regenerate + download
RUN go mod tidy && go mod download

# Build PromEL
RUN mkdir -p /out && \
    CGO_ENABLED=0 GOOS=linux go build -mod=mod -trimpath -ldflags "-s -w" -o /out/promel ./cmd

FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 9090/tcp 9091/tcp
COPY --from=builder /out/promel /usr/local/sbin/promel

ENTRYPOINT ["/usr/local/sbin/promel"]
CMD ["-config", "/etc/promel/promel.yml"]
DF
}

main() {
  need_root
  ensure_deps

  # Default: preserve existing Metricbeat/OTel (requested).
  # Legacy: REPLACE_EXISTING=1 means preserve=false.
  PRESERVE_EXISTING="${PRESERVE_EXISTING:-true}"
  if [[ "${REPLACE_EXISTING:-0}" == "1" ]]; then
    PRESERVE_EXISTING="false"
  fi

  ES_HOSTS="${ES_HOSTS:-${ES_HOST:-}}"
  ES_USER="${ES_USER:-elastic}"
  ES_PASS="${ES_PASS:-}"
  ES_PROTO="${ES_PROTO:-}"
  KIBANA_URL="${KIBANA_URL:-}"

  if [[ -z "$ES_HOSTS" || -z "$ES_PASS" || -z "$KIBANA_URL" ]]; then
    autodiscover_from_filebeat || true
  fi

  [[ -n "$ES_HOSTS" ]] || die "Elasticsearch host not found. Set ES_HOSTS (e.g. '10.0.0.10:9200' or 'https://10.0.0.10:9200')."
  [[ -n "$ES_PASS"  ]] || die "Elasticsearch password not found. Set ES_PASS (or ensure /etc/filebeat/filebeat.yml contains output.elasticsearch.password)."

  ES_URL=$(normalize_url "$ES_HOSTS")

  ES_URL_AUTH=$(ES_URL="$ES_URL" ES_USER="$ES_USER" ES_PASS="$ES_PASS" python3 - <<'PY'
import os, urllib.parse
u=os.environ['ES_URL']
user=os.environ['ES_USER']
pw=os.environ['ES_PASS']
p=urllib.parse.urlparse(u)
netloc=p.netloc
if '@' in netloc:
  print(u)
else:
  new=f"{urllib.parse.quote(user)}:{urllib.parse.quote(pw)}@{netloc}"
  print(urllib.parse.urlunparse(p._replace(netloc=new)))
PY
  )

  if [[ -z "$KIBANA_URL" ]]; then
    KIBANA_URL="https://localhost:5601"
  fi
  if [[ ! "$KIBANA_URL" =~ ^https?:// ]]; then
    KIBANA_URL="https://${KIBANA_URL}"
  fi

  ES_SSL=false
  [[ "$ES_URL" =~ ^https:// ]] && ES_SSL=true

  ES_CA=""
  if [[ "$ES_SSL" == "true" ]]; then
    ES_CA=$(find_es_ca_cert || true)
    [[ -n "$ES_CA" ]] || die "Elasticsearch is HTTPS but CA cert not found. Set ES_CA_CERT=/path/to/http_ca.crt (commonly /etc/elasticsearch/certs/http_ca.crt)."
  fi

  PROM_PORT="${PROM_PORT:-$(pick_free_port 9090 || true)}"
  NODE_EXPORTER_PORT="${NODE_EXPORTER_PORT:-$(pick_free_port 9100 || true)}"
  PROMEL_PORT="${PROMEL_PORT:-$(pick_free_port 9201 || true)}"
  PROMEL_METRICS_PORT="${PROMEL_METRICS_PORT:-$(pick_free_port 9202 || true)}"

  [[ -n "$PROM_PORT" ]] || die "Could not find a free port for Prometheus."
  [[ -n "$NODE_EXPORTER_PORT" ]] || die "Could not find a free port for node_exporter."
  [[ -n "$PROMEL_PORT" ]] || die "Could not find a free port for PromEL input."
  [[ -n "$PROMEL_METRICS_PORT" ]] || die "Could not find a free port for PromEL metrics."

  BASE_DIR="${BASE_DIR:-/opt/soc-prometheus}"
  mkdir -p "$BASE_DIR"

  log "Using directory: $BASE_DIR"
  log "Prometheus UI: http://localhost:${PROM_PORT}"
  log "node_exporter: http://localhost:${NODE_EXPORTER_PORT}/metrics"
  log "PromEL write endpoint: http://localhost:${PROMEL_PORT}/write"

  if [[ "$PRESERVE_EXISTING" != "true" ]]; then
    log "PRESERVE_EXISTING=false -> stopping/disabling existing Metricbeat/OTel to avoid duplicates"
    disable_service_if_exists metricbeat.service
    disable_service_if_exists otel-collector.service
    stop_container_if_exists otel-collector
    stop_container_if_exists otelcol
    stop_container_if_exists otel-collector-contrib
  else
    log "PRESERVE_EXISTING=true -> keeping existing Metricbeat/OTel (no stop/disable/removal)"
  fi

  # ---- Get PromEL ----
  if [[ ! -d "$BASE_DIR/promel-src" ]]; then
    log "Cloning PromEL..."
    git clone https://github.com/uzhinskiy/PromEL.git "$BASE_DIR/promel-src"
  else
    log "PromEL source already present."
  fi

  # Safe patch: store values as double
  if grep -Rni 'Properties.Value.Type = "long"' "$BASE_DIR/promel-src/modules/es/index.go" >/dev/null 2>&1; then
    sed -i 's/Properties\.Value\.Type = "long"/Properties.Value.Type = "double"/g' "$BASE_DIR/promel-src/modules/es/index.go" || true
  fi

  write_fixed_promel_dockerfile "$BASE_DIR/promel-src"

  log "Building PromEL Docker image (soc-promel:0.0.3) using scripts/Dockerfile.fixed ..."
  docker build --no-cache -t soc-promel:0.0.3 -f "$BASE_DIR/promel-src/scripts/Dockerfile.fixed" "$BASE_DIR/promel-src"

  # ---- Write configs ----
  cat > "$BASE_DIR/prometheus.yml" <<EOFY
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: prometheus
    static_configs:
      - targets: ['localhost:9090']

  - job_name: node
    static_configs:
      - targets: ['node-exporter:9100']

remote_write:
  - url: 'http://promel:9090/write'
    queue_config:
      max_samples_per_send: 1000
      capacity: 5000
      max_shards: 8
EOFY

  cat > "$BASE_DIR/promel.yml" <<EOFY
app:
  debug: false
metric:
  bind: 0.0.0.0
  port: 9091
input:
  bind: 0.0.0.0
  port: 9090
elastic:
  hosts:
    - "${ES_URL_AUTH}/"
  ssl: ${ES_SSL}
  certfile: /etc/promel/ca.crt
  index: "prometheus-metrics"
  replicas: 0
  shards: 1
  bulk:
    size: 1000
    flush: 5
    workers: 2
logging:
  enable: false
EOFY

  if [[ -n "$ES_CA" ]]; then
    cp -f "$ES_CA" "$BASE_DIR/ca.crt"
  else
    : > "$BASE_DIR/ca.crt"
  fi

  cat > "$BASE_DIR/docker-compose.yml" <<EOFY
services:
  promel:
    image: soc-promel:0.0.3
    container_name: soc-promel
    restart: unless-stopped
    volumes:
      - ./promel.yml:/etc/promel/promel.yml:ro
      - ./ca.crt:/etc/promel/ca.crt:ro
    ports:
      - "${PROMEL_PORT}:9090"
      - "${PROMEL_METRICS_PORT}:9091"

  node-exporter:
    image: prom/node-exporter:v1.10.2
    container_name: soc-node-exporter
    restart: unless-stopped
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    command:
      - --path.procfs=/host/proc
      - --path.sysfs=/host/sys
      - --path.rootfs=/rootfs
      - --collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)(\\$\\$|/)
    ports:
      - "${NODE_EXPORTER_PORT}:9100"

  prometheus:
    image: prom/prometheus:v3.9.1
    container_name: soc-prometheus
    restart: unless-stopped
    depends_on:
      - node-exporter
      - promel
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prom_data:/prometheus
    command:
      - --config.file=/etc/prometheus/prometheus.yml
      - --storage.tsdb.retention.time=24h
      - --storage.tsdb.path=/prometheus
    ports:
      - "${PROM_PORT}:9090"

volumes:
  prom_data:
EOFY

  log "Starting Prometheus stack (docker compose)..."
  (cd "$BASE_DIR" && "${COMPOSE[@]}" up -d)

  log "Waiting for Prometheus readiness..."
  for _ in {1..40}; do
    if curl -fsS "http://localhost:${PROM_PORT}/-/ready" >/dev/null 2>&1; then break; fi
    sleep 1
  done
  curl -fsS "http://localhost:${PROM_PORT}/-/ready" >/dev/null 2>&1 || die "Prometheus is not ready on port ${PROM_PORT}."

  log "Waiting for PromEL metrics endpoint..."
  for _ in {1..30}; do
    if curl -fsS "http://localhost:${PROMEL_METRICS_PORT}/metrics" >/dev/null 2>&1; then break; fi
    sleep 1
  done
  curl -fsS "http://localhost:${PROMEL_METRICS_PORT}/metrics" >/dev/null 2>&1 || die "PromEL metrics endpoint not reachable on ${PROMEL_METRICS_PORT}."

  log "Checking that Elasticsearch receives prometheus-metrics docs (may take ~30s)..."
  for _ in {1..15}; do
    if curl -sk -u "${ES_USER}:${ES_PASS}" "${ES_URL}/_cat/indices/prometheus-metrics*?h=index,docs.count" 2>/dev/null | grep -q 'prometheus-metrics'; then
      break
    fi
    sleep 2
  done

  if ! curl -sk -u "${ES_USER}:${ES_PASS}" "${ES_URL}/_cat/indices/prometheus-metrics*?h=index,docs.count" 2>/dev/null | grep -q 'prometheus-metrics'; then
    warn "No prometheus-metrics index found yet. Check PromEL logs: docker logs soc-promel --tail=200"
  else
    curl -sk -u "${ES_USER}:${ES_PASS}" "${ES_URL}/_cat/indices/prometheus-metrics*?h=index,docs.count" || true
  fi

  log "Ensuring Kibana data view exists: prometheus-metrics-* (time field: datetime)"
  k() { curl -sk -u "${ES_USER}:${ES_PASS}" -H 'kbn-xsrf: true' -H 'Content-Type: application/json' "$@"; }
  kget() { curl -sk -u "${ES_USER}:${ES_PASS}" -H 'kbn-xsrf: true' "$@"; }

  existing_id=$(kget --get "${KIBANA_URL}/api/saved_objects/_find" \
    --data-urlencode "type=index-pattern" \
    --data-urlencode "search_fields=title" \
    --data-urlencode "search=prometheus-metrics-*" \
    --data-urlencode "per_page=100" \
    | python3 - <<'PY'
import sys, json
try:
  data=json.load(sys.stdin)
  for so in data.get('saved_objects', []):
    if so.get('attributes', {}).get('title') == 'prometheus-metrics-*':
      print(so.get('id',''))
      break
except Exception:
  pass
PY
  )

  if [[ -z "$existing_id" ]]; then
    k "${KIBANA_URL}/api/saved_objects/index-pattern/prometheus-metrics" \
      -X POST \
      -d '{"attributes":{"title":"prometheus-metrics-*","timeFieldName":"datetime"}}' >/dev/null || true
  fi

  log "DONE."
  log "Containers:" 
  log "  docker ps | egrep 'soc-(prometheus|node-exporter|promel)'"
  log "Prometheus UI: http://localhost:${PROM_PORT}"
}

main "$@"
