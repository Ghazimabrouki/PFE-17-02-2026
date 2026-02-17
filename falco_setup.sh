#!/bin/bash
# Falco Runtime Security Setup Script (OpenSearch/Elasticsearch compatible)
# Author: Ghazi Mabrouki (patched)
# Goal: Ensure Falco events are indexed and visible in OpenSearch/OpenSearch Dashboards.

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

log() { local color=$1; shift; echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${color}$*${NC}"; }
die() { log "${RED}" "Error: $*"; exit 1; }
ok()  { log "${GREEN}" "$*"; }

welcome_message() {
  echo -e "${YELLOW}#############################################${NC}"
  echo -e "${YELLOW}##   Falco Runtime Security Setup          ##${NC}"
  echo -e "${YELLOW}##   (patched for OpenSearch visibility)    ##${NC}"
  echo -e "${YELLOW}#############################################${NC}"
  echo ""
}

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "Missing command: $1"; }

check_docker() {
  require_cmd docker
  if ! command -v docker-compose >/dev/null 2>&1; then
    require_cmd docker
    die "docker-compose is missing. Install docker compose (plugin or legacy) then re-run."
  fi
  ok "Docker and Docker Compose are installed."
}

# Extract OpenSearch/Elasticsearch connection details.
# Priority:
#   1) Environment variables OPENSEARCH_URL / OPENSEARCH_USERNAME / OPENSEARCH_PASSWORD
#   2) Parse /etc/filebeat/filebeat.yml output.elasticsearch.hosts/username/password
extract_backend_credentials() {
  log "${YELLOW}" "Resolving OpenSearch/Elasticsearch credentials..."

  OS_URL="${OPENSEARCH_URL:-}"
  OS_USERNAME="${OPENSEARCH_USERNAME:-}"
  OS_PASSWORD="${OPENSEARCH_PASSWORD:-}"

  if [[ -n "${OS_URL}" && -n "${OS_PASSWORD}" ]]; then
    [[ -n "${OS_USERNAME}" ]] || OS_USERNAME="elastic"
    ok "Using OPENSEARCH_* environment variables."
    return 0
  fi

  [[ -f /etc/filebeat/filebeat.yml ]] || die "Filebeat config not found at /etc/filebeat/filebeat.yml (install SIEM first, or set OPENSEARCH_URL/OPENSEARCH_PASSWORD)."

  # hosts can be written as:
  #   hosts: ["https://10.0.0.1:9200"]
  #   hosts: ["10.0.0.1:9200"]
  #   hosts:
  #     - "https://10.0.0.1:9200"
  # We keep the first host.
  host_line=$(awk '
    $0 ~ /^[[:space:]]*output\.elasticsearch:/ {inout=1}
    inout && $0 ~ /^[[:space:]]*hosts:/ {print; exit}
  ' /etc/filebeat/filebeat.yml || true)

  if [[ -z "${host_line}" ]]; then
    # Try multiline hosts list
    host_line=$(awk '
      $0 ~ /^[[:space:]]*output\.elasticsearch:/ {inout=1}
      inout && $0 ~ /^[[:space:]]*hosts:/ {getline; print; exit}
    ' /etc/filebeat/filebeat.yml || true)
  fi

  first_host=$(echo "${host_line}" | sed -E 's/.*hosts:[[:space:]]*\[?//; s/\]//; s/,.*//; s/"//g; s/'\''//g; s/[[:space:]]//g')
  [[ -n "${first_host}" ]] || die "Could not parse output.elasticsearch.hosts from /etc/filebeat/filebeat.yml. Set OPENSEARCH_URL instead."

  if [[ "${first_host}" != http* ]]; then
    # Filebeat often uses https; keep https by default (works with Elastic Stack security)
    first_host="https://${first_host}"
  fi
  # Ensure port
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

  ok "Backend credentials extracted successfully."
  log "${GREEN}" "Backend URL: ${OS_URL}"
  log "${GREEN}" "Backend user: ${OS_USERNAME}"
}

backend_healthcheck() {
  log "${YELLOW}" "Checking backend connectivity..."
  require_cmd curl
  if ! curl -sS -k -u "${OS_USERNAME}:${OS_PASSWORD}" "${OS_URL}/" >/dev/null; then
    die "Cannot reach backend at ${OS_URL}. Check URL/credentials and network/firewall."
  fi
  ok "Backend reachable."
}

check_existing_falco() {
  if docker ps -a --format '{{.Names}}' | grep -qxE 'falco|falcosidekick'; then
    log "${YELLOW}" "Existing Falco containers found."
    read -r -p "Remove and reinstall Falco + Falcosidekick? (y/n): " remove_choice
    if [[ "${remove_choice}" == "y" ]]; then
      log "${YELLOW}" "Removing existing Falco containers..."
      docker-compose -f /opt/falco/docker-compose.yml down -v 2>/dev/null || true
      docker rm -f falco falcosidekick 2>/dev/null || true
      rm -rf /opt/falco
      ok "Existing Falco containers removed."
    else
      die "Aborted."
    fi
  fi
}

create_falco_config() {
  log "${YELLOW}" "Creating Falco configuration..."
  mkdir -p /opt/falco

  cat > /opt/falco/docker-compose.yml <<EOF
version: '3.8'

services:
  falco:
    image: ghaziiii/falco:custom
    container_name: falco
    privileged: true
    restart: unless-stopped
    command: >
      /usr/bin/falco
      -o "json_output=true"
      -o "json_include_output_property=true"
      -o "http_output.enabled=true"
      -o "http_output.url=http://falcosidekick:2801/"
    volumes:
      - /sys/kernel/tracing:/sys/kernel/tracing:ro
      - /proc:/host/proc:ro
      - /etc:/host/etc:ro
      - /var/run/docker.sock:/host/var/run/docker.sock:ro
    depends_on:
      - falcosidekick
    networks:
      - falco-net

  falcosidekick:
    image: falcosecurity/falcosidekick:latest
    container_name: falcosidekick
    restart: unless-stopped
    ports:
      - "2801:2801"
    environment:
      DEBUG: "false"
      # Falcosidekick uses ELASTICSEARCH_* but it works with OpenSearch as well.
      ELASTICSEARCH_HOSTPORT: "${OS_URL}"
      ELASTICSEARCH_INDEX: "falco-events"
      ELASTICSEARCH_USERNAME: "${OS_USERNAME}"
      ELASTICSEARCH_PASSWORD: "${OS_PASSWORD}"
      ELASTICSEARCH_CHECKCERT: "false"
      ELASTICSEARCH_FLUSHINTERVAL: "1s"
    networks:
      - falco-net

networks:
  falco-net:
    driver: bridge
EOF

  ok "Falco configuration written to /opt/falco/docker-compose.yml"
}

start_falco() {
  log "${YELLOW}" "Starting Falco containers..."
  cd /opt/falco
  docker-compose up -d
  ok "Falco containers started."

  sleep 6
  docker ps --format 'table {{.Names}}\t{{.Status}}' | grep -E 'falco|falcosidekick' || true
}

verify_integration() {
  log "${YELLOW}" "Verifying Falco → OpenSearch ingestion..."

  # Generate a test event by listing containers (Falco often triggers some rules quickly).
  # If you have no events, run: sudo cat /etc/shadow (will trigger) — but that’s risky; we avoid doing it automatically.
  sleep 10

  # Check index existence and doc count
  idx=$(curl -sS -k -u "${OS_USERNAME}:${OS_PASSWORD}" "${OS_URL}/_cat/indices/falco-events?v" || true)
  if echo "${idx}" | grep -q 'falco-events'; then
    ok "Index 'falco-events' exists."
  else
    log "${YELLOW}" "Index 'falco-events' not visible yet. Waiting a bit more..."
    sleep 15
    idx=$(curl -sS -k -u "${OS_USERNAME}:${OS_PASSWORD}" "${OS_URL}/_cat/indices/falco-events?v" || true)
    echo "${idx}" | grep -q 'falco-events' || log "${RED}" "Still not visible. Check: docker logs falcosidekick"
  fi

  ok "Useful checks:"
  echo "  - docker logs --tail=200 falco"
  echo "  - docker logs --tail=200 falcosidekick"
  echo "  - curl -k -u ${OS_USERNAME}:<PASSWORD> '${OS_URL}/falco-events/_search?size=3&sort=@timestamp:desc'"
}

main() {
  welcome_message
  check_docker
  extract_backend_credentials
  backend_healthcheck
  check_existing_falco
  create_falco_config
  start_falco
  verify_integration
  ok "Falco setup completed."
}

main "$@"
