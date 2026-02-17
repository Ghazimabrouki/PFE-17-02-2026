#!/usr/bin/env bash
set -Eeuo pipefail

###############################################
# machine_metrics_setup.sh
# Goal: Send MACHINE metrics to Elasticsearch (easy way) using Metricbeat
#
# ✅ Reads ES + Kibana connection from /etc/filebeat/filebeat.yml
# ✅ Detects ES version (7.x / 8.x) and installs matching Metricbeat
# ✅ Fixes Elastic APT Signed-By conflicts automatically
# ✅ Enables Metricbeat "system" module (CPU/RAM/Disk/Network/Load/Process)
# ✅ Loads Kibana dashboards (best-effort)
# ✅ Starts & enables metricbeat service
#
# Usage:
#   sudo bash ./machine_metrics_setup.sh
#   sudo bash ./machine_metrics_setup.sh --clean
###############################################

SCRIPT_NAME="$(basename "$0")"
FILEBEAT_YML="/etc/filebeat/filebeat.yml"
MB_YML="/etc/metricbeat/metricbeat.yml"
MB_MODULES="/etc/metricbeat/modules.d"

CLEAN=0
VERBOSE=0

log()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
ok()   { log "OK: $*"; }
warn() { log "WARN: $*"; }
err()  { log "ERROR: $*" >&2; }

usage() {
  cat <<EOF
Usage:
  sudo bash ${SCRIPT_NAME} [--clean] [--verbose]

Options:
  --clean     Remove metricbeat + config
  --verbose   Extra debug output
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --clean) CLEAN=1; shift ;;
    --verbose) VERBOSE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) err "Unknown arg: $1"; usage; exit 1 ;;
  esac
done

need_cmd() { command -v "$1" >/dev/null 2>&1 || { err "Missing command: $1"; exit 1; }; }

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    err "Run as root: sudo bash ${SCRIPT_NAME}"
    exit 1
  fi
}

clean_all() {
  log "CLEAN enabled: removing metricbeat..."
  set +e
  systemctl disable --now metricbeat >/dev/null 2>&1 || true
  apt-get -y purge metricbeat >/dev/null 2>&1 || true
  rm -f /etc/apt/sources.list.d/elastic-7.x.list /etc/apt/sources.list.d/elastic-8.x.list >/dev/null 2>&1 || true
  rm -f /etc/apt/sources.list.d/elastic-beats.list >/dev/null 2>&1 || true
  apt-get update -y >/dev/null 2>&1 || true
  set -e
  ok "Metricbeat removed."
  exit 0
}

###############################################
# Parse filebeat.yml (safe + simple for our keys)
# Supports:
# output.elasticsearch:
#   hosts: ["10.1.2.3:9200"]
#   username: "elastic"
#   password: "xxx"
# setup.kibana:
#   host: "10.1.2.3:5601"
###############################################
parse_filebeat() {
  [[ -f "$FILEBEAT_YML" ]] || { err "Missing: $FILEBEAT_YML"; exit 1; }
  need_cmd python3

  python3 - "$FILEBEAT_YML" <<'PY'
import sys, re

p = sys.argv[1]
txt = open(p, 'r', encoding='utf-8', errors='ignore').read().splitlines()

def find_block(key):
    # find "key:" top-level
    for i, line in enumerate(txt):
        if re.match(r'^\s*%s\s*:\s*$' % re.escape(key), line):
            base = len(line) - len(line.lstrip())
            block = []
            for j in range(i+1, len(txt)):
                l = txt[j]
                if not l.strip(): 
                    continue
                ind = len(l) - len(l.lstrip())
                if ind <= base:
                    break
                block.append(l)
            return block
    return []

def get_scalar(block, k):
    for l in block:
        m = re.match(r'^\s*%s\s*:\s*(.+)\s*$' % re.escape(k), l)
        if m:
            v = m.group(1).strip().strip('"').strip("'")
            return v
    return None

def get_hosts(block):
    for l in block:
        m = re.match(r'^\s*hosts\s*:\s*(.+)\s*$', l)
        if m:
            rhs = m.group(1).strip()
            # hosts: ["a:9200"]
            if rhs.startswith('['):
                rhs = rhs.strip('[]')
                rhs = rhs.replace('"','').replace("'","")
                parts = [x.strip() for x in rhs.split(',') if x.strip()]
                return parts
            # hosts: "a:9200"
            rhs = rhs.strip('"').strip("'")
            return [rhs]
    return []

out = find_block("output.elasticsearch")
if not out:
    # Some configs use output: elasticsearch:
    out_top = find_block("output")
    if out_top:
        # find elasticsearch nested
        # crude but ok for our filebeat.yml style
        start = None
        for i,l in enumerate(out_top):
            if re.match(r'^\s*elasticsearch\s*:\s*$', l.strip()):
                start = i
                break
        if start is not None:
            base = len(out_top[start]) - len(out_top[start].lstrip())
            sub = []
            for j in range(start+1, len(out_top)):
                l2 = out_top[j]
                if not l2.strip(): 
                    continue
                ind = len(l2) - len(l2.lstrip())
                if ind <= base:
                    break
                sub.append(l2)
            out = sub

hosts = get_hosts(out)
user = get_scalar(out, "username")
pwd  = get_scalar(out, "password")

kib = find_block("setup.kibana")
kib_host = get_scalar(kib, "host")

# sanitize
if not hosts:
    print("PARSE_ERROR=1"); sys.exit(0)

print("PARSE_ERROR=0")
print("ES_HOSTS=" + ",".join(hosts))
if user: print("ES_USER=" + user)
if pwd:  print("ES_PASS=" + pwd)
if kib_host: print("KIBANA_HOST=" + kib_host)
PY
}

load_config() {
  local parsed
  parsed="$(parse_filebeat)"
  [[ "$VERBOSE" -eq 1 ]] && echo "$parsed"

  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    eval "$line"
  done <<<"$parsed"

  if [[ "${PARSE_ERROR:-1}" != "0" ]]; then
    err "Could not parse Elasticsearch connection from $FILEBEAT_YML"
    exit 1
  fi

  : "${ES_HOSTS:?missing ES hosts}"
  : "${ES_USER:?missing ES username}"
  : "${ES_PASS:?missing ES password}"

  ES_URL="https://$(echo "$ES_HOSTS" | cut -d',' -f1)"
  # If the host already contains scheme, keep it
  if [[ "$ES_URL" == https://https://* ]]; then ES_URL="${ES_URL#https://}"; fi
  if [[ "$(echo "$ES_HOSTS" | cut -d',' -f1)" == http://* || "$(echo "$ES_HOSTS" | cut -d',' -f1)" == https://* ]]; then
    ES_URL="$(echo "$ES_HOSTS" | cut -d',' -f1)"
  fi

  # Kibana host fallback if missing
  if [[ -z "${KIBANA_HOST:-}" ]]; then
    # common default: same host as ES but 5601
    local h
    h="$(echo "$ES_URL" | sed -E 's#https?://##' | cut -d: -f1)"
    KIBANA_HOST="https://${h}:5601"
  else
    # if Kibana host is without scheme, assume https
    if [[ "$KIBANA_HOST" != http://* && "$KIBANA_HOST" != https://* ]]; then
      KIBANA_HOST="https://${KIBANA_HOST}"
    fi
  fi

  ok "Elasticsearch URL: $ES_URL"
  ok "Elasticsearch user: $ES_USER"
  ok "Kibana host (from filebeat.yml): $KIBANA_HOST"
}

detect_ca() {
  # We will prefer the same CA used by your ES stack if present
  ES_CA=""
  for p in \
    /etc/elasticsearch/certs/ca/ca.crt \
    /etc/elasticsearch/certs/http_ca.crt \
    /usr/share/elasticsearch/config/certs/http_ca.crt \
    /etc/opensearch/certs/ca.pem \
    /etc/opensearch/certs/root-ca.pem
  do
    if [[ -f "$p" ]]; then ES_CA="$p"; break; fi
  done
  if [[ -n "$ES_CA" ]]; then
    ok "TLS CA detected: $ES_CA"
  else
    warn "No ES CA detected. Metricbeat will use 'ssl.verification_mode: none' (not recommended)."
  fi
}

curl_es() {
  local path="$1"
  local ca_opt=()
  if [[ -n "${ES_CA:-}" ]]; then
    ca_opt=(--cacert "$ES_CA")
  else
    ca_opt=(-k)
  fi
  curl -sS "${ca_opt[@]}" -u "${ES_USER}:${ES_PASS}" --connect-timeout 5 --max-time 15 "${ES_URL}${path}"
}

detect_es_version() {
  local v
  v="$(curl_es "/" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("version",{}).get("number",""))' 2>/dev/null || true)"
  if [[ -z "$v" ]]; then
    err "Cannot detect ES version (auth/TLS/network). Check ES_URL/creds."
    curl_es "/_cluster/health?pretty" || true
    exit 1
  fi
  ES_VERSION="$v"
  ES_MAJOR="${v%%.*}"
  ok "Detected Elasticsearch version: $ES_VERSION (major=$ES_MAJOR)"
}

###############################################
# Elastic APT repo: fix Signed-By conflicts
###############################################
fix_elastic_repo_conflicts() {
  # If multiple repo files point to same artifacts.elastic.co with different signed-by,
  # remove the "extra" one so apt doesn't error.
  local major="$1"
  local url="https://artifacts.elastic.co/packages/${major}.x/apt"

  local matches
  matches="$(grep -R --line-number "artifacts.elastic.co/packages/${major}.x/apt" /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null || true)"
  if [[ -z "$matches" ]]; then
    return 0
  fi

  # Keep the FIRST file; remove other duplicates for this same URL
  local keep_file
  keep_file="$(echo "$matches" | head -n1 | cut -d: -f1)"
  local dup_files
  dup_files="$(echo "$matches" | cut -d: -f1 | sort -u | grep -v "^${keep_file}$" || true)"

  if [[ -n "$dup_files" ]]; then
    warn "Found multiple Elastic APT repo entries for ${major}.x. Removing duplicates to avoid Signed-By conflict."
    while IFS= read -r f; do
      [[ -z "$f" ]] && continue
      warn "Removing duplicate repo file: $f"
      rm -f "$f" || true
    done <<<"$dup_files"
  fi
}

ensure_elastic_repo() {
  local major="$1"   # 7 or 8
  local repo_url="https://artifacts.elastic.co/packages/${major}.x/apt"

  fix_elastic_repo_conflicts "$major"

  # If repo already exists, reuse it
  if grep -R "artifacts.elastic.co/packages/${major}.x/apt" /etc/apt/sources.list /etc/apt/sources.list.d/*.list >/dev/null 2>&1; then
    ok "Elastic APT repo already present (reusing)."
    return 0
  fi

  need_cmd gpg
  need_cmd curl

  local keyring="/usr/share/keyrings/elasticsearch.gpg"
  local list_file="/etc/apt/sources.list.d/elastic-${major}.x.list"

  if [[ ! -f "$keyring" ]]; then
    curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o "$keyring"
    chmod 644 "$keyring"
  fi

  echo "deb [signed-by=${keyring}] ${repo_url} stable main" > "$list_file"
  ok "Elastic repo added: $list_file"
}

install_metricbeat() {
  ok "Installing Metricbeat (matching ES major ${ES_MAJOR}.x)..."
  export DEBIAN_FRONTEND=noninteractive

  ensure_elastic_repo "$ES_MAJOR"

  # update must not fail
  apt-get update -y

  # install
  apt-get install -y metricbeat
  ok "Metricbeat installed."
}

configure_metricbeat() {
  [[ -f "$MB_YML" ]] || { err "metricbeat.yml not found at $MB_YML"; exit 1; }

  # Backup once
  if [[ ! -f "${MB_YML}.bak" ]]; then
    cp -f "$MB_YML" "${MB_YML}.bak"
  fi

  # Write a clean, simple config (avoid YAML edits complexity)
  local ssl_block=""
  if [[ -n "${ES_CA:-}" ]]; then
    ssl_block=$(
      cat <<EOF
  ssl.certificate_authorities: ["${ES_CA}"]
EOF
    )
  else
    ssl_block=$(
      cat <<EOF
  ssl.verification_mode: "none"
EOF
    )
  fi

  cat > "$MB_YML" <<EOF
# Generated by ${SCRIPT_NAME}
# Sends MACHINE metrics -> Elasticsearch, dashboards -> Kibana

metricbeat.config.modules:
  path: ${MB_MODULES}/*.yml
  reload.enabled: false

setup.kibana:
  host: "${KIBANA_HOST}"
  username: "${ES_USER}"
  password: "${ES_PASS}"
$( [[ -n "${ES_CA:-}" ]] && echo "  ssl.certificate_authorities: [\"${ES_CA}\"]" || echo "  ssl.verification_mode: \"none\"" )

output.elasticsearch:
  hosts: ["${ES_URL}"]
  username: "${ES_USER}"
  password: "${ES_PASS}"
${ssl_block}

processors:
  - add_host_metadata: {}
  - add_cloud_metadata: {}
  - add_docker_metadata: {}
  - add_process_metadata: {}
EOF

  chmod 600 "$MB_YML"
  ok "Metricbeat configured: $MB_YML"
}

enable_system_module() {
  # This is what gives you real machine metrics in Kibana/ES
  metricbeat modules enable system >/dev/null 2>&1 || true

  # Make sure system module is ON with useful metricsets
  cat > "${MB_MODULES}/system.yml" <<'EOF'
- module: system
  period: 10s
  metricsets:
    - cpu
    - load
    - memory
    - network
    - process
    - process_summary
    - socket_summary
    - filesystem
    - fsstat
  processes: ['.*']
  process.include_top_n:
    by_cpu: 5
    by_memory: 5
EOF

  ok "Enabled Metricbeat system module (machine metrics)."
}

setup_dashboards_best_effort() {
  # dashboards are super useful; do best-effort without failing whole script
  log "Loading Kibana dashboards (best-effort)..."
  set +e
  metricbeat setup -e >/dev/null 2>&1
  local rc=$?
  set -e
  if [[ $rc -eq 0 ]]; then
    ok "Dashboards loaded."
  else
    warn "Dashboards setup failed (not fatal). You can retry: sudo metricbeat setup"
  fi
}

start_metricbeat() {
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable --now metricbeat

  # Wait a bit then validate logs
  sleep 2
  if ! systemctl is-active --quiet metricbeat; then
    err "metricbeat service is not running."
    systemctl status metricbeat --no-pager -l || true
    exit 1
  fi
  ok "metricbeat is running."
}

verify_data() {
  log "Verifying data arrives in Elasticsearch (metricbeat-* indices)..."

  # wait up to ~60s for index creation/docs
  local found=0
  for _ in {1..30}; do
    if curl_es "/_cat/indices/metricbeat-*?h=index,docs.count" 2>/dev/null | awk '{print $2}' | grep -Eq '^[1-9]'; then
      found=1
      break
    fi
    sleep 2
  done

  if [[ $found -eq 1 ]]; then
    ok "Metricbeat indices detected with docs ✅"
  else
    warn "No docs detected yet. Showing metricbeat logs (tail 120):"
    journalctl -u metricbeat --no-pager -n 120 || true
  fi

  log "Elasticsearch indices metricbeat-*:"
  curl_es "/_cat/indices/metricbeat-*?v" || true
}

main() {
  require_root
  need_cmd curl
  need_cmd python3
  need_cmd apt-get
  need_cmd systemctl

  if [[ "$CLEAN" -eq 1 ]]; then
    clean_all
  fi

  load_config
  detect_ca
  detect_es_version

  # We only support ES major 7 or 8 in this script
  if [[ "$ES_MAJOR" != "7" && "$ES_MAJOR" != "8" ]]; then
    err "Unsupported ES major version: $ES_MAJOR (expected 7 or 8)"
    exit 1
  fi

  install_metricbeat
  configure_metricbeat
  enable_system_module
  setup_dashboards_best_effort
  start_metricbeat
  verify_data

  ok "DONE. You can open Kibana and search for:"
  log "  Index pattern: metricbeat-*"
  log "  Discover: filter by event.module: system"
}

main
