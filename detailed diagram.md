# Detailed Project Diagram (Services, Interactions, and Log Transit)

This document maps the full platform described by this repository, including setup orchestration, runtime service interactions, and telemetry/log paths into Elasticsearch/OpenSearch-compatible backends.

## 1) End-to-End Service Topology

```mermaid
flowchart TB
  %% ==============================
  %% HOST / ORCHESTRATION
  %% ==============================
  subgraph HOST["Host Machine (Ubuntu) - Single-node SOC deployment"]

    subgraph ORCH["Installer / Orchestration Layer"]
      SETUP["setup_script.sh\n- root/prereq checks\n- prompts install order\n- invokes component scripts"]
      SIEM_SCRIPT["siem_setup.sh"]
      SURI_SCRIPT["suricata_setup.sh"]
      WAZUH_SCRIPT["wazuh_setup.sh"]
      FALCO_SCRIPT["falco_setup.sh"]
      OTEL_SCRIPT["otel_setup.sh"]
      MB_SCRIPT["machine_metrics_setup.sh"]

      SETUP --> SIEM_SCRIPT
      SETUP --> SURI_SCRIPT
      SETUP --> WAZUH_SCRIPT
      SETUP --> FALCO_SCRIPT
      SETUP --> OTEL_SCRIPT
      SETUP --> MB_SCRIPT
    end

    subgraph SIEM["SIEM Core (systemd services)"]
      ES["Elasticsearch 7.17.13\nPort 9200/TLS\nIndex/Search backend"]
      KB["Kibana 7.17.13\nPort 5601/TLS\nVisualization/UI"]
      FB["Filebeat\nShipper + modules"]
      CERTS["Self-signed cert generation\nCA + node certs\nused by ES/Kibana/Filebeat"]

      CERTS --> ES
      CERTS --> KB
      CERTS --> FB
      KB <-->|"API + auth"| ES
      FB -->|"output.elasticsearch (TLS/auth)"| ES
    end

    subgraph NETSEC["Network Security Layer"]
      SURI["Suricata NIDS\nLocal interface capture\nEVE JSON output"]
      SURI_LOG["/var/log/suricata/eve.json"]
      SURI --> SURI_LOG
    end

    subgraph HOSTSEC["Host Security Layer"]
      WAZUH["Wazuh Manager 4.5.4\nPorts 1514/1515 TCP\nFIM/Vuln/Compliance/Active response"]
      AGENTS["Wazuh agents (external hosts)"]
      AGENTS -->|"register 1515 / events 1514"| WAZUH
    end

    subgraph RUNTIMESEC["Runtime Security Layer (Docker)"]
      FALCO["Falco container\nKernel/eBPF syscall detection\njson_output + http_output"]
      FSK["Falcosidekick container\nPort 2801\nEvent forwarder"]
      FALCO -->|"HTTP events"| FSK
      FSK -->|"ELASTICSEARCH_* env\nindex: falco-events"| ES
    end

    subgraph OBS["Observability Layer (Docker)"]
      OTEL["OpenTelemetry Collector\notel/opentelemetry-collector-contrib:0.91.0\nnetwork_mode: host"]
      APPS["OTLP clients/apps/services\n(any telemetry source)"]
      APPS -->|"OTLP gRPC :4317"| OTEL
      APPS -->|"OTLP HTTP :4318"| OTEL
      OTEL -->|"elasticsearch/logs exporter\nlogs_index=otel-logs"| ES
      OTEL -->|"elasticsearch/traces exporter\ntraces_index=otel-traces"| ES
      OTEL_H["Health :13133"]
      OTEL_M["Prometheus :8888/metrics"]
      OTEL_Z["zPages :55679"]
      OTEL --> OTEL_H
      OTEL --> OTEL_M
      OTEL --> OTEL_Z
    end

    subgraph METRICS["Infrastructure Metrics (systemd)"]
      MB["Metricbeat 7.17.13\nSystem module + optional Prometheus module"]
      MB -->|"metricbeat-*"| ES
      MB -->|"setup.kibana"| KB
      OTEL_M -->|"scraped by Metricbeat prometheus module"| MB
    end

    SURI_LOG -->|"Filebeat suricata module"| FB
    WAZUH -->|"Filebeat wazuh module\nalerts/archive streams"| FB

    USER["SOC analyst / operator"]
    USER -->|"HTTPS :5601"| KB
    USER -->|"API queries"| ES
  end

  %% ==============================
  %% OPTIONAL/SEPARATE AI STACK
  %% ==============================
  subgraph AI["Separate docker-compose stack (docker-compose.yml)"]
    OLLAMA["ollama container\nPort 11434"]
    DS["deepseek-setup init container\npulls deepseek-r1:14b"]
    WEBUI["open-webui container\nHost port 3000 -> container 8080"]

    DS --> OLLAMA
    WEBUI -->|"OLLAMA_BASE_URL"| OLLAMA
  end
```

## 2) Detailed Log/Telemetry Transit Paths

```mermaid
flowchart LR
  %% Suricata pipeline
  SURI_EVT["Suricata EVE events\n/var/log/suricata/eve.json"] --> FB_SURI["Filebeat suricata module\nmodules.d/suricata.yml"]
  FB_SURI --> ES_FILEBEAT["Elasticsearch index family\nfilebeat-*"]

  %% Wazuh pipeline
  WAZUH_ALERT["Wazuh manager alerts"] --> FB_WAZUH["Filebeat wazuh module\n+wazuh-template.json"]
  FB_WAZUH --> ES_WAZUH["Elasticsearch index family\nwazuh-alerts-*"]

  %% Falco pipeline
  FALCO_EVT["Falco syscall/rule events\njson_output + http_output"] --> FSK_IN["Falcosidekick :2801"]
  FSK_IN --> ES_FALCO["Elasticsearch index family\nfalco-events-*"]

  %% OTel pipeline
  OTLP_IN_G["OTLP gRPC :4317"] --> OTEL_PIPE["OTel pipelines\nreceivers: otlp\nprocessor: batch"]
  OTLP_IN_H["OTLP HTTP :4318"] --> OTEL_PIPE
  OTEL_PIPE --> ES_OTEL_LOGS["Elasticsearch index family\notel-logs-*"]
  OTEL_PIPE --> ES_OTEL_TRACES["Elasticsearch index family\notel-traces-*"]

  %% Metricbeat pipeline
  HOST_MET["Host metrics\nCPU/RAM/Disk/Network/Processes"] --> MB_SYS["Metricbeat system module"]
  OTEL_PROM["OTel /metrics :8888"] --> MB_PROM["Metricbeat prometheus module"]
  MB_SYS --> MB_OUT["Metricbeat output.elasticsearch"]
  MB_PROM --> MB_OUT
  MB_OUT --> ES_MB["Elasticsearch index family\nmetricbeat-*"]

  %% Search/visualization sink
  ES_FILEBEAT --> KIBANA["Kibana Discover/Dashboards"]
  ES_WAZUH --> KIBANA
  ES_FALCO --> KIBANA
  ES_OTEL_LOGS --> KIBANA
  ES_OTEL_TRACES --> KIBANA
  ES_MB --> KIBANA
```

## 3) Control-Plane and Credential/Config Dependency Flow

```mermaid
flowchart TD
  SIEM_CFG["siem_setup.sh creates /etc/filebeat/filebeat.yml\nwith output.elasticsearch hosts/user/password\nand setup.kibana host"]
  FALCO_PARSE["falco_setup.sh parses /etc/filebeat/filebeat.yml\n(if OPENSEARCH_* env not set)"]
  OTEL_PARSE["otel_setup.sh parses /etc/filebeat/filebeat.yml\n(if OPENSEARCH_* env not set)"]
  MB_PARSE["machine_metrics_setup.sh parses /etc/filebeat/filebeat.yml\nfor ES/Kibana endpoints + creds"]

  SIEM_CFG --> FALCO_PARSE
  SIEM_CFG --> OTEL_PARSE
  SIEM_CFG --> MB_PARSE

  ENV_OVERRIDE["Optional env override:\nOPENSEARCH_URL / OPENSEARCH_USERNAME / OPENSEARCH_PASSWORD"] --> FALCO_PARSE
  ENV_OVERRIDE --> OTEL_PARSE

  FALCO_PARSE --> FALCO_DEPLOY["/opt/falco/docker-compose.yml\nELASTICSEARCH_* env for Falcosidekick"]
  OTEL_PARSE --> OTEL_DEPLOY["/opt/otel/.env + otel-collector-config.yaml\nelasticsearch exporters"]
  MB_PARSE --> MB_CFG["/etc/metricbeat/metricbeat.yml\noutput.elasticsearch + setup.kibana"]
```

## 4) Installation/Startup Dependency Graph

```mermaid
flowchart LR
  A["1. SIEM setup\n(Elasticsearch + Kibana + Filebeat)"] --> B["2. Suricata setup\n(Filebeat suricata module)"]
  A --> C["3. Wazuh setup\n(Filebeat wazuh module + Kibana plugin)"]
  A --> D["4. Falco setup\n(needs backend creds)"]
  A --> E["5. OpenTelemetry setup\n(needs backend creds)"]
  A --> F["6. Metricbeat setup\n(reuses Filebeat backend config)"]
```

## 5) Port-Level Interaction Map

```mermaid
flowchart TB
  ES9200["Elasticsearch :9200 HTTPS"]
  KB5601["Kibana :5601 HTTPS"]
  W1514["Wazuh :1514 TCP"]
  W1515["Wazuh :1515 TCP"]
  F2801["Falcosidekick :2801 HTTP"]
  O4317["OTel OTLP gRPC :4317"]
  O4318["OTel OTLP HTTP :4318"]
  O13133["OTel Health :13133"]
  O8888["OTel Metrics :8888"]
  O55679["OTel zPages :55679"]
  OLLAMA11434["Ollama :11434"]
  WEBUI3000["Open-WebUI :3000 -> 8080"]

  Filebeat["Filebeat"] --> ES9200
  Kibana["Kibana server"] --> ES9200
  Analyst["Browser/Operator"] --> KB5601
  Agents["Wazuh agents"] --> W1515
  Agents --> W1514
  Falco["Falco"] --> F2801
  Falcosidekick["Falcosidekick"] --> ES9200
  OTLPClients["Telemetry clients"] --> O4317
  OTLPClients --> O4318
  Metricbeat["Metricbeat prometheus module"] --> O8888
  OTEL["OTel Collector"] --> O13133
  OTEL --> O55679
  OTEL --> ES9200
  WebUI["Open-WebUI"] --> OLLAMA11434
  UserAI["AI UI user"] --> WEBUI3000
```
