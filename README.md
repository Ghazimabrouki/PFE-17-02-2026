# Automated SOC Components Setup Script

## Overview

This script automates the setup of a comprehensive security monitoring environment, including a Security Information and Event Management (SIEM) system, Network-based Intrusion Detection System (NIDS), Host-based Intrusion Detection System (HIDS), Runtime Security (Falco), and Observability (OpenTelemetry) on a single machine. It streamlines the installation process, making it accessible to users with different levels of technical expertise.

**Author:** Ghazi Mabrouki

**Note:** This script is intended to install all the components on a single machine, meaning the same box will have the SIEM, NIDS, HIDS, Runtime Security, and Observability components.

## Components

The script facilitates the installation of the following SOC components:

1. **SIEM (Security Information and Event Management):** This component combines Elasticsearch, Kibana, and Filebeat to provide a powerful platform for monitoring and analyzing security events in your environment. The SIEM setup includes Elasticsearch, Kibana and Filebeat version 7.17.13 as it is the compatible version to integrate with Wazuh manager version 4.5

2. **NIDS (Network-based Intrusion Detection System):** Suricata, a high-performance NIDS, is configured to help protect your network from intrusions and suspicious activities.
   **Note:** Suricata will monitor the local interface of the machine where it is installed. To monitor the entire network traffic, it should receive traffic from a TAP device or a SPAN port.

3. **HIDS (Host-based Intrusion Detection System):** The script installs the Wazuh Manager, an open-source HIDS. It aids in monitoring, detecting, and responding to security threats on individual hosts. The setup includes the installation of Wazuh Manager version 4.5

4. **Runtime Security (Falco):** Falco provides real-time threat detection for containers and cloud-native environments. It monitors system calls and kernel events to detect anomalous behavior and security threats at runtime.

5. **Observability (OpenTelemetry):** OpenTelemetry collector gathers metrics, logs, and traces from your infrastructure, providing comprehensive observability into system performance and behavior.

## System Requirements

Before running the script, please ensure that your system meets the following requirements:

- Ubuntu OS (18.04, 20.04, 22.04 or later)
- Minimum 4GB of RAM (8GB recommended for all components)
- Minimum 30GB of free disk space
- Docker and Docker Compose (will be installed automatically if not present)

If your system doesn't meet these requirements, the script will issue a warning and allow you to proceed at your own risk.

## Usage

1. Clone this repository to your local machine:

   ```bash
   git clone https://github.com/Ghazimabrouki/PFE-17-02-2026/
   ```

2. Navigate to the repository's directory:
   ```bash
   cd PFE-17-02-2026
   ```

3. Make the setup_script.sh executable:
   ```bash
   chmod +x *.sh
   ```

4. Execute the setup_script.sh:
   ```bash
   sudo ./setup_script.sh
   ```

5. Follow the on-screen prompts to choose which components you want to install and continue with the setup.

## Post-Installation Steps

After successfully running the script, consider the following post-installation steps:

### Verify NIDS Logs
Check if logs are getting written to the /var/log/suricata/eve.json file. This is essential for monitoring network traffic. Also verify from Kibana if data is being displayed in Suricata Dashboard.

### Wazuh-Agent Installation
To complete the setup and ensure effective security monitoring, install Wazuh agents on Linux or Windows machines in your network. This allows you to ingest logs into the SIEM, enhancing your security monitoring capabilities.

### Verify Falco Events
Check Kibana for the `falco-events` index to see runtime security events being captured by Falco.

### Verify OpenTelemetry Metrics
Check Kibana for the `otel-metrics` index to see system metrics being collected by OpenTelemetry.

## Component Integration

All components are configured to send their data to the central Elasticsearch instance:

- **Suricata** → Filebeat → Elasticsearch
- **Wazuh** → Filebeat → Elasticsearch  
- **Falco** → Falcosidekick → Elasticsearch
- **OpenTelemetry** → Python Forwarder → Elasticsearch

Access all dashboards through Kibana at: `https://<your-server-ip>:5601`

## Warnings and Considerations

**Data Backup:** Before proceeding, it's advisable to backup your data, especially if you plan to run the script on a production system.

## Security Best Practices

After setting up the security components, consider following best practices for system hardening, firewall configurations, and securing sensitive data.

## Troubleshooting

If you encounter issues:

1. Check service status: `systemctl status <service-name>`
2. Review logs in `/var/log/` directory
3. Verify Docker containers: `docker ps -a`
4. Check Elasticsearch health: `curl -k -u elastic:<password> https://localhost:9200/_cluster/health`

## License

See LICENSE file for details.

## Author

**Ghazi Mabrouki**

For issues and contributions, please open an issue or pull request on the repository.


## OpenSearch note (patched)

Falco and OpenTelemetry scripts can send data to **OpenSearch** (or Elasticsearch-compatible endpoints).

You can override the backend target without touching Filebeat by exporting:

- `OPENSEARCH_URL` (example: `https://10.0.0.10:9200`)
- `OPENSEARCH_USERNAME`
- `OPENSEARCH_PASSWORD`

If you don’t set these, the scripts will try to parse `/etc/filebeat/filebeat.yml` (output.elasticsearch.*).
