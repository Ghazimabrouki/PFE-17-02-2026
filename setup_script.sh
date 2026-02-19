#!/bin/bash

# Automated SOC Components Setup Script
# Author: Ghazi Mabrouki

# Color codes for formatting
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Function to check if a command is available
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Function to check for root privileges
check_root_privileges() {
  if [[ $(id -u) -ne 0 ]]; then
    echo -e "${RED}Error: This script must be run with root privileges.${NC}"
    exit 1
  fi
}

# Function to check if prerequisites are installed
check_prerequisites() {
  local prerequisites=("git" "curl" "figlet" "lolcat")
  local missing_prerequisites=()

  for prerequisite in "${prerequisites[@]}"; do
    if ! command_exists "$prerequisite"; then
      missing_prerequisites+=("$prerequisite")
    fi
  done

  if [ ${#missing_prerequisites[@]} -eq 0 ]; then
    echo -e "${GREEN}All prerequisites are installed.${NC}"
  else
    echo -e "${RED}Prerequisites missing:${NC}"
    for prerequisite in "${missing_prerequisites[@]}"; do
      echo -e "  - $prerequisite"
    done
    echo -e "Installing missing prerequisites..."
    install_prerequisites
  fi
}

# Function to install prerequisites if missing
install_prerequisites() {
  local prerequisites=("lsb-release" "curl" "apt-transport-https" "zip" "unzip" "gnupg" "lolcat" "figlet")

  echo -e "${GREEN}Installing prerequisites...${NC}"
  apt-get update
  apt-get install -y "${prerequisites[@]}"
  echo -e "${GREEN}All prerequisites have been installed.${NC}"
}

# Function to check if lolcat is installed and install it if not
check_and_install_lolcat() {
  if ! command_exists "lolcat"; then
    echo -e "${RED}lolcat is not installed. Installing lolcat...${NC}"
    if command_exists "sudo"; then
      sudo gem install lolcat
      echo -e "${GREEN}lolcat has been installed.${NC}"
    else
      echo -e "${RED}sudo is not available. Please install lolcat manually.${NC}"
    fi
  fi
}

# Function to check and install Docker
check_and_install_docker() {
  if ! command_exists "docker"; then
    echo -e "${YELLOW}Docker is not installed. Installing Docker...${NC}"
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    systemctl enable docker
    systemctl start docker
    echo -e "${GREEN}Docker has been installed.${NC}"
    rm -f get-docker.sh
  else
    echo -e "${GREEN}Docker is already installed.${NC}"
  fi

  if ! command_exists "docker-compose"; then
    echo -e "${YELLOW}Docker Compose is not installed. Installing Docker Compose...${NC}"
    curl -L "https://github.com/docker/compose/releases/download/v2.24.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    echo -e "${GREEN}Docker Compose has been installed.${NC}"
  else
    echo -e "${GREEN}Docker Compose is already installed.${NC}"
  fi
}

# Function to display a welcome message with figlet and lolcat
welcome_message() {
  figlet "SOC Setup" | lolcat
  echo -e "${GREEN}Automated SOC Components Setup Script${NC}"
  echo -e "${GREEN}Author: Ghazi Mabrouki${NC}"
  echo ""
  echo -e "${GREEN}This script will help you set up a comprehensive security monitoring environment.${NC}"
  echo "It includes the following components:"
  echo "1. SIEM (Elasticsearch, Kibana, Filebeat)"
  echo "2. NIDS (Suricata)"
  echo "3. HIDS (Wazuh Manager)"
  echo "4. Runtime Security (Falco)"
  echo "5. Observability (OpenTelemetry)"
  echo "6. Machine Metrics (Metricbeat)"
  echo "7. Prometheus Metrics Pipeline (Prometheus + node_exporter + PromEL -> Elasticsearch)"
  echo ""
  echo "The SIEM will be installed with Elasticsearch version 7.17.13 and Wazuh version 4.5, as they were compatible during the script creation."
  echo "Falco and OpenTelemetry will run as Docker containers and send data to Elasticsearch."
  echo "Metricbeat will ship host (machine) metrics (CPU/RAM/Disk/Network/Processes) to Elasticsearch."
  echo "Prometheus pipeline is containerized and can run alongside existing agents (no deletion/disable by default)."
}

# Function to install SIEM and display a message with figlet and lolcat
install_siem() {
  check_and_install_lolcat
  figlet "Starting SIEM Setup" | lolcat
  chmod +x siem_setup.sh
  ./siem_setup.sh
  figlet "SIEM Setup Completed" | lolcat
  read -p "Press Enter to continue..."
}

# Function to install Suricata (NIDS) and display a message with figlet and lolcat
install_suricata() {
  check_and_install_lolcat
  figlet "Starting Suricata Setup" | lolcat
  chmod +x suricata_setup.sh
  ./suricata_setup.sh
  figlet "Suricata Setup Completed" | lolcat
  read -p "Press Enter to continue..."
}

# Function to install Wazuh (HIDS) and display a message with figlet and lolcat
install_wazuh() {
  check_and_install_lolcat
  figlet "Starting Wazuh Setup" | lolcat
  chmod +x wazuh_setup.sh
  ./wazuh_setup.sh
  figlet "Wazuh Setup Completed" | lolcat
  read -p "Press Enter to continue..."
}

# Function to install Falco and display a message with figlet and lolcat
install_falco() {
  check_and_install_lolcat
  check_and_install_docker
  figlet "Starting Falco Setup" | lolcat
  chmod +x falco_setup.sh
  ./falco_setup.sh
  figlet "Falco Setup Completed" | lolcat
  read -p "Press Enter to continue..."
}

# Function to install OpenTelemetry and display a message with figlet and lolcat
install_otel() {
  check_and_install_lolcat
  check_and_install_docker
  figlet "Starting OTel Setup" | lolcat
  chmod +x otel_setup.sh
  ./otel_setup.sh
  figlet "OTel Setup Completed" | lolcat
  read -p "Press Enter to continue..."
}

# Function to install Machine Metrics (Metricbeat) and display a message with figlet and lolcat
install_machine_metrics() {
  check_and_install_lolcat
  figlet "Starting Metricbeat Setup" | lolcat

  # Metricbeat setup relies on Filebeat config to discover ES/Kibana connection.
  if [[ ! -f /etc/filebeat/filebeat.yml ]]; then
    echo -e "${YELLOW}Skipping Metricbeat: /etc/filebeat/filebeat.yml not found.${NC}"
    echo -e "${YELLOW}Tip: Install SIEM/Filebeat first, then rerun Metricbeat setup.${NC}"
    read -p "Press Enter to continue..."
    return 0
  fi

  chmod +x machine_metrics_setup.sh
  ./machine_metrics_setup.sh
  figlet "Metricbeat Setup Completed" | lolcat
  read -p "Press Enter to continue..."
}

# Function to install Prometheus metrics pipeline (Prometheus + node_exporter + PromEL)
# NOTE: This does NOT disable/remove Metricbeat or OpenTelemetry (runs alongside by default).
install_prometheus_metrics() {
  check_and_install_lolcat
  check_and_install_docker
  figlet "Starting Prometheus" | lolcat

  # Prometheus setup relies on Filebeat config to discover ES/Kibana connection.
  if [[ ! -f /etc/filebeat/filebeat.yml ]]; then
    echo -e "${YELLOW}Skipping Prometheus pipeline: /etc/filebeat/filebeat.yml not found.${NC}"
    echo -e "${YELLOW}Tip: Install SIEM/Filebeat first, then rerun Prometheus setup.${NC}"
    read -p "Press Enter to continue..."
    return 0
  fi

  chmod +x prometheus_setup.sh
  # Preserve existing agents/services (requested)
  PRESERVE_EXISTING=true REPLACE_EXISTING=0 ./prometheus_setup.sh

  figlet "Prometheus Completed" | lolcat
  read -p "Press Enter to continue..."
}

# Function to check system requirements
check_system_requirements() {
  total_ram=$(free -m | awk '/^Mem:/{print $2}')
  available_disk_space=$(df -h / | awk 'NR==2{print "Available Disk Space: " $4}')

  echo "Checking Requirements" | lolcat
  echo "Total RAM: ${total_ram} MB" | lolcat
  echo "${available_disk_space}" | lolcat

  if [ "$total_ram" -lt 4096 ]; then
    echo "Warning: Not Enough RAM." | lolcat
    echo -e "${YELLOW}Recommended: 8GB RAM for all components${NC}"
    read -p "Do you want to continue with the installation? (y/n): " continue_choice
    if [ "$continue_choice" != "y" ]; then
      figlet "Setup Aborted" | lolcat
      exit 1
    fi
  fi
}

# Main function to start the setup process
main() {
  check_root_privileges
  check_prerequisites
  check_and_install_lolcat
  welcome_message
  check_system_requirements

  read -p "Do you want to proceed with the setup? (y/n): " choice

  if [ "$choice" != "y" ]; then
    figlet "Setup Aborted" | lolcat
    exit 1
  fi

  read -p "Do you want to install the SIEM (Elasticsearch, Kibana, Filebeat)? (y/n): " install_siem_choice
  if [ "$install_siem_choice" == "y" ]; then
    install_siem
  fi

  read -p "Do you want to install Suricata (NIDS)? (y/n): " install_suricata_choice
  if [ "$install_suricata_choice" == "y" ]; then
    install_suricata
  fi

  read -p "Do you want to install Wazuh (HIDS)? (y/n): " install_wazuh_choice
  if [ "$install_wazuh_choice" == "y" ]; then
    install_wazuh
  fi

  read -p "Do you want to install Falco (Runtime Security)? (y/n): " install_falco_choice
  if [ "$install_falco_choice" == "y" ]; then
    install_falco
  fi

  read -p "Do you want to install OpenTelemetry (Observability)? (y/n): " install_otel_choice
  if [ "$install_otel_choice" == "y" ]; then
    install_otel
  fi

  read -p "Do you want to install Machine Metrics (Metricbeat)? (y/n): " install_machine_metrics_choice
  if [ "$install_machine_metrics_choice" == "y" ]; then
    install_machine_metrics
  fi

  read -p "Do you want to install Prometheus Metrics Pipeline (Prometheus + node_exporter + PromEL)? (y/n): " install_prometheus_choice
  if [ "$install_prometheus_choice" == "y" ]; then
    install_prometheus_metrics
  fi

  figlet "All done!" | lolcat
  echo -e "${GREEN}============================================${NC}"
  echo -e "${GREEN}SOC Setup Complete!${NC}"
  echo -e "${GREEN}Author: Ghazi Mabrouki${NC}"
  echo -e "${GREEN}============================================${NC}"
  echo ""
  echo -e "${YELLOW}Access your dashboards at:${NC}"
  echo -e "Kibana: https://$(hostname -I | cut -d' ' -f1):5601"
  echo ""
  echo -e "${YELLOW}Check service status:${NC}"
  echo "systemctl status elasticsearch kibana filebeat"
  [ "$install_suricata_choice" == "y" ] && echo "systemctl status suricata"
  [ "$install_wazuh_choice" == "y" ] && echo "systemctl status wazuh-manager"
  [ "$install_falco_choice" == "y" ] && echo "docker ps | grep falco"
  [ "$install_otel_choice" == "y" ] && echo "docker ps | grep otel"
  [ "$install_machine_metrics_choice" == "y" ] && echo "systemctl status metricbeat"
  [ "${install_prometheus_choice:-n}" == "y" ] && echo "docker ps | egrep 'soc-(prometheus|node-exporter|promel)'"
}

# Execute the main function
main
