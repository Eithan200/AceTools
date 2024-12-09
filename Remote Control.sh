#!/bin/bash

# ==========================
# Author - Eithan Saragosti
# ==========================
# DESC: This tool Connects and Executes commands on a Remote Server while making sure you are anonymous.
# ==========================
# Project: Remote Control
# ==========================
VERSION="1.0"
SCRIPT_DIR=$(dirname "$(realpath "$0")")
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
LOG_DIR=$SCRIPT_DIR/RC_Results/$TIMESTAMP
LOG_FILE="$LOG_DIR/remote_control.log"
CONFIG_FILE="$SCRIPT_DIR/.remote_control_config"

# ==========================
# Colors
# ==========================
RED="\033[0;31m"
GREEN="\033[0;32m"
CYAN="\033[0;36m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
BOLD="\033[1m"
RESET="\033[0m"

# ==========================
# Helper Functions
# ==========================
log_message() {
    local message="$1"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo -e "$timestamp - $message" >> "$LOG_FILE"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Error: This script must be run as root!${RESET}"
        exit 1
    fi
}

install_apps() {
    local apps=("sshpass" "nmap" "whois" "tor" "nipe" "torify")

    for app in "${apps[@]}"; do
        if ! command -v "$app" &>/dev/null; then
            echo -e "${CYAN}Installing $app...${RESET}"
            apt-get install -y "$app"
            log_message "$app installed."
        else
            echo -e "${GREEN}$app is already installed.${RESET}"
        fi
    done
}

start_tor() {
    # Start Tor service if not running
    echo -e "${CYAN}Starting Tor service...${RESET}"
    systemctl start tor
    systemctl enable tor
    sleep 5  # Wait for Tor to initialize
}

check_anonymity() {
    # Check if the network is anonymous using Tor
    echo -e "${CYAN}Checking network anonymity...${RESET}"

    # Check if Tor is running
    if ! pgrep -x "tor" > /dev/null; then
        echo -e "${RED}Error: Tor service is not running. Starting it now...${RESET}"
        start_tor
    fi

    # Use torify with curl to check the IP through Tor
    tor_ip=$(torify curl -s https://check.torproject.org/api/ip)

    # If Tor is working, the response will contain an IP address, otherwise, it's blocked
    if [[ "$tor_ip" == *"\"IsTor\":true"* ]]; then
        # Extract the IP address from the JSON response
        tor_ip=$(echo "$tor_ip" | grep -oP '"IP":"\K[^"]+')
        log_message "Network is anonymous. Your spoofed IP is: $tor_ip."
    else
        log_message "Error: Tor anonymity check failed."
        exit 1
    fi
}

get_remote_info() {
    # Get remote server details (Country, IP, Uptime, OS, and more)
    local remote_ip="$1"
    local timestamp
    timestamp=$(date +"%Y-%m-%d_%H-%M-%S")
    
    # Get the remote server IP, country, and uptime via SSH
    server_info=$(torify curl -s "https://geolocation-db.com/json/$remote_ip")
    server_ip=$(echo $server_info | grep -oP '"IPv4":"\K[^"]+')
    
    # Get the OS, Uptime
    os_info=$(sshpass -p "$SSH_PASSWORD" ssh -o StrictHostKeyChecking=no "$REMOTE_USER@$remote_ip" "uname -a")
    uptime=$(sshpass -p "$SSH_PASSWORD" ssh -o StrictHostKeyChecking=no "$REMOTE_USER@$remote_ip" "uptime -p")
    
    # Display remote info to the CLI
    echo -e "${CYAN}Remote Server Details:${RESET}"
    echo -e "${GREEN}IP: $1${RESET}"
    echo -e "${GREEN}OS Info: $os_info${RESET}"
    echo -e "${GREEN}Uptime: $uptime${RESET}"
    
    # Save output to log files with timestamps
    echo -e "IP: $server_ip\nOS Info: $os_info\nUptime: $uptime" > "$LOG_DIR/remote_info_$timestamp.txt"
    log_message "Fetched remote server details for $remote_ip."
}

scan_remote_ports() {
    # Scan for open ports on the remote server
    local remote_ip="$1"
    local timestamp
    timestamp=$(date +"%Y-%m-%d_%H-%M-%S")
    
    nmap -p- "$remote_ip" -oN "$LOG_DIR/nmap_scan_$timestamp.txt"
    log_message "Port scan completed for $remote_ip."
}

perform_whois() {
    # Perform Whois lookup on a given address
    local address="$1"
    local timestamp
    timestamp=$(date +"%Y-%m-%d_%H-%M-%S")
    
    whois "$address" > "$LOG_DIR/whois_$timestamp.txt"
    log_message "Whois lookup completed for $address."
}

# ==========================
# Main Script Logic
# ==========================
log_message "Remote Control script started."

# Ensure the log directory exists
mkdir -p "$LOG_DIR"

# 1. Install necessary applications if not already installed
install_apps

# 2. Check if the network is anonymous (using Tor)
check_anonymity

# 3. Allow the user to specify the remote server address
echo -e "${CYAN}Enter the remote server IP address to scan: ${RESET}"
read -r REMOTE_SERVER_IP

echo -e "${CYAN}Enter the SSH username for the remote server: ${RESET}"
read -r REMOTE_USER

echo -e "${CYAN}Enter the SSH password for the remote server: ${RESET}"
read -r -s SSH_PASSWORD

# 4. Connect and execute commands on the remote server via SSH
get_remote_info "$REMOTE_SERVER_IP"
perform_whois "$REMOTE_SERVER_IP"
scan_remote_ports "$REMOTE_SERVER_IP"

# 5. End the process and display a log message
log_message "Remote control process completed for $REMOTE_SERVER_IP."
