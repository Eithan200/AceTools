#!/bin/bash

# ==========================
# Author: Eithan Sargosti
# ==========================
# DESC: Network vulnerability scanner performs a scan, checks for weak credentials, and provides vulnerability analysis using Searchsploit.
# ==========================
# Project: Vulner
# ==========================

# Set up color codes
GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
MAGENTA='\033[1;35m'
NC='\033[0m' # No color

# ==========================
# Helper Functions
# ==========================

# Display the welcome banner
show_banner() {
    clear
    figlet -f slant "Ace Tools" | lolcat
    echo -e " "
    echo -e "${CYAN}Welcome to Ace Tools Vulnerability Scanner!${NC}"
    echo -e "${YELLOW}Follow the instructions carefully.${NC}"
    echo -e " "
}

# Ensure the script is run as root
check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo -e " "
        echo -e "${RED}This script must be run as root.${NC}"
        echo -e " "
        echo -e "${MAGENTA}Exiting...${NC}"
        exit 1
    fi
}

# Install missing tools
install_tools() {
    local tools=(nmap hydra searchsploit xsltproc figlet lolcat zip grep)
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo -e "${YELLOW}Installing missing tool: ${tool}${NC}"
            apt-get install -y "$tool" &> /dev/null
            if ! command -v "$tool" &> /dev/null; then
                echo -e "${RED}Error: Could not install ${tool}. Please install it manually.${NC}"
                exit 1
            fi
        fi
    done
    echo -e "${GREEN}All required tools are installed.${NC}"
}

# Validate network input
validate_network() {
    if [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
        return 0
    else
        echo -e "${RED}Invalid network address format. Please enter a valid IP or CIDR.${NC}"
        return 1
    fi
}

# Function to perform weak credential checks
check_weak_passwords() {
    echo -e "${GREEN}Checking for weak passwords...${NC}"
    local password_list="$1"
    hydra -L "$usernames_list" -P "$password_list" ssh://"$network" -o "$output_dir/weak_passwords_ssh.txt"
    hydra -L "$usernames_list" -P "$password_list" ftp://"$network" -o "$output_dir/weak_passwords_ftp.txt"
    hydra -L "$usernames_list" -P "$password_list" rdp://"$network" -o "$output_dir/weak_passwords_rdp.txt"
    hydra -L "$usernames_list" -P "$password_list" telnet://"$network" -o "$output_dir/weak_passwords_telnet.txt"
}


# Perform vulnerability mapping
map_vulnerabilities() {
    local nmap_output="$1"
    echo -e "${GREEN}Mapping vulnerabilities with Searchsploit...${NC}"
    grep -oP "CVE-\d+-\d+" "$nmap_output" | sort -u | while read -r cve; do
        searchsploit "$cve" >> "$output_dir/vulnerability_results.txt"
    done
    echo -e "${CYAN}Vulnerability mapping completed.${NC}"
}

# Allow user to search results
search_results() {
    read -p "Do you want to search within the results? (Y/N): " search_choice
    search_choice=$(echo "$search_choice" | tr '[:lower:]' '[:upper:]')
    if [[ "$search_choice" == "Y" ]]; then
        read -p "Enter a search term: " search_term
        grep -i "$search_term" "$output_dir"/* | less
    fi
}

# Save results as a Zip file
save_results() {
    read -p "Do you want to save all results as a Zip file? (Y/N): " zip_choice
    zip_choice=$(echo "$zip_choice" | tr '[:lower:]' '[:upper:]')
    if [[ "$zip_choice" == "Y" ]]; then
        zip -r "$output_dir.zip" "$output_dir"
        echo -e "${GREEN}Results saved as: $output_dir.zip${NC}"
    fi
}

# ==========================
# Main Script
# ==========================

show_banner
check_root
install_tools

# Get user input for network
read -p "Enter the network to scan (e.g., 192.168.1.0/24): " network
while ! validate_network "$network"; do
    read -p "Enter a valid network to scan (e.g., 192.168.1.0/24): " network
done

# Get output directory
read -p "Enter a name for the output directory: " output_dir
while [[ -z "$output_dir" ]]; do
    echo -e "${RED}Output directory name cannot be empty.${NC}"
    read -p "Enter a name for the output directory: " output_dir
done
mkdir -p "$output_dir"

# Get scan type
while true; do
    read -p "Choose scan type - Basic (B) or Full (F): " scan_type
    scan_type=$(echo "$scan_type" | tr '[:lower:]' '[:upper:]')
    if [[ "$scan_type" == "B" || "$scan_type" == "F" ]]; then
        break
    else
        echo -e "${RED}Invalid input. Please enter 'B' for Basic or 'F' for Full.${NC}"
    fi
done

# Get password list
read -p "Do you want to use the built-in password list? (Y/N): " use_builtin_pass
use_builtin_pass=$(echo "$use_builtin_pass" | tr '[:lower:]' '[:upper:]')
if [[ "$use_builtin_pass" == "N" ]]; then
    read -p "Provide the path to your password list: " password_list
    while [[ ! -f "$password_list" ]]; do
        echo -e "${RED}File not found. Please provide a valid file path.${NC}"
        read -p "Provide the path to your password list: " password_list
    done
else
    password_list="/usr/share/wordlists/rockyou.txt"
    echo -e "${CYAN}Using default password list: $password_list${NC}"
fi

# Get usernames list
read -p "Do you want to use the built-in usernames list? (Y/N): " use_builtin_usr
use_builtin_usr=$(echo "$use_builtin_usr" | tr '[:lower:]' '[:upper:]')
if [[ "$use_builtin_usr" == "N" ]]; then
    read -p "Provide the path to your usernames list: " usernames_list
    while [[ ! -f "$usernames_list" ]]; do
        echo -e "${RED}File not found. Please provide a valid file path.${NC}"
        read -p "Provide the path to your usernames list: " usernames_list
    done
else
    usernames_list="/usr/share/wordlists/usernames.lst"
    echo -e "${CYAN}Using default usernames list: $usernames_list${NC}"
fi


# Perform the selected scan type
if [[ "$scan_type" == "B" ]]; then
    echo -e "${GREEN}Performing Basic Scan...${NC}"
    nmap -sS -sU -sV -oA "$output_dir/basic_scan" "$network"
    xsltproc "$output_dir/basic_scan.xml" -o "$output_dir/basic_scan.html"
    check_weak_passwords "$password_list"
elif [[ "$scan_type" == "F" ]]; then
    echo -e "${GREEN}Performing Full Scan...${NC}"
    nmap -sS -sU -sV --script vuln -oA "$output_dir/full_scan" "$network"
    xsltproc "$output_dir/full_scan.xml" -o "$output_dir/full_scan.html"
    check_weak_passwords "$password_list"
    echo -e "${CYAN}Mapping vulnerabilities with Searchsploit...${NC}"
    grep -oP "CVE-\d+-\d+" "$output_dir/full_scan.nmap" | sort -u | while read -r cve; do
        searchsploit "$cve" >> "$output_dir/vulnerability_results.txt"
    done
else
    echo -e "${RED}Invalid scan type selected. Exiting.${NC}"
    exit 1
fi

# Allow user to search and save results
search_results
save_results

figlet -f slant "Good Bye!" | lolcat
echo -e "${CYAN}Thank you for using Ace Tools Vulner!${NC}"

