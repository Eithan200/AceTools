#!/bin/bash

# ==========================
# Author: Eithan Sargosti
# ==========================
# DESC: Automated HDD and Memory Analysis with Menu Interface.
# ==========================
# Project: Analyzer
# ==========================
VERSION="2.3"
SCRIPT_DIR=$(dirname "$(realpath "$0")")
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
OUTPUT_DIR=$SCRIPT_DIR/Analysis_results/$TIMESTAMP
EXTRACTED_DIR="$OUTPUT_DIR/extracted_files"
REPORT_FILE="$OUTPUT_DIR/report.txt"
LOG_FILE="analyzer.log"
TOOLS=("bulk_extractor" "binwalk" "foremost" "strings" "volatility3" "exiftool")
RED="\033[0;31m"
GREEN="\033[0;32m"
CYAN="\033[0;36m"
YELLOW="\033[0;33m"
BLUE="\033[0;34m"
MAGENTA="\033[0;35m"
WHITE="\033[1;37m"
RESET="\033[0m"
BOLD="\033[1m"
UNDERLINE="\033[4m"

# ==========================
# Functions
# ==========================
log_message() {
    local message="$1"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo -e "$timestamp - $message" >> "$LOG_FILE"
}

check_root() {
    # 1.1 Check if user is root
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}${BOLD}Error: This script must be run as root!${RESET}"
        exit 1
    fi
}

check_file() {
    local file="$1"
    # 1.2 Check if file exists
    if [ ! -f "$file" ]; then
        echo -e "${RED}${BOLD}Error: File '$file' does not exist!${RESET}"
        exit 1
    fi
}

install_tools() {
    # 1.3 Install required forensic tools if missing
    log_message "Checking and installing required tools."
    for tool in "${TOOLS[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            echo -e "${YELLOW}${BOLD}Tool '$tool' not found. Installing...${RESET}"
            log_message "Installing missing tool: $tool."
            if [ "$tool" == "volatility3" ]; then
                pip install volatility3
            else
                apt-get install -y "$tool" &>/dev/null
            fi
            echo -e "${GREEN}${BOLD}Tool '$tool' installed successfully!${RESET}"
        fi
    done
    echo -e "${CYAN}All required tools are installed. Let's start analyzing!${RESET}"
}

create_directories() {
    # 1.5 Create necessary directories for saving results
    mkdir -p "$OUTPUT_DIR" "$EXTRACTED_DIR"    
    log_message "Created directories: $OUTPUT_DIR, $EXTRACTED_DIR."
}

extract_data() {
    local file="$1"
    # 1.4 Automatically extract data using carvers
    log_message "Extracting data from file: $file."

    # Bulk Extractor (finds patterns like email addresses, URLs, credit card numbers, etc.)
    bulk_extractor -o "$EXTRACTED_DIR/bulk_extractor" "$file" &>/dev/null

    # Foremost (file carver, extracts common file types like images, pdfs, etc.)
    foremost -i "$file" -o "$EXTRACTED_DIR/foremost" &>/dev/null

    # Binwalk (extracts embedded files in firmware, compressed files, etc.)
    binwalk -e "$file" -C "$EXTRACTED_DIR/binwalk" &>/dev/null

    # Strings (extracts readable strings from the file)
    strings "$file" >"$EXTRACTED_DIR/strings_output.txt"

    # Exiftool (extracts metadata from image files)
    exiftool "$file" >"$EXTRACTED_DIR/exiftool_output.txt"

    log_message "Data extraction completed for $file."
}

analyze_memory() {
    local memory_dump="$1"
    # Check if the file can be analyzed with Volatility 3
    log_message "Checking if memory dump can be analyzed with Volatility 3."
    if [[ "$memory_dump" == *.mem || "$memory_dump" == *.dmp || "$memory_dump" == *.raw ]]; then
        echo -e "${CYAN}File identified as memory dump. Running Volatility 3 analysis...${RESET}"

        # Get memory profile automatically using Volatility 3
        profile=$(volatility3 -f "$memory_dump" -h | grep -i "profile" | head -n 1 | awk -F': ' '{print $2}')

        # 2.2 Display running processes
        echo -e "${CYAN}Running processes in memory dump:${RESET}"
        volatility3 -f "$memory_dump" windows.pslist.PsList >"$EXTRACTED_DIR/pslist.txt"

        # 2.3 Display network connections
        echo -e "${CYAN}Network connections in memory dump:${RESET}"
        volatility3 -f "$memory_dump" windows.netscan.NetScan >"$EXTRACTED_DIR/netscan.txt"

        # 2.4 Attempt to extract registry information
        echo -e "${CYAN}Registry information from memory dump:${RESET}"
        volatility3 -f "$memory_dump" windows.psscan.PsScan >"$EXTRACTED_DIR/registry.txt"

        echo -e "${CYAN}Memory analysis completed for '$memory_dump'. Results saved to '$EXTRACTED_DIR'.${RESET}"
        log_message "Memory analysis completed for $memory_dump."
    else        
        log_message "File $memory_dump is not a valid memory dump for Volatility analysis."
    fi
}


generate_report() {
    # 3.1 Display general statistics (time of analysis, number of found files, etc.)
    end_time=$(date +%s)
    duration=$((end_time - start_time))

    echo -e "${CYAN}${BOLD}Analysis Summary:${RESET}"
    echo -e "${CYAN}Time taken: $duration seconds"
    echo -e "${CYAN}Number of extracted files: $(ls "$EXTRACTED_DIR" | wc -l)"
    echo -e "${CYAN}${BOLD}Saving results to report...${RESET}"

    # 3.2 Save the results to a report
    echo "Analysis Report" >"$REPORT_FILE"
    echo "================" >>"$REPORT_FILE"
    echo "Time taken: $duration seconds" >>"$REPORT_FILE"
    echo "Extracted files: $(ls "$EXTRACTED_DIR" | wc -l)" >>"$REPORT_FILE"
    echo "Extracted files can be found in: $EXTRACTED_DIR" >>"$REPORT_FILE"

    # 3.3 Zip the extracted files and report file
    zip -r "$OUTPUT_DIR/results.zip" "$EXTRACTED_DIR" "$REPORT_FILE" &>/dev/null
    echo -e "${GREEN}${BOLD}Results saved in '$OUTPUT_DIR/results.zip'.${RESET}"
    log_message "Results zipped and saved to $OUTPUT_DIR/results.zip."
}

show_banner() {
    clear
    figlet -f slant "Ace Tools" | lolcat
    echo -e "${CYAN}${BOLD}Welcome to Ace Tools's Analyzer! v${VERSION}!${RESET}"
    echo -e "${CYAN}${BOLD}This script automates HDD and memory analysis.${RESET}"
    echo -e "${CYAN}${BOLD}Select an option to begin the analysis.${RESET}"
    log_message "Script started"
}

show_menu() {
    # Display the main menu with proper color formatting
    echo -e "${CYAN}${BOLD}Please select an option:${RESET}"
    echo -e "1. ${BLUE}Analyze a file${RESET}"
    echo -e "2. ${MAGENTA}Exit${RESET}"
    read -p "$(echo -e ${YELLOW}'Enter your choice (1-2): '${RESET})" choice

    case $choice in
        1)
            # Let the user select a file
            read -p "$(echo -e ${BLUE}'Please specify the full path of the file to analyze: '${RESET})" file_to_analyze
            check_file "$file_to_analyze"
            start_analysis "$file_to_analyze"
            ;;
        2)
            # Exit the script
            echo -e "${MAGENTA}${BOLD}Exiting...${RESET}"
            exit 0
            ;;
        *)
            # Invalid choice
            echo -e "${RED}${BOLD}Invalid choice, please try again.${RESET}"
            show_menu
            ;;
    esac
}




start_analysis() {
    local file="$1"
    # Install required tools
    install_tools
    create_directories

    # 1.4 Extract data from file
    extract_data "$file"

    # 2.1 Perform memory analysis if the file is a memory dump
    analyze_memory "$file"

    # 3.1 Display statistics and create a report
    generate_report
}

# ==========================
# Main Script Logic
# ==========================
show_banner
show_menu
