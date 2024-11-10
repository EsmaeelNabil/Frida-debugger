#!/bin/bash

# Check if a package name is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <package_name>"
  exit 1
fi

PACKAGE_NAME=$1

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m' # No Color

# Function to fetch and format section with colors
fetch_and_format_section() {
  SECTION_NAME=$1
  COMMAND=$2
  FILTER=$3
  
  echo -e "${YELLOW}${SECTION_NAME}${NC}"
  adb shell $COMMAND $PACKAGE_NAME | grep "$FILTER" | while read -r line; do
    echo -e "  ${GREEN}${line}${NC}"
  done
  echo
}

# Create a temporary file to store the output
TEMP_FILE=$(mktemp)

# Fetch and format basic package information
echo -e "${BLUE}PACKAGE INFORMATION${NC}" >> $TEMP_FILE
adb shell dumpsys package $PACKAGE_NAME | while read -r line; do
  echo -e "  ${GREEN}${line}${NC}" >> $TEMP_FILE
done
echo >> $TEMP_FILE

# Fetch and format app permissions
fetch_and_format_section "PERMISSIONS" "pm dump" "permission" >> $TEMP_FILE

# Fetch and format app activities
fetch_and_format_section "ACTIVITIES" "dumpsys package" "Activity" >> $TEMP_FILE

# Fetch and format app services
fetch_and_format_section "SERVICES" "dumpsys package" "Service" >> $TEMP_FILE

# Fetch and format app receivers
fetch_and_format_section "RECEIVERS" "dumpsys package" "Receiver" >> $TEMP_FILE

# Fetch and format app providers
fetch_and_format_section "PROVIDERS" "dumpsys package" "Provider" >> $TEMP_FILE

# Fetch and format app version info
fetch_and_format_section "VERSION INFO" "dumpsys package" "version" >> $TEMP_FILE

# Fetch and format app metadata
fetch_and_format_section "METADATA" "dumpsys package" "meta-data" >> $TEMP_FILE

# Fetch and format app resources
echo -e "${YELLOW}RESOURCES${NC}" >> $TEMP_FILE
adb shell pm list packages -f | grep $PACKAGE_NAME | while read -r line; do
  echo -e "  ${GREEN}${line}${NC}" >> $TEMP_FILE
done
echo >> $TEMP_FILE

# Display the output using fzf with preview window
cat $TEMP_FILE | fzf --preview 'echo {} | bat --color=always --style=plain' --ansi --bind 'alt-enter:execute(bat {})'

# Clean up
rm $TEMP_FILE

