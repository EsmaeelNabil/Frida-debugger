#!/bin/bash

# Source the install_fzf.sh script to ensure fzf is installed
source "$(dirname "$0")/installPreqs.sh"

# Default path to Android emulator
DEFAULT_EMULATOR_PATH="$HOME/Library/Android/sdk/emulator/emulator"

# Function to find the emulator
find_emulator() {
    if [ -x "$DEFAULT_EMULATOR_PATH" ]; then
        echo "$DEFAULT_EMULATOR_PATH"
    elif command -v emulator &> /dev/null; then
        command -v emulator
    else
        echo ""
    fi
}

# Get the emulator path
EMULATOR_PATH=$(find_emulator)

# Check if the emulator was found
if [ -z "$EMULATOR_PATH" ]; then
    echo "Android emulator command not found in default path or in PATH. Please ensure the Android SDK is installed and the emulator is in your PATH."
    exit 1
fi

# Get list of available Android emulators
emulators=$("$EMULATOR_PATH" -list-avds)

# If first line includes "INFO", remove it
if echo "$emulators" | head -n 1 | grep -q "INFO"; then
    emulators=$(echo "$emulators" | sed '1d')
fi

# Use fzf to select an emulator
selected_emulator=$(echo "$emulators" | fzf --height 10 --border --prompt="Select an emulator: ")

# Check if an emulator was selected
if [ -n "$selected_emulator" ]; then
    echo "Launching $selected_emulator"
    nohup "$EMULATOR_PATH" -avd "$selected_emulator" >/dev/null 2>&1 &
else
    echo "No emulator selected."
fi

