#!/bin/bash

# Function to check for common root indicators
check_root() {
    local result="false"

    # List of common root binaries and apps
    root_binaries=(
        "/system/app/Superuser.apk"
        "/sbin/su"
        "/system/bin/su"
        "/system/xbin/su"
        "/data/local/xbin/su"
        "/data/local/bin/su"
        "/system/sd/xbin/su"
        "/system/bin/failsafe/su"
        "/data/local/su"
        "/system/xbin/busybox"
        "/system/xbin/daemonsu"
        "/system/etc/init.d/99SuperSUDaemon"
        "/system/bin/.ext/.su"
        "/system/usr/we-need-root/su-backup"
        "/system/xbin/mu"
    )

    # Check for root binaries
    for binary in "${root_binaries[@]}"; do
        if adb shell "[ -f $binary ] && echo 'Found' $binary"; then
            result="true"
            break
        fi
    done

    # Check for build tags
    if adb shell getprop ro.build.tags | grep -q "test-keys"; then
        result="true"
    fi

    # Check for su binary using which command
    if adb shell "which su" | grep -q "/"; then
        result="true"
    fi

    echo "Device is rooted: $result"
}

# Ensure ADB is available
if ! command -v adb &> /dev/null; then
    echo "adb command not found. Please ensure ADB is installed and in your PATH."
    exit 1
fi

# Ensure a device is connected
if ! adb devices | grep -q "device$"; then
    echo "No device connected. Please connect a device with USB debugging enabled."
    exit 1
fi

# Check if the device is rooted
check_root

