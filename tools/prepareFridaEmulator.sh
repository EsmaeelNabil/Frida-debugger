#!/bin/bash
# Define colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get list of connected devices
echo -e "${YELLOW}Getting list of connected devices...${NC}"
DEVICE_LIST="$(adb devices | tail -n +2 | cut -f 1)"

if [ "$(echo "$DEVICE_LIST" | wc -l)" -eq 1 ]; then
    # If there is only one device, use it
    DEVICE_SERIAL="$DEVICE_LIST"
    echo -e "${GREEN}Using device $DEVICE_SERIAL.${NC}"
else
    # Prompt user to choose a device
    echo -e "${YELLOW}Choose a device:${NC}"
    PS3="Device selection: "
    select DEVICE_SERIAL in $DEVICE_LIST; do
        if [ -n "$DEVICE_SERIAL" ]; then
            break
        fi
    done
fi

# check if frida is existing and or running already on the device
FRIDA_SERVER_PID=$(adb -s $DEVICE_SERIAL shell ps | grep fridaserver | awk '{print $2}')

if [ -z "$FRIDA_SERVER_PID" ]; then
    echo -e "${YELLOW}Frida server is not running on $EMULATOR_NAME.${NC}"
    # push frida server using adb to emulator device after choosing the emulator
    adb -s $DEVICE_SERIAL push fridaserver /data/local/tmp/
    adb -s $DEVICE_SERIAL cd /data/local/tmp/ && ls -l
    # make frida server executable
    adb -s $DEVICE_SERIAL shell chmod 777 /data/local/tmp/fridaserver
    adb root
    # run frida server
    adb -s $DEVICE_SERIAL shell /data/local/tmp/fridaserver &
    # get the pid of frida server
    FRIDA_SERVER_PID=$(adb -s $DEVICE_SERIAL shell ps | grep fridaserver | awk '{print $2}')
    # get the name of the emulator
    EMULATOR_NAME=$(adb -s $DEVICE_SERIAL shell getprop ro.product.model)
    echo -e "${GREEN}Frida server is running on $EMULATOR_NAME with pid $FRIDA_SERVER_PID.${NC}"
else
    echo -e "${YELLOW}Frida server is running on $EMULATOR_NAME with pid $FRIDA_SERVER_PID.${NC}"
fi