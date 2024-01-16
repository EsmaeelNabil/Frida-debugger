#!/bin/bash

# list all the android emulators and choose one of them to open it
# Get list of available Android emulators
emulators=$(/Users/$USER/Library/Android/sdk/emulator/emulator emulator -list-avds)

# Choose one of the emulators
echo "Choose an emulator to launch:"
select emulator in $emulators; do
    echo "Launching $emulator"
    nohup ~/Library/Android/sdk/emulator/emulator -avd "$emulator" >/dev/null 2>&1 &
    break
done
