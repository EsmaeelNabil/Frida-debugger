#!/bin/bash

# Function to execute build.sh and wait for its success result
execute_build() {
  pushd "$(dirname "$1")" # Change to the directory of the selected JavaScript file
  ./build.sh
  local build_exit_code=$?
  popd # Return to the previous directory
  return $build_exit_code
}

# Check if -b flag is provided
execute_build=false
while getopts "b" opt; do
  case $opt in
    b)
      execute_build=true
      ;;
    \?)
      echo "Invalid option: -$OPTARG"
      exit 1
      ;;
  esac
done

# Find all .js files in the current directory and its subdirectories
files=$(find . -type f -name "*.js" | sed 's|^\./||')

# Check if any .js files were found
if [ -z "$files" ]; then
  echo "No .js files found in the current directory or its subdirectories."
  exit 1
fi

# Display files and allow selection using arrow keys and Enter key to confirm selection (or Ctrl+C to cancel), display the files nested to its directory structure
echo "Select the script you want to run with Frida:"
select file in $files; do
  echo "Selected script: $file"
  break
done

# Execute build.sh if the flag is set
if $execute_build ; then
  echo "Executing build.sh..."
  execute_build "$file"
  if [ $? -eq 0 ]; then
    echo "Build successful."
  else
    echo "Build failed. Exiting."
    exit 1
  fi
fi

# Run the selected script with Frida
echo "Running script $file with Frida..."
frida -U -F -l "$file"
