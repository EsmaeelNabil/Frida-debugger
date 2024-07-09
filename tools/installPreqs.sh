#!/bin/bash

# install_fzf.sh
# Function to check if fzf is installed
check_fzf() {
    if ! command -v fzf &> /dev/null; then
        echo "fzf is not installed. Installing fzf..."
        install_fzf
    fi
}

# Function to install fzf on macOS
install_fzf_macos() {
    if ! command -v brew &> /dev/null; then
        echo "Homebrew is not installed. Installing Homebrew first..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    brew install fzf
}

# Function to install fzf on Linux
install_fzf_linux() {
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y fzf
    elif command -v yum &> /dev/null; then
        sudo yum install -y fzf
    elif command -v pacman &> /dev/null; then
        sudo pacman -Syu fzf
    else
        echo "Package manager not supported. Please install fzf manually."
        exit 1
    fi
}

# Function to determine the OS and install fzf
install_fzf() {
    case "$(uname -s)" in
        Darwin)
            install_fzf_macos
            ;;
        Linux)
            install_fzf_linux
            ;;
        *)
            echo "Unsupported OS. Please install fzf manually."
            exit 1
            ;;
    esac
}

# Check and install fzf if necessary
check_fzf

