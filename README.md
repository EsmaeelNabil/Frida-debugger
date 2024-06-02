# Frida-debugger

Frida-debugger is a powerful tool designed for mobile development, testing, debugging, and security analysis, powered by the Frida framework. It currently supports Android platforms, with plans for expansion to iOS and OSX in the future.

![Frida-debugger Screenshot](https://github.com/EsmaeelNabil/Frida-debugger/assets/28542963/8188f2f9-1ddf-4c10-b375-f90ca0b69129)

## Overview

Frida-debugger provides a robust set of features for enhancing mobile development and security analysis. Here's how you can get started:

## Prerequisites

Before using Frida-debugger, ensure you have the following prerequisites installed:

- `node`
- `yarn`
- Android Development Environment:
  - `gradle`
  - `jdk`
  - `ADB`

## Installation

Follow these steps to install and run Frida-debugger:

1. Clone the repository:

    ```bash
    git clone https://github.com/EsmaeelNabil/Frida-debugger.git
    ```

2. Navigate to the backend directory:

    ```bash
    cd Frida-debugger/backend
    ```

3. Install dependencies:

    ```bash
    yarn install
    ```

4. Build the project:

    ```bash
    yarn build
    ```

5. Start the backend server:

    ```bash
    node dist/bundle.js
    ```

## Running the Desktop App

To run the desktop app, execute the following commands:

```bash
cd Frida-debugger/front-end
./gradlew run
