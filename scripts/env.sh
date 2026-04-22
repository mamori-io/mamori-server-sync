#!/bin/bash

# =============================================================================
# MAMORI SYNC ENVIRONMENT VARIABLES
# =============================================================================
# Update these values with your actual server details before running sync
# See ../doc/ENVIRONMENT_VARIABLES.md for detailed documentation

# Source server (where data comes from)
export MAMORI_SERVER="https://SOURCE_SERVER"
export MAMORI_USERNAME="syncapi"
export MAMORI_PASSWORD="SOURCE_SERVER_PASSWORD"

# Target server (where data goes to)
export MAMORI_SERVER2="https://TARGET_SERVER"
export MAMORI_USERNAME2="syncapi"
export MAMORI_PASSWORD2="TARGET_SERVER_PASSWORD"

# Output directory for configuration files
export MAMORI_OUTPUT_DIRECTORY="/app/sync"

