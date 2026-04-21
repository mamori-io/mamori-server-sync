#!/bin/bash

# =============================================================================
# MAMORI SYNC ENVIRONMENT VARIABLES
# =============================================================================
# Update these values with your actual server details before running sync
# See ../doc/ENVIRONMENT_VARIABLES.md for detailed documentation

# Source server (where data comes from)
export MAMORI_SERVER="https://sandbox.mamori.io"
export MAMORI_USERNAME="syncapi"
export MAMORI_PASSWORD="!Redblack30@api"

# Target server (where data goes to)
export MAMORI_SERVER2="https://103.100.39.162"
export MAMORI_USERNAME2="syncapi"
export MAMORI_PASSWORD2="!Redblack30@api"

# Output directory for configuration files
export MAMORI_OUTPUT_DIRECTORY="/app/sync"

