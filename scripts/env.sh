#!/bin/bash

# =============================================================================
# MAMORI SYNC ENVIRONMENT VARIABLES
# =============================================================================
# Update these values with your actual server details before running sync
# See ../doc/ENVIRONMENT_VARIABLES.md for detailed documentation

# Source server (where data comes from)
export MAMORI_SERVER="https://"
export MAMORI_USERNAME=""
export MAMORI_PASSWORD=""

# Target server (where data goes to)
export MAMORI_SERVER2="https://"
export MAMORI_USERNAME2=""
export MAMORI_PASSWORD2=""


# Active Directory providers (optional - leave empty if not using AD)
export MAMORI_AD_PROVIDER=""
export MAMORI_AD_PROVIDER2=""

# Output directory for configuration files
export MAMORI_OUTPUT_DIRECTORY="/app/sync"

