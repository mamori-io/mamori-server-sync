#!/bin/sh

cd /home/omasri/sync

# Create logs directory if it doesn't exist
mkdir -p logs

# Check for mode parameters
if [ "$1" = "test" ]; then
    CONFIG_FILE="sync-config-test.json"
    echo "Running in TEST MODE with limited operations"
elif [ "$1" = "report" ]; then
    CONFIG_FILE="sync-config.json"
    echo "Running in REPORT MODE - count summary only"
else
    CONFIG_FILE="sync-config.json"
    echo "Running in FULL SYNC MODE"
fi

# Use the same pattern as run_docker.sh
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="logs/sync_${TIMESTAMP}.log"

echo "Starting sync - dual logging enabled"
echo "Main log file: logs/sync_main_${TIMESTAMP}.log"
echo "Error details log: logs/sync_errors_${TIMESTAMP}.log"
echo "Using configuration: $CONFIG_FILE"

# Copy the selected config file to the standard name for the container
cp "$SCRIPT_DIR/$CONFIG_FILE" "$SCRIPT_DIR/sync-config.json"

if [ "$1" = "report" ]; then
    docker run --rm -t --network host -e REPORT_MODE=true -v `pwd`/logs:/app/logs -v $SCRIPT_DIR:/app/scripts mamori-api-runner-custom  /app/scripts/run_script.sh sync-config.ts
else
    docker run --rm -t --network host -v `pwd`/logs:/app/logs -v $SCRIPT_DIR:/app/scripts mamori-api-runner-custom  /app/scripts/run_script.sh sync-config.ts
fi

# Check if log files were created
MAIN_LOG="logs/sync_main_${TIMESTAMP}.log"
ERROR_LOG="logs/sync_errors_${TIMESTAMP}.log"

if [ -f "$MAIN_LOG" ]; then
    echo "Sync completed successfully!"
    echo "Main log file: $MAIN_LOG"
    if [ -f "$ERROR_LOG" ]; then
        echo "Error details log: $ERROR_LOG"
    fi
else
    echo "Warning: Expected log files not found. Check Docker output above for errors."
fi

