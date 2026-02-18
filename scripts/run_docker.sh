#!/bin/sh

helpFunction()
{
   echo ""
   echo "Usage: $0 -f scriptName  -l logDirectory"
   echo -e "\t-f Name of script to run"
   echo -e "\t-l Directory to map /apps/logs to"
   exit 1 # Exit script after printing help
}

while getopts "f:l:" opt
do
   case "$opt" in
      f ) scriptName="$OPTARG" ;;
      l ) logDirectory="$OPTARG" ;;
      ? ) helpFunction ;; # Print helpFunction in case parameter is non-existent
   esac
done

# Print helpFunction in case parameters are empty
if [ -z "$scriptName" ] || [ -z "$logDirectory" ]
then
   echo "Some or all of the parameters are empty";
   helpFunction
fi

echo "Running script: $scriptName"
echo "Mapping to log directory: $logDirectory"

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
docker run --rm -t --network host -v $logDirectory:/app/logs -v $SCRIPT_DIR:/app/scripts mamori-api-runner  /app/scripts/run_script.sh $scriptName

