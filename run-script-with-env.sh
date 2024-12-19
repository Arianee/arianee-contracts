#!/usr/bin/env bash

# Check if required arguments are provided
if [ "$#" -lt 2 ]; then
  echo "Usage: $0 <chainId> <script> [additional forge parameters...]"
  exit 1
fi

chainId=$1
script=$2
shift 2

env_dir="script/config"
env_file="${env_dir}/${chainId}_${script}.env"

# Check if the .env file exists
if [ ! -f "$env_file" ]; then
echo "Error: Environment file not found at \`${env_file}\`"
  exit 1
fi

# Source the .env file
echo "Sourcing environment file: ${env_file}"
set -o allexport
source "$env_file"
set +o allexport

# Check if RPC_URL is set
if [ -z "$RPC_URL" ]; then
  echo "Error: RPC_URL not set"
  exit 1
fi
# Check if EVM_VERSION is set
if [ -z "$EVM_VERSION" ]; then
  echo "Error: EVM_VERSION not set"
  exit 1
fi

# Output additional forge parameters
forge_params=(--rpc-url "$RPC_URL" --evm-version "$EVM_VERSION" --force --gas-limit 1000000000000 "$@")
echo "Forge parameters: ${forge_params[@]}"

# Set environment variables
export CHAIN_ID=$chainId

broadcast=false
for arg in "$@"; do
  if [ "$arg" == "--broadcast" ]; then
    broadcast=true
    break
  fi
done
export BROADCAST=$broadcast

# Run the forge script
start_time=$(date +%s)
forge script "$script" "${forge_params[@]}"
end_time=$(date +%s)
elapsed_time=$((end_time - start_time))
echo "Elapsed time: $elapsed_time seconds"

# After script completion, check for `prover.pid` and stop the prover if it exists
# This can happen if the script is stopped before it can stop the prover
pid_file="prover.pid"

if [ -f "$pid_file" ]; then
  echo -e "\nDetected '${pid_file}'. Attempting to stop prover..."
  
  # Optionally, you can verify if the process is running before attempting to stop
  pid=$(cat "$pid_file")
  if ps -p "$pid" > /dev/null 2>&1; then
    echo "Stopping prover process with PID: $pid"
    npm run prover stop
  else
    echo "No running prover process found with PID: $pid. Removing stale ${pid_file}."
    rm "$pid_file"
  fi
fi