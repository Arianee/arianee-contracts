#!/usr/bin/env bash

# Usage:
# ./verify-from-run-file.sh --file <path_to_broadcast_json> [--tx-index <transaction_index>] [--verifier <verifier>] [--verifier-url <verifier-url>] [--compiler-version <compiler-version>] [--optimizer-runs <runs>] [--via-ir <true|false>] [--evm-version <version>] [--debug]

# Default values
BROADCAST_FILE=""
TRANSACTION_INDEX=""
VERIFIER="blockscout"
VERIFIER_URL="https://testnet.explorer.etherlink.com/api/"
COMPILER_VERSION="v0.8.28+commit.7893614a"
OPTIMIZER_RUNS="200"
VIA_IR="true"
EVM_VERSION="shanghai"
WATCH="true"
DEBUG="false"

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --file)
            BROADCAST_FILE="$2"
            shift
            shift
            ;;
        --tx-index)
            TRANSACTION_INDEX="$2"
            shift
            shift
            ;;
        --verifier)
            VERIFIER="$2"
            shift
            shift
            ;;
        --verifier-url)
            VERIFIER_URL="$2"
            shift
            shift
            ;;
        --compiler-version)
            COMPILER_VERSION="$2"
            shift
            shift
            ;;
        --optimizer-runs)
            OPTIMIZER_RUNS="$2"
            shift
            shift
            ;;
        --via-ir)
            VIA_IR="$2"
            shift
            shift
            ;;
        --evm-version)
            EVM_VERSION="$2"
            shift
            shift
            ;;
        --debug)
            DEBUG="true"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

if [ -z "$BROADCAST_FILE" ]; then
    echo "Usage: $0 --file <path_to_broadcast_json> [--tx-index <transaction_index>] [--verifier <verifier>] [--verifier-url <url>] [--compiler-version <version>] [--optimizer-runs <runs>] [--via-ir <true|false>] [--evm-version <version>] [--debug]"
    exit 1
fi

VIA_IR_FLAG=""
if [ "$VIA_IR" = "true" ]; then
  VIA_IR_FLAG="--via-ir"
fi

WATCH_FLAG=""
if [ "$WATCH" = "true" ]; then
  WATCH_FLAG="--watch"
fi

CHAIN_ID=$(jq '.chain' "$BROADCAST_FILE")

run_forge_verification() {
    local CONTRACT_ADDR="$1"
    local CONTRACT_NAME="$2"
    local CTOR_ARGS="$3"

    # If contract name is "null", skip verification
    if [ "$CONTRACT_NAME" = "null" ]; then
        echo "Skipping verification for contract $CONTRACT_ADDR"
        return
    fi

    # Build the arguments array for forge verify-contract
    CMD_ARGS=(
      "forge" "verify-contract"
      "$CONTRACT_ADDR" "$CONTRACT_NAME"
      "--verifier" "$VERIFIER"
      "--verifier-url" "$VERIFIER_URL"
      "--compiler-version" "$COMPILER_VERSION"
      "--optimizer-runs" "$OPTIMIZER_RUNS"
      $VIA_IR_FLAG
      "--constructor-args" "$CTOR_ARGS"
      "--chain-id" "$CHAIN_ID"
      "--evm-version" "$EVM_VERSION"
      $WATCH_FLAG
    )

    # If DEBUG is true, print the command
    if [ "$DEBUG" = "true" ]; then
      echo "${CMD_ARGS[@]}"
    fi

    # Execute the command
    "${CMD_ARGS[@]}"
}

if [ -n "$TRANSACTION_INDEX" ]; then
    TRANSACTION=$(jq -c ".transactions[$TRANSACTION_INDEX]" "$BROADCAST_FILE")
    TYPE=$(echo "$TRANSACTION" | jq -r '.transactionType')

    if [ "$TYPE" = "CREATE" ]; then
        CONTRACT_ADDR=$(echo "$TRANSACTION" | jq -r '.contractAddress')
        CONTRACT_NAME=$(echo "$TRANSACTION" | jq -r '.contractName')
        CTOR_ARGS=$(echo "$TRANSACTION" | jq -r 'if .arguments then .arguments | join(" ") else "" end')

        run_forge_verification "$CONTRACT_ADDR" "$CONTRACT_NAME" "$CTOR_ARGS"
    else
        echo "Transaction at index $TRANSACTION_INDEX is not of type CREATE."
        exit 1
    fi
else
    # If no index is specified, we verify all CREATE transactions
    jq -c '.transactions[] | select(.transactionType=="CREATE")' "$BROADCAST_FILE" | while read -r contract; do
        CONTRACT_ADDR=$(echo "$contract" | jq -r '.contractAddress')
        CONTRACT_NAME=$(echo "$contract" | jq -r '.contractName')
        CTOR_ARGS=$(echo "$contract" | jq -r 'if .arguments then .arguments | join(" ") else "" end')

        run_forge_verification "$CONTRACT_ADDR" "$CONTRACT_NAME" "$CTOR_ARGS"
    done
fi
