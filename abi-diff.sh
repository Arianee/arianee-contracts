#!/usr/bin/env bash

# abi-diff.sh
# Usage: ./abi-diff.sh <old_abi.json> <new_abi.json>
# Compares two ABI JSON files, outputs differences in same functions and lists missing/added functions with stateMutability

# Exit immediately if a command exits with a non-zero status
set -e

# Function to display usage instructions
usage() {
    echo "Usage: $0 <old_abi.json> <new_abi.json>"
    exit 1
}

# Check if two arguments are provided
if [ "$#" -ne 2 ]; then
    echo "Error: Two ABI JSON files must be provided"
    usage
fi

# Assign input arguments to variables
old_abi="$1"
new_abi="$2"

# Verify that both files exist
if [ ! -f "$old_abi" ]; then
    echo "Error: File '$old_abi' not found"
    exit 1
fi

if [ ! -f "$new_abi" ]; then
    echo "Error: File '$new_abi' not found"
    exit 1
fi

# Check if 'jq' is installed
if ! command -v jq &> /dev/null; then
    echo "Error: 'jq' is not installed. Please install it to proceed"
    echo "You can install it using:"
    echo "  sudo apt-get install jq          # On Debian/Ubuntu"
    echo "  brew install jq                  # On macOS with Homebrew"
    exit 1
fi

# Check if 'gawk' is installed; if not, fallback to 'awk'
if command -v gawk &> /dev/null; then
    AWK_CMD="gawk"
else
    AWK_CMD="awk"
fi

# Create a temporary directory to store intermediate files
temp_dir=$(mktemp -d)
# Ensure temporary files are cleaned up on script exit
cleanup() {
    rm -rf "$temp_dir"
}
trap cleanup EXIT

# Define paths for temporary files
old_functions="$temp_dir/old_functions.txt"
new_functions="$temp_dir/new_functions.txt"
old_signatures="$temp_dir/old_signatures.txt"
new_signatures="$temp_dir/new_signatures.txt"
common_signatures="$temp_dir/common_signatures.txt"
common_joined="$temp_dir/common_joined.txt"
missing_in_new="$temp_dir/missing_in_new.txt"
added_in_new="$temp_dir/added_in_new.txt"
differences="$temp_dir/differences.txt"

# Function to extract functions from an ABI and format them
extract_functions() {
    local abi_file="$1"
    local output_file="$2"

    jq -r '
        .[] |
        select(.type == "function") |
        "\(.name)(\(.inputs | map(.type) | join(",")))\t\(.stateMutability // "nonpayable")\t\(.outputs | map(.type) | join(","))"
    ' "$abi_file" | sort > "$output_file"
}

# Extract functions from both ABIs
extract_functions "$old_abi" "$old_functions"
extract_functions "$new_abi" "$new_functions"

# Extract function signatures (name and input types) for comparison
cut -f1 "$old_functions" | sort > "$old_signatures"
cut -f1 "$new_functions" | sort > "$new_signatures"

# Identify functions present in old ABI but missing in new ABI
comm -23 "$old_signatures" "$new_signatures" > "$missing_in_new"

# Identify functions present in new ABI but missing in old ABI
comm -13 "$old_signatures" "$new_signatures" > "$added_in_new"

# Identify functions present in both ABIs
comm -12 "$old_signatures" "$new_signatures" > "$common_signatures"

# Join the details of common functions from both ABIs
join -t $'\t' -1 1 -2 1 <(sort "$old_functions") <(sort "$new_functions") > "$common_joined"

# Compare properties of common functions and identify differences
$AWK_CMD -F'\t' '{
    if ($2 != $4 || $3 != $5) {
        print "Function: " $1
        if ($2 != $4) {
            print "  - stateMutability changed from \"" $2 "\" to \"" $4 "\""
        }
        if ($3 != $5) {
            print "  - Outputs changed from [" $3 "] to [" $5 "]"
        }
        print ""
    }
}' "$common_joined" > "$differences"

# Display the comparison results
echo "=== ABI Comparison Result ==="

# Display missing functions in the new ABI with stateMutability
if [ -s "$missing_in_new" ]; then
    echo ""
    echo "🔴 Missing functions in new ABI:"
    while IFS= read -r func; do
        # Extract stateMutability from old_functions using inline awk substitution
        # Handle special characters by embedding the function signature directly into awk
        state=$($AWK_CMD -F'\t' '$1 == "'"$func"'" {print $2}' "$old_functions")
        # Handle empty stateMutability
        if [ -z "$state" ]; then
            state="N/A"
        fi
        echo "  - $func [stateMutability: $state]"
    done < "$missing_in_new"
else
    echo ""
    echo "✅ No missing functions in new ABI"
fi

# Display added functions in the new ABI with stateMutability
if [ -s "$added_in_new" ]; then
    echo ""
    echo "🟢 Added functions in new ABI:"
    while IFS= read -r func; do
        # Extract stateMutability from new_functions using inline awk substitution
        state=$($AWK_CMD -F'\t' '$1 == "'"$func"'" {print $2}' "$new_functions")
        # Handle empty stateMutability
        if [ -z "$state" ]; then
            state="N/A"
        fi
        echo "  - $func [stateMutability: $state]"
    done < "$added_in_new"
else
    echo ""
    echo "✅ No added functions in new ABI"
fi

# Display functions with differing properties
if [ -s "$differences" ]; then
    echo ""
    echo "🟡 Functions with differences:"
    echo ""
    cat "$differences"
else
    echo ""
    echo "✅ No differences found in common functions"
fi

# Final confirmation if ABIs are fully compatible
if [ ! -s "$missing_in_new" ] && [ ! -s "$added_in_new" ] && [ ! -s "$differences" ]; then
    echo ""
    echo "🎉 No differences found. The ABIs are fully identical"
fi