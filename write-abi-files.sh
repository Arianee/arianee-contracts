#!/usr/bin/env bash

# If an argument is passed, use it as SRC_DIR, otherwise default to "src"
SRC_DIR="${1:-src}"

# Skip list of Solidity files (just filenames)
SKIP_LIST=("Constants.sol")

mkdir -p abi

echo "Searching for .sol files under '$SRC_DIR'..."

files_count=$(find "$SRC_DIR" -type f -name "*.sol" | wc -l | xargs)
if [ "$files_count" -eq 0 ]; then
    echo "No .sol files found under '$SRC_DIR'"
    exit 1
fi

find "$SRC_DIR" -type f -name "*.sol" | while read sol_file; do
    # Compute relative path from 'src/' always to preserve full structure
    rel_path="${sol_file#src/}"

    dir_part=$(dirname "$rel_path")
    filename=$(basename "$rel_path" .sol)
    full_filename="${filename}.sol"

    # Check if this file is in the skip list
    if [[ " ${SKIP_LIST[@]} " =~ " ${full_filename} " ]]; then
        echo "Skipping contract '${full_filename}'"
        continue
    fi

    mkdir -p "abi/$dir_part"

    echo "Generating ABI for '$filename'..."
    forge inspect "$filename" abi > "abi/$dir_part/$filename.json"
    echo "ABI generated: abi/$dir_part/$filename.json"
done

echo "$files_count ABIs generated"