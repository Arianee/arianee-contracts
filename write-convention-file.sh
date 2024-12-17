#!/usr/bin/env bash

SUCCESS_HEX="0x0000000000000000000000000000000000000000000000000000000000000001"
FAILURE_HEX="0x0000000000000000000000000000000000000000000000000000000000000000"
ZERO_ADDRESS_HEX="0x0000000000000000000000000000000000000000"

# Convention JSON file template
json_template='{
  "contractAdresses": {
    "aria": "'"$ZERO_ADDRESS_HEX"'",
    "identity": "'"$ZERO_ADDRESS_HEX"'",
    "smartAsset": "'"$ZERO_ADDRESS_HEX"'",
    "updateSmartAssets": "'"$ZERO_ADDRESS_HEX"'",
    "eventArianee": "'"$ZERO_ADDRESS_HEX"'",
    "message": "'"$ZERO_ADDRESS_HEX"'",
    "whitelist": "'"$ZERO_ADDRESS_HEX"'",
    "lost": "'"$ZERO_ADDRESS_HEX"'",
    "creditHistory": "'"$ZERO_ADDRESS_HEX"'",
    "rewardsHistory": "'"$ZERO_ADDRESS_HEX"'",
    "store": "'"$ZERO_ADDRESS_HEX"'",
    "staking": "'"$ZERO_ADDRESS_HEX"'",
    "userAction": "'"$ZERO_ADDRESS_HEX"'",
    "hasher": "'"$ZERO_ADDRESS_HEX"'",
    "creditRegister": "'"$ZERO_ADDRESS_HEX"'",
    "creditVerifier": "'"$ZERO_ADDRESS_HEX"'",
    "creditNotePool": "'"$ZERO_ADDRESS_HEX"'",
    "poseidon": "'"$ZERO_ADDRESS_HEX"'",
    "ownershipVerifier": "'"$ZERO_ADDRESS_HEX"'",
    "issuerProxy": "'"$ZERO_ADDRESS_HEX"'"
  },
  "httpProvider": "",
  "gasStation": "",
  "chainId": 0,
  "protocolVersion": "1.6"
}'

# Silence all output except final result
exec 3>&1 4>&2
exec 1>/dev/null 2>/dev/null

fail() {
  exec 1>&3 2>&4
  echo "$FAILURE_HEX"
  exit 1
}

succeed() {
  exec 1>&3 2>&4
  echo "$SUCCESS_HEX"
  exit 0
}

# Parse command-line arguments
while [ "$#" -gt 0 ]; do
  case "$1" in
    --aria=*) aria="${1#*=}" ;;
    --creditHistory=*) creditHistory="${1#*=}" ;;
    --rewardsHistory=*) rewardsHistory="${1#*=}" ;;
    --eventArianee=*) eventArianee="${1#*=}" ;;
    --identity=*) identity="${1#*=}" ;;
    --smartAsset=*) smartAsset="${1#*=}" ;;
    --staking=*) staking="${1#*=}" ;;
    --store=*) store="${1#*=}" ;;
    --whitelist=*) whitelist="${1#*=}" ;;
    --lost=*) lost="${1#*=}" ;;
    --message=*) message="${1#*=}" ;;
    --userAction=*) userAction="${1#*=}" ;;
    --updateSmartAssets=*) updateSmartAssets="${1#*=}" ;;
    --hasher=*) hasher="${1#*=}" ;;
    --creditRegister=*) creditRegister="${1#*=}" ;;
    --creditVerifier=*) creditVerifier="${1#*=}" ;;
    --creditNotePool=*) creditNotePool="${1#*=}" ;;
    --poseidon=*) poseidon="${1#*=}" ;;
    --ownershipVerifier=*) ownershipVerifier="${1#*=}" ;;
    --issuerProxy=*) issuerProxy="${1#*=}" ;;
    --httpProvider=*) httpProvider="${1#*=}" ;;
    --gasStation=*) gasStation="${1#*=}" ;;
    --chainId=*) chainId="${1#*=}" ;;
    *) fail ;; # If any unknown parameter is provided, fail
  esac
  shift
done

output_dir="convention"
output_file="${output_dir}/${chainId}.json"

mkdir -p "$output_dir" || fail

# If file exists, read it; else start from template
if [ -f "$output_file" ]; then
  base_json=$(cat "$output_file") || fail
else
  base_json="$json_template"
fi

jq_script='.'

# Validate chainId is provided and not zero
if [ -z "$chainId" ] || [ "$chainId" -eq 0 ]; then
  fail
else
  jq_script="$jq_script | .chainId = \$chainId"
fi

update_address_field() {
  local var_name="$1"
  local var_value="$2"
  local jq_path="$3"

  if [ -n "$var_value" ] && [ "$var_value" != "$ZERO_ADDRESS_HEX" ]; then
    jq_script="$jq_script | $jq_path = \$$var_name"
  fi
}

update_string_field() {
  local var_name="$1"
  local var_value="$2"
  local jq_path="$3"

  if [ -n "$var_value" ]; then
    # If string is non-empty, update it ("" would be default)
    # Check if it's not empty
    if [ "$var_value" != "" ]; then
      jq_script="$jq_script | $jq_path = \$$var_name"
    fi
  fi
}

update_address_field "aria" "$aria" ".contractAdresses.aria"
update_address_field "creditHistory" "$creditHistory" ".contractAdresses.creditHistory"
update_address_field "rewardsHistory" "$rewardsHistory" ".contractAdresses.rewardsHistory"
update_address_field "eventArianee" "$eventArianee" ".contractAdresses.eventArianee"
update_address_field "identity" "$identity" ".contractAdresses.identity"
update_address_field "smartAsset" "$smartAsset" ".contractAdresses.smartAsset"
update_address_field "staking" "$staking" ".contractAdresses.staking"
update_address_field "store" "$store" ".contractAdresses.store"
update_address_field "whitelist" "$whitelist" ".contractAdresses.whitelist"
update_address_field "lost" "$lost" ".contractAdresses.lost"
update_address_field "message" "$message" ".contractAdresses.message"
update_address_field "userAction" "$userAction" ".contractAdresses.userAction"
update_address_field "updateSmartAssets" "$updateSmartAssets" ".contractAdresses.updateSmartAssets"
update_address_field "hasher" "$hasher" ".contractAdresses.hasher"
update_address_field "creditRegister" "$creditRegister" ".contractAdresses.creditRegister"
update_address_field "creditVerifier" "$creditVerifier" ".contractAdresses.creditVerifier"
update_address_field "creditNotePool" "$creditNotePool" ".contractAdresses.creditNotePool"
update_address_field "poseidon" "$poseidon" ".contractAdresses.poseidon"
update_address_field "ownershipVerifier" "$ownershipVerifier" ".contractAdresses.ownershipVerifier"
update_address_field "issuerProxy" "$issuerProxy" ".contractAdresses.issuerProxy"

update_string_field "httpProvider" "$httpProvider" ".httpProvider"
update_string_field "gasStation" "$gasStation" ".gasStation"

updated_json=$(jq \
  --arg aria "$aria" \
  --arg creditHistory "$creditHistory" \
  --arg rewardsHistory "$rewardsHistory" \
  --arg eventArianee "$eventArianee" \
  --arg identity "$identity" \
  --arg smartAsset "$smartAsset" \
  --arg staking "$staking" \
  --arg store "$store" \
  --arg whitelist "$whitelist" \
  --arg lost "$lost" \
  --arg message "$message" \
  --arg userAction "$userAction" \
  --arg updateSmartAssets "$updateSmartAssets" \
  --arg hasher "$hasher" \
  --arg creditRegister "$creditRegister" \
  --arg creditVerifier "$creditVerifier" \
  --arg creditNotePool "$creditNotePool" \
  --arg poseidon "$poseidon" \
  --arg ownershipVerifier "$ownershipVerifier" \
  --arg issuerProxy "$issuerProxy" \
  --arg httpProvider "$httpProvider" \
  --arg gasStation "$gasStation" \
  --argjson chainId "$chainId" \
  "$jq_script" <<< "$base_json") || fail

echo "$updated_json" > "$output_file" || fail
succeed
