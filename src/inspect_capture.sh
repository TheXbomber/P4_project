#!/bin/bash
# Launch Wireshark with the custom NSH-over-MPLS Lua dissector.
# Usage:
#   ./wireshark.sh
#   ./wireshark.sh shared/pkt_captures/d_eth2.pcap

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LUA_FILE="${SCRIPT_DIR}/shared/nsh_mpls.lua"

if [ ! -f "$LUA_FILE" ]; then
    echo "Error: Lua dissector not found at $LUA_FILE"
    exit 1
fi

echo "Launching Wireshark with Lua dissector: $LUA_FILE"
wireshark -X "lua_script:${LUA_FILE}" "$@" &
