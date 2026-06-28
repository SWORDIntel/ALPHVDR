#!/bin/bash
# ALPHVDR Research / Local Dev Toggle
# Toggles the /tmp/ALPHVDR_RESEARCH_MODE flag which disarms eBPF traps and behavioral heuristics.

RESEARCH_FLAG="/tmp/ALPHVDR_RESEARCH_MODE"

if [ -f "$RESEARCH_FLAG" ]; then
    echo "[!] Research mode is currently ON."
    echo "[*] Disabling Research Mode..."
    rm "$RESEARCH_FLAG"
    echo "✅ ALPHVDR is now ARMED and ACTIVE."
else
    echo "[!] ALPHVDR is currently ARMED."
    echo "[*] Enabling Research Mode..."
    touch "$RESEARCH_FLAG"
    echo "⚠️  ALPHVDR is now DISARMED. Safe for local malware development."
fi
