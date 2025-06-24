#!/bin/bash
# Smart VIP down script that auto-detects IPv4 vs IPv6

INTERFACE=$1
VIP=$2
VHID=$3

# Auto-detect IPv4 vs IPv6
if [[ "$VIP" =~ : ]]; then
    # IPv6 address (contains colons)
    echo "$(date): IPv6 VIP DOWN - Removing $VIP from $INTERFACE" | logger -t ucarp
    ip -6 addr del "$VIP" dev "$INTERFACE" 2>/dev/null
    # Optional: Remove IPv6 routes if needed
    # ip -6 route del default via fe80::1 dev $INTERFACE 2>/dev/null
else
    # IPv4 address
    echo "$(date): IPv4 VIP DOWN - Removing $VIP from $INTERFACE" | logger -t ucarp
    ip addr del "$VIP" dev "$INTERFACE" 2>/dev/null
    # Optional: Clean up ARP entries
    # ip neigh flush dev $INTERFACE
fi

echo "$(date): VIP $VIP is now INACTIVE on $INTERFACE (VHID $VHID)" | logger -t ucarp
