#!/bin/bash
# Smart VIP up script that auto-detects IPv4 vs IPv6

INTERFACE=$1
VIP=$2
VHID=$3

# Auto-detect IPv4 vs IPv6
if [[ "$VIP" =~ : ]]; then
    # IPv6 address (contains colons)
    echo "$(date): IPv6 VIP UP - Adding $VIP to $INTERFACE" | logger -t ucarp
    ip -6 addr add "$VIP" dev "$INTERFACE" 2>/dev/null
    # Optional: Add IPv6 route if needed
    # ip -6 route add default via fe80::1 dev $INTERFACE
else
    # IPv4 address
    echo "$(date): IPv4 VIP UP - Adding $VIP to $INTERFACE" | logger -t ucarp  
    ip addr add "$VIP" dev "$INTERFACE" 2>/dev/null
    # Optional: Send gratuitous ARP
    # arping -c 3 -A -I $INTERFACE ${VIP%/*}
fi

echo "$(date): VIP $VIP is now ACTIVE on $INTERFACE (VHID $VHID)" | logger -t ucarp
