#!/bin/bash
# VIP down script with explicit address family parameter

INTERFACE=$1
VIP=$2
ADDRESS_FAMILY=$3
VHID=$4

# Use address family parameter to determine IP version
if [[ "$ADDRESS_FAMILY" == "6" ]]; then
    # IPv6 address
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

echo "$(date): VIP $VIP (IPv$ADDRESS_FAMILY) is now INACTIVE on $INTERFACE (VHID $VHID)" | logger -t ucarp
