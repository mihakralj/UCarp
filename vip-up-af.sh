#!/bin/bash
# VIP up script with explicit address family parameter

INTERFACE=$1
VIP=$2
ADDRESS_FAMILY=$3
VHID=$4

# Use address family parameter to determine IP version
if [[ "$ADDRESS_FAMILY" == "6" ]]; then
    # IPv6 address
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

echo "$(date): VIP $VIP (IPv$ADDRESS_FAMILY) is now ACTIVE on $INTERFACE (VHID $VHID)" | logger -t ucarp
