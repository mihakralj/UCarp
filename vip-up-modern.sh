#!/bin/bash
# Modern UCarp VIP-up script supporting IPv4 and IPv6
# Parameters: $1=interface $2=VIP_with_prefix $3=address_family $4=extra_param

INTERFACE="$1"
VIP="$2"
ADDRESS_FAMILY="$3"
EXTRA_PARAM="$4"

# Log the action
logger "UCarp: Adding VIP $VIP to $INTERFACE (IPv$ADDRESS_FAMILY)"

# Handle IPv4 and IPv6 differently
if [ "$ADDRESS_FAMILY" = "6" ]; then
    # IPv6 - VIP already includes prefix like [2001:db8::100]/64
    /sbin/ip -6 addr add "$VIP" dev "$INTERFACE"
    if [ $? -eq 0 ]; then
        logger "UCarp: Successfully added IPv6 VIP $VIP to $INTERFACE"
    else
        logger "UCarp: Failed to add IPv6 VIP $VIP to $INTERFACE"
        exit 1
    fi
else
    # IPv4 - VIP already includes prefix like 192.168.1.100/24
    /sbin/ip addr add "$VIP" dev "$INTERFACE"
    if [ $? -eq 0 ]; then
        logger "UCarp: Successfully added IPv4 VIP $VIP to $INTERFACE"
    else
        logger "UCarp: Failed to add IPv4 VIP $VIP to $INTERFACE"
        exit 1
    fi
fi

# Optional: Add routes, send notifications, etc.
# if [ -n "$EXTRA_PARAM" ]; then
#     # Handle extra parameter if provided
#     logger "UCarp: Extra parameter: $EXTRA_PARAM"
# fi

# Optional: Send gratuitous ARP/NA (usually handled by UCarp itself)
# For IPv4: arping -c 1 -A -I "$INTERFACE" "${VIP%/*}"
# For IPv6: neighbor advertisement is sent by UCarp

exit 0
