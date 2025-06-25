#!/bin/bash
# Modern UCarp VIP-down script supporting IPv4 and IPv6
# Parameters: $1=interface $2=VIP_with_prefix $3=address_family $4=extra_param

INTERFACE="$1"
VIP="$2"
ADDRESS_FAMILY="$3"
EXTRA_PARAM="$4"

# Log the action
logger "UCarp: Removing VIP $VIP from $INTERFACE (IPv$ADDRESS_FAMILY)"

# Handle IPv4 and IPv6 differently
if [ "$ADDRESS_FAMILY" = "6" ]; then
    # IPv6 - VIP already includes prefix like [2001:db8::100]/64
    /sbin/ip -6 addr del "$VIP" dev "$INTERFACE"
    if [ $? -eq 0 ]; then
        logger "UCarp: Successfully removed IPv6 VIP $VIP from $INTERFACE"
    else
        logger "UCarp: Failed to remove IPv6 VIP $VIP from $INTERFACE"
        exit 1
    fi
else
    # IPv4 - VIP already includes prefix like 192.168.1.100/24
    /sbin/ip addr del "$VIP" dev "$INTERFACE"
    if [ $? -eq 0 ]; then
        logger "UCarp: Successfully removed IPv4 VIP $VIP from $INTERFACE"
    else
        logger "UCarp: Failed to remove IPv4 VIP $VIP from $INTERFACE"
        exit 1
    fi
fi

# Optional: Remove routes, send notifications, etc.
# if [ -n "$EXTRA_PARAM" ]; then
#     # Handle extra parameter if provided
#     logger "UCarp: Extra parameter: $EXTRA_PARAM"
# fi

exit 0
