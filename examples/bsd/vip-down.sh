#! /bin/sh
exec 2> /dev/null

# Extract IP address from CIDR notation (if present)
ip_addr=$(echo "$2" | cut -d'/' -f1)

/sbin/ifconfig "$1" -alias "$ip_addr"
