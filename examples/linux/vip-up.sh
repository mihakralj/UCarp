#! /bin/sh
exec 2> /dev/null

/sbin/ip addr add "$2" dev "$1"

# or alternatively, if using ifconfig, you would need to parse the CIDR notation:
# /sbin/ifconfig "$1":254 "$2" netmask 255.255.255.0
