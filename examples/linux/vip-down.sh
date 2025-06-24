#! /bin/sh
exec 2> /dev/null

/sbin/ip addr del "$2" dev "$1"

# or alternatively:
# /sbin/ifconfig "$1":254 down
