# UCarp - Portable Unix CARP Implementation

## Overview

UCarp is a portable userland implementation of the Common Address Redundancy Protocol (CARP). It allows multiple hosts to share virtual IP addresses for automatic failover, providing high availability without requiring dedicated hardware or complex networking setups.

CARP is a secure, patent-free alternative to VRRP (Virtual Router Redundancy Protocol) originally developed by OpenBSD. UCarp brings this technology to Linux and other Unix-like systems.

## Version 1.6.0 - What's New

### 🆕 **Complete IPv6 Support**
- Native IPv6 CARP protocol implementation
- FreeBSD CARP IPv6 compatibility
- Automatic IPv4/IPv6 protocol detection
- Mixed dual-stack environments supported

### 🔒 **Enhanced Security & Stability**
- Eliminated memory safety vulnerabilities (ALLOCA → malloc)
- Comprehensive input validation and bounds checking
- Modernized function architecture (600+ line functions → modular design)
- Enhanced error handling and logging

### 🚀 **Performance Improvements**
- Optimized packet processing paths
- Reduced code duplication (unified IPv4/IPv6 state machine)
- Better memory management
- Faster failover detection

### 🛡️ **Production Hardening**
- Fixed stack overflow risks
- Enhanced authentication validation
- Improved network packet validation
- Better compatibility with modern operating systems

## Key Features

- **Low Overhead**: Minimal network traffic (small packets every second)
- **Cryptographically Secure**: HMAC-SHA1 signed messages
- **Cross-Platform**: Linux, FreeBSD, OpenBSD, NetBSD, macOS
- **No Dedicated Links**: No need for heartbeat cables between hosts
- **Dual Stack**: Full IPv4 and IPv6 support
- **FreeBSD Compatible**: Interoperates with FreeBSD's native CARP

## Quick Start

### Prerequisites

- libpcap development libraries
- C compiler (GCC recommended)
- Root privileges for network interface access

### Installation

```bash
./configure
make
sudo make install
```

### Basic IPv4 Setup

**Host 1 (10.1.1.1):**
```bash
ucarp --interface=eth0 --srcip=10.1.1.1/24 --vhid=1 --pass=mypassword \
      --addr=10.1.1.100/24 \
      --upscript=/etc/vip-up.sh --downscript=/etc/vip-down.sh
```

**Host 2 (10.1.1.2):**
```bash
ucarp --interface=eth0 --srcip=10.1.1.2/24 --vhid=1 --pass=mypassword \
      --addr=10.1.1.100/24 \
      --upscript=/etc/vip-up.sh --downscript=/etc/vip-down.sh
```

### Basic IPv6 Setup

**Host 1:**
```bash
ucarp --interface=eth0 --srcip="[2001:db8::10]/64" --vhid=2 --pass=mypassword \
      --addr="[2001:db8::100]/64" \
      --upscript=/etc/vip-up.sh --downscript=/etc/vip-down.sh
```

**Host 2:**
```bash
ucarp --interface=eth0 --srcip="[2001:db8::20]/64" --vhid=2 --pass=mypassword \
      --addr="[2001:db8::100]/64" \
      --upscript=/etc/vip-up.sh --downscript=/etc/vip-down.sh
```

## Script Examples

### Universal Script (IPv4/IPv6)

**`/etc/vip-up.sh`:**
```bash
#!/bin/bash
INTERFACE=$1
VIP=$2
ADDRESS_FAMILY=$3

if [ "$ADDRESS_FAMILY" = "6" ]; then
    ip -6 addr add "$VIP" dev "$INTERFACE"
else
    ip addr add "$VIP" dev "$INTERFACE"
fi

# Optional: Update routing, send notifications, etc.
logger "UCarp: Added VIP $VIP to $INTERFACE (IPv$ADDRESS_FAMILY)"
```

**`/etc/vip-down.sh`:**
```bash
#!/bin/bash
INTERFACE=$1
VIP=$2
ADDRESS_FAMILY=$3

if [ "$ADDRESS_FAMILY" = "6" ]; then
    ip -6 addr del "$VIP" dev "$INTERFACE"
else
    ip addr del "$VIP" dev "$INTERFACE"
fi

logger "UCarp: Removed VIP $VIP from $INTERFACE (IPv$ADDRESS_FAMILY)"
```

Make scripts executable:
```bash
chmod +x /etc/vip-up.sh /etc/vip-down.sh
```

## Command Line Options

```
Usage: ucarp [OPTIONS]

Required Options:
  -i, --interface=IF     Network interface to use
  -s, --srcip=IP[/PFX]   Source (real) IP address
  -a, --addr=IP[/PFX]    Virtual IP address to share
  -v, --vhid=ID          Virtual Host ID (1-255)
  -p, --pass=PASSWORD    Shared password

Optional Options:
  -b, --advbase=SEC      Advertisement interval base (default: 1)
  -k, --advskew=SKEW     Advertisement skew (0-255, default: 0)
  -P, --preempt          Enable preemption mode
  -n, --neutral          Don't run down script at startup
  -u, --upscript=FILE    Script to run when becoming master
  -d, --downscript=FILE  Script to run when becoming backup
  -r, --deadratio=RATIO  Dead ratio (default: 3)
  -z, --shutdown         Run down script on exit
  -B, --daemonize        Run in background
  -D, --debug            Enable debug output
  -S, --ignoreifstate    Ignore interface state
  -M, --nomcast          Use broadcast instead of multicast
  -m, --mcast=IP         Multicast address (default: 224.0.0.18)
  -f, --facility=FAC     Syslog facility (default: daemon)
  -x, --xparam=VALUE     Extra parameter for scripts
  -o, --passfile=FILE    Read password from file
  -h, --help             Show this help
```

## IPv6 Considerations

### Address Format
IPv6 addresses must be enclosed in brackets:
```bash
--srcip="[2001:db8::10]/64"
--addr="[2001:db8::100]/64"
```

### Takeover Behavior
IPv6 CARP takeover may take longer than IPv4 due to Neighbor Discovery Protocol:
- **IPv4**: ~1 second (immediate ARP Gratuitous)
- **IPv6**: Up to 30 seconds (depends on router neighbor table expiration)

This is not a UCarp limitation but an inherent IPv6 protocol characteristic.

### FreeBSD Compatibility
UCarp IPv6 is compatible with FreeBSD's native CARP IPv6 implementation:

**FreeBSD Configuration:**
```bash
# /etc/rc.conf
ifconfig_em0_alias0="inet6 2001:db8::100 prefixlen 64 vhid 1 advskew 100 pass mypassword"
```

**UCarp Equivalent:**
```bash
ucarp -i em0 -s "[2001:db8::10]/64" -a "[2001:db8::100]/64" -v 1 -k 100 -p mypassword
```

## Advanced Configuration

### Master Election

Priority is determined by `advbase + (advskew/256)` seconds:
- **Lower values = Higher priority**
- **Preemption**: Use `-P` flag to take over from lower priority masters

**Example - Preferred Master:**
```bash
# High priority master (advskew=50)
ucarp -i eth0 -s 10.1.1.1/24 -a 10.1.1.100/24 -v 1 -k 50 -P -p secret

# Backup (advskew=100)  
ucarp -i eth0 -s 10.1.1.2/24 -a 10.1.1.100/24 -v 1 -k 100 -p secret
```

### Monitoring and Signals

**Check Status:**
```bash
kill -USR1 <ucarp_pid>  # Logs current state to syslog
```

**Force Backup:**
```bash
kill -USR2 <ucarp_pid>  # Demote to backup, wait 3s, resume normal operation
```

**Graceful Shutdown:**
```bash
kill -TERM <ucarp_pid>  # Runs down script if master, then exits
```

### Multiple VIPs

Run separate UCarp instances for each VIP:
```bash
# VIP 1
ucarp -i eth0 -s 10.1.1.1/24 -a 10.1.1.100/24 -v 1 -p secret1 -B

# VIP 2  
ucarp -i eth0 -s 10.1.1.1/24 -a 10.1.1.200/24 -v 2 -p secret2 -B

# IPv6 VIP
ucarp -i eth0 -s "[2001:db8::1]/64" -a "[2001:db8::100]/64" -v 3 -p secret3 -B
```

## Troubleshooting

### Debug Mode
```bash
ucarp -D [other options]  # Run in foreground with debug output
```

### Network Analysis
```bash
# Capture CARP packets
tcpdump -i eth0 proto 112

# IPv6 CARP packets
tcpdump -i eth0 ip6 proto 112

# Multicast traffic
tcpdump -i eth0 net 224.0.0.0/4
```

### Common Issues

**Permission Denied:**
- UCarp requires root privileges for raw socket access

**Interface State:**
- Use `-S` flag to ignore interface carrier state
- Useful for direct connections without switches

**IPv6 Slow Takeover:**
- Normal behavior due to Neighbor Discovery Protocol
- Consider tuning router neighbor table timeouts

**Authentication Failures:**
- Ensure identical passwords on all nodes
- Check that VHIDs match exactly
- Verify virtual IP addresses are identical

### Log Messages
```bash
# View UCarp logs
tail -f /var/log/syslog | grep ucarp

# Or with systemd
journalctl -f -u ucarp
```

## Integration Examples

### Systemd Service

**`/etc/systemd/system/ucarp@.service`:**
```ini
[Unit]
Description=UCarp VHID %i
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/ucarp -B -i eth0 -s 10.1.1.1/24 -a 10.1.1.100/24 -v %i -p mypassword -u /etc/vip-up.sh -d /etc/vip-down.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**Usage:**
```bash
systemctl enable ucarp@1.service
systemctl start ucarp@1.service
```

### Docker Integration

**Dockerfile:**
```dockerfile
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y libpcap-dev
COPY ucarp /usr/local/sbin/
COPY scripts/ /etc/ucarp/
ENTRYPOINT ["/usr/local/sbin/ucarp"]
```

### Cloud Deployments

UCarp works in cloud environments with proper network configuration:
- **AWS**: Use secondary private IPs or Elastic Network Interfaces
- **GCP**: Configure alias IP ranges
- **Azure**: Use internal load balancer or secondary IPs

Note: Cloud environments may require additional routing/security group configuration.

## Performance Tuning

### Recommended Settings

**Production High-Availability:**
```bash
ucarp -i eth0 -s 10.1.1.1/24 -a 10.1.1.100/24 -v 1 \
      -b 1 -k 0 -r 3 -p strongpassword \
      -u /etc/vip-up.sh -d /etc/vip-down.sh -B
```

**Fast Failover (< 3 seconds):**
```bash
ucarp -i eth0 -s 10.1.1.1/24 -a 10.1.1.100/24 -v 1 \
      -b 1 -k 10 -r 2 -p strongpassword \
      -u /etc/vip-up.sh -d /etc/vip-down.sh -B
```

### Network Considerations

- **Multicast**: Ensure switches support IGMP
- **Security**: Consider dedicated VLAN for CARP traffic
- **Monitoring**: Monitor CARP packet loss and timing

## Security

### Password Requirements
- Use strong, unique passwords for each VHID
- Store passwords in files with restrictive permissions (600)
- Consider key rotation policies

### Network Security
- Isolate CARP traffic when possible
- Monitor for unauthorized CARP advertisements
- Use network access control (802.1X) where applicable

### Access Control
```bash
# Store password securely
echo "strongpassword" > /etc/ucarp.key
chmod 600 /etc/ucarp.key
chown root:root /etc/ucarp.key

# Use password file
ucarp -o /etc/ucarp.key [other options]
```

## Compatibility

### Operating System Support
- **Linux**: 2.6+ (tested on RHEL, Ubuntu, Debian, CentOS)
- **FreeBSD**: 10+ (full IPv6 CARP interoperability)
- **OpenBSD**: 4.0+ (native CARP compatibility)
- **NetBSD**: 5.0+
- **macOS**: 10.9+

### Network Equipment
- **Switches**: Must support IGMP for multicast
- **Routers**: Standard IPv4/IPv6 forwarding
- **Firewalls**: Allow CARP protocol (IP protocol 112)

## Contributing

UCarp is open source software. Contributions are welcome:

1. **Bug Reports**: Use GitHub issues with full debug output
2. **Feature Requests**: Propose enhancements with use cases
3. **Code Contributions**: Submit pull requests with tests
4. **Documentation**: Help improve examples and guides

### Development

```bash
# Build from source
git clone https://github.com/jedisct1/ucarp.git
cd ucarp
./configure --enable-debug
make
```

## License

UCarp is distributed under a BSD-style license. See the source code for full license terms.

## Support

- **Documentation**: This README and man pages
- **Community**: GitHub issues and discussions
- **Commercial**: Contact maintainers for commercial support options

---

**UCarp** - Bringing enterprise-grade high availability to Unix systems since 2003.
