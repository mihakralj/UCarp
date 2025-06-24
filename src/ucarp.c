
#define DEFINE_GLOBALS 1

#include <config.h>
#include "ucarp.h"
#ifndef HAVE_GETOPT_LONG
# include "bsd-getopt_long.h"
#else
# include <getopt.h>
#endif
#ifdef HAVE_SETLOCALE
# include <locale.h>
#endif
#include "log.h"
#include "daemonize.h"
#include "ucarp_p.h"

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

static void usage(void)
{
    puts("\n" PACKAGE_STRING " - " __DATE__ "\n");
    fputs(_(
        "UCarp - Portable Unix CARP implementation with IPv4 and IPv6 support\n"
        "\n"
        "COMMAND LINE OPTIONS:\n"
        "--interface=<if> (-i <if>): bind interface <if>\n"
        "--srcip=<ip[/prefix]> (-s <ip[/prefix]>): source (real) IP address of that host\n"
        "    IPv4: 192.168.1.10/24 or 192.168.1.10\n"
        "    IPv6: [2001:db8::10]/64 or [2001:db8::10]\n"
        "--mcast=<ip> (-m <ip>): multicast group IP address (default 224.0.0.18)\n"
        "--vhid=<id> (-v <id>): virtual IP identifier (1-255)\n"
        "--pass=<pass> (-p <pass>): password\n"
        "--passfile=<file> (-o <file>): read password from file\n"
        "--preempt (-P): becomes a master as soon as possible\n"
        "--neutral (-n): don't run downscript at start if backup\n"
        "--addr=<ip[/prefix]> (-a <ip[/prefix]>): virtual shared IP address\n"
        "    IPv4: 192.168.1.100/24 or 192.168.1.100\n"
        "    IPv6: [2001:db8::100]/64 or [2001:db8::100]\n"
        "--help (-h): summary of command-line options\n"
        "--advbase=<seconds> (-b <seconds>): advertisement frequency\n"
        "--advskew=<skew> (-k <skew>): advertisement skew (0-255)\n"
        "--upscript=<file> (-u <file>): run <file> to become a master\n"
        "--downscript=<file> (-d <file>): run <file> to become a backup\n"
        "--deadratio=<ratio> (-r <ratio>): ratio to consider a host as dead\n"
        "--debug (-D): enable debug output\n"
        "--shutdown (-z): call shutdown script at exit\n"
        "--daemonize (-B): run in background\n"
        "--ignoreifstate (-S): ignore interface state (down, no carrier)\n"
        "--nomcast (-M): use broadcast (instead of multicast) advertisements\n"
        "--facility=<facility> (-f): set syslog facility (default=daemon)\n"
        "--xparam=<value> (-x): extra parameter to send to up/down scripts\n"
        "\n"
        "SCRIPT PARAMETERS:\n"
        "Up/down scripts receive the following parameters:\n"
        "  $1 = interface name (e.g., eth0)\n"
        "  $2 = virtual IP address with prefix (e.g., 192.168.1.100/24 or [2001:db8::100]/64)\n"
        "  $3 = address family (\"4\" for IPv4, \"6\" for IPv6)\n"
        "  $4 = extra parameter (--xparam value, if specified)\n"
        "\n"
        "SAMPLE USAGE:\n"
        "\n"
        "IPv4 CARP:\n"
        "Manage the 10.1.1.252/24 shared virtual address on interface eth0, with\n"
        "1 as a virtual address identifier, mypassword as a password, and\n"
        "10.1.1.1/24 as a real permanent address for this host.\n"
        "\n"
        "ucarp --interface=eth0 --srcip=10.1.1.1/24 --vhid=1 --pass=mypassword \\\n"
        "      --addr=10.1.1.252/24 \\\n"
        "      --upscript=/etc/vip-up.sh --downscript=/etc/vip-down.sh\n"
        "\n"
        "IPv6 CARP:\n"
        "Manage the [2001:db8::100]/64 shared virtual address on interface eth0, with\n"
        "2 as a virtual address identifier, mypassword as a password, and\n"
        "[2001:db8::10]/64 as a real permanent address for this host.\n"
        "\n"
        "ucarp --interface=eth0 --srcip=\"[2001:db8::10]/64\" --vhid=2 --pass=mypassword \\\n"
        "      --addr=\"[2001:db8::100]/64\" \\\n"
        "      --upscript=/etc/vip-up.sh --downscript=/etc/vip-down.sh\n"
        "\n"
        "Mixed IPv4/IPv6 environments are supported. UCarp automatically detects\n"
        "address families and handles IPv4 and IPv6 CARP protocols appropriately.\n"
        "\n\n"
        "Please report bugs to "), stdout);
    puts(PACKAGE_BUGREPORT ".\n");

    exit(EXIT_SUCCESS);
}

static void init_rand(void)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);
#ifdef HAVE_SRANDOMDEV
    srandomdev();
#elif defined(HAVE_RANDOM)
    srandom((unsigned int) (tv.tv_sec ^ tv.tv_usec ^ (getpid() << 16)));
#else
    srand((unsigned int) (tv.tv_sec ^ tv.tv_usec ^ (getpid() << 16)));
#endif
}

static void die_mem(void)
{
    logfile(LOG_ERR, _("Out of memory"));

    exit(EXIT_FAILURE);
}

int parse_cidr(const char *cidr_str, struct in_addr *addr, int *prefix)
{
    char *addr_str = NULL;
    char *prefix_str = NULL;
    char *slash_pos = NULL;
    int result = 0;
    
    /* Make a copy of the input string */
    addr_str = strdup(cidr_str);
    if (addr_str == NULL) {
        return -1;
    }
    
    /* Look for the slash separator */
    slash_pos = strchr(addr_str, '/');
    if (slash_pos != NULL) {
        /* Split the string at the slash */
        *slash_pos = '\0';
        prefix_str = slash_pos + 1;
        
        /* Parse the prefix length */
        *prefix = (int) strtol(prefix_str, NULL, 10);
        if (*prefix < 0 || *prefix > 32) {
            logfile(LOG_ERR, _("Invalid prefix length: %d (must be 0-32)"), *prefix);
            result = -1;
            goto cleanup;
        }
    } else {
        /* No slash found, assume /32 for host addresses */
        *prefix = 32;
    }
    
    /* Parse the IP address */
    if (inet_pton(AF_INET, addr_str, addr) != 1) {
        logfile(LOG_ERR, _("Invalid IP address: [%s]"), addr_str);
        result = -1;
        goto cleanup;
    }
    
cleanup:
    free(addr_str);
    return result;
}

#ifdef INET6
int is_ipv6_address(const char *addr_str)
{
    if (addr_str == NULL || strlen(addr_str) < 3) {
        return 0;
    }
    
    /* IPv6 addresses must be in brackets: [addr] */
    return (addr_str[0] == '[' && strchr(addr_str, ']') != NULL);
}

int parse_ipv6_cidr(const char *cidr_str, struct in6_addr *addr, int *prefix)
{
    char *addr_str = NULL;
    char *prefix_str = NULL;
    char *bracket_start = NULL;
    char *bracket_end = NULL;
    char *slash_pos = NULL;
    int result = 0;
    size_t addr_len;
    
    if (cidr_str == NULL || addr == NULL || prefix == NULL) {
        return -1;
    }
    
    /* Make a copy of the input string */
    addr_str = strdup(cidr_str);
    if (addr_str == NULL) {
        return -1;
    }
    
    /* IPv6 addresses must be in brackets: [addr]/prefix or [addr] */
    bracket_start = strchr(addr_str, '[');
    bracket_end = strchr(addr_str, ']');
    
    if (bracket_start == NULL || bracket_end == NULL || bracket_start != addr_str) {
        logfile(LOG_ERR, _("Invalid IPv6 format: [%s] - must be [address]/prefix"), cidr_str);
        result = -1;
        goto cleanup;
    }
    
    if (bracket_end <= bracket_start + 1) {
        logfile(LOG_ERR, _("Empty IPv6 address in brackets: [%s]"), cidr_str);
        result = -1;
        goto cleanup;
    }
    
    /* Look for prefix after the closing bracket */
    slash_pos = strchr(bracket_end, '/');
    if (slash_pos != NULL) {
        prefix_str = slash_pos + 1;
        
        /* Parse the prefix length */
        *prefix = (int) strtol(prefix_str, NULL, 10);
        if (*prefix < 0 || *prefix > 128) {
            logfile(LOG_ERR, _("Invalid IPv6 prefix length: %d (must be 0-128)"), *prefix);
            result = -1;
            goto cleanup;
        }
    } else {
        /* No slash found, assume /128 for host addresses */
        *prefix = 128;
    }
    
    /* Extract IPv6 address from between brackets */
    *bracket_end = '\0';  /* Terminate the address string */
    addr_len = bracket_end - (bracket_start + 1);
    if (addr_len == 0) {
        logfile(LOG_ERR, _("Empty IPv6 address: [%s]"), cidr_str);
        result = -1;
        goto cleanup;
    }
    
    /* Parse the IPv6 address */
    if (inet_pton(AF_INET6, bracket_start + 1, addr) != 1) {
        logfile(LOG_ERR, _("Invalid IPv6 address: [%s]"), bracket_start + 1);
        result = -1;
        goto cleanup;
    }
    
cleanup:
    free(addr_str);
    return result;
}
#endif /* INET6 */

int main(int argc, char *argv[])
{
    int option_index = 0;
    int fodder;

#ifdef HAVE_SETLOCALE
    setlocale(LC_ALL, "");
#endif
    bindtextdomain(PACKAGE, LOCALEDIR);
    textdomain(PACKAGE);

    if (argc <= 1) {
        usage();
    }
    inet_pton(AF_INET, DEFAULT_MCASTIP, &mcastip);
    while ((fodder = getopt_long(argc, argv, GETOPT_OPTIONS, long_options,
                                 &option_index)) != -1) {
        switch (fodder) {
        case 'h': {
            usage();
        }
        case 'i': {
            free(interface);
            if ((interface = strdup(optarg)) == NULL) {
                die_mem();
            }
            break;
        }
        case 's': {
#ifdef INET6
            if (is_ipv6_address(optarg)) {
                /* IPv6 address detected */
                if (parse_ipv6_cidr(optarg, &srcip6, &srcip6_prefix) != 0) {
                    return 1;
                }
                address_family = AF_INET6;
            } else {
#endif
                /* IPv4 address */
                if (parse_cidr(optarg, &srcip, &srcip_prefix) != 0) {
                    return 1;
                }
#ifdef INET6
                address_family = AF_INET;
            }
#endif
            break;
        }
        case 'm': {
            if (inet_pton(AF_INET, optarg, &mcastip) == 0) {
                logfile(LOG_ERR, _("Invalid address: [%s]"), optarg);
                return 1;
            }
            break;
        }
        case 'v': {
            if (strtoul(optarg, NULL, 0) > 255 || strtol(optarg, NULL, 0) < 1) {
                logfile(LOG_ERR, _("vhid must be between 1 and 255."));
                return 1;
            }
            vhid = (unsigned char) strtoul(optarg, NULL, 0);
            break;
        }
        case 'p': {
            free(pass);
            if ((pass = strdup(optarg)) == NULL) {
                die_mem();
            }
            break;
        }
        case 'o': {
            char buf[512U];
            char *p;
            FILE *pw;
            if ((pw = fopen(optarg, "r")) == NULL) {
                logfile(LOG_ERR,
                        _("unable to open passfile %s for reading: %s"),
                        optarg, strerror(errno));
                return 1;
            }
            if (fgets(buf, sizeof buf, pw) == NULL) {
                logfile(LOG_ERR, _("error reading passfile %s: %s"), optarg,
                        ferror(pw) ?
                        strerror(errno) : _("unexpected end of file"));
                fclose(pw);
                return 1;
            }
            fclose(pw);
            p = strchr(buf, '\n');
            if (p != NULL) {
                *p = 0;
            }
            if ((pass = strdup(buf)) == NULL) {
                die_mem();
            }
            break;
        }
        case 'P': {
            preempt = 1;
            break;
        }
        case 'n': {
            neutral = 1;
            break;
        }
        case 'a': {
            free(vaddr_arg);
#ifdef INET6
            free(vaddr6_arg);
            if (is_ipv6_address(optarg)) {
                /* IPv6 virtual address */
                if (parse_ipv6_cidr(optarg, &vaddr6, &vaddr6_prefix) != 0) {
                    return 1;
                }
                vaddr6_arg = strdup(optarg);
                /* Check if we already set address family from srcip */
                if (address_family != 0 && address_family != AF_INET6) {
                    logfile(LOG_ERR, _("Mixed address families: srcip is IPv4 but addr is IPv6"));
                    return 1;
                }
                address_family = AF_INET6;
            } else {
#endif
                /* IPv4 virtual address */
                if (parse_cidr(optarg, &vaddr, &vaddr_prefix) != 0) {
                    return 1;
                }
                vaddr_arg = strdup(optarg);
#ifdef INET6
                /* Check if we already set address family from srcip */
                if (address_family != 0 && address_family != AF_INET) {
                    logfile(LOG_ERR, _("Mixed address families: srcip is IPv6 but addr is IPv4"));
                    return 1;
                }
                address_family = AF_INET;
            }
#endif
            break;
        }
        case 'b': {
            advbase = (unsigned char) strtoul(optarg, NULL, 0);
            break;
        }
        case 'k': {
            advskew = (unsigned char) strtoul(optarg, NULL, 0);
            break;
        }
        case 'd': {
            free(downscript);
            if ((downscript = strdup(optarg)) == NULL) {
                die_mem();
            }
            break;
        }
        case 'D': {
            debug = 1;
            break;
        }
        case 'u': {
            free(upscript);
            if ((upscript = strdup(optarg)) == NULL) {
                die_mem();
            }
            break;
        }
        case 'r': {
            dead_ratio = (unsigned int) strtoul(optarg, NULL, 0);
            break;
        }
        case 'z': {
            shutdown_at_exit = 1;
            break;
        }
        case 'B': {
            daemonize = 1;
            break;
        }
        case 'S': {
            ignoreifstate = 1;
            break;
        }
        case 'f': {
            int n = 0;

            if (strcasecmp(optarg, "none") == 0) {
                no_syslog = 1;
                break;
            }
            while (facilitynames[n].c_name &&
                   strcasecmp(facilitynames[n].c_name, optarg) != 0) {
                n++;
            }
            if (facilitynames[n].c_name) {
                syslog_facility = facilitynames[n].c_val;
            } else {
                logfile(LOG_ERR, _("Unknown syslog facility: [%s]"), optarg);
            }
            break;
        }
        case 'x': {
            free(xparam);
            if ((xparam = strdup(optarg)) == NULL) {
                die_mem();
            }
            break;
        }
        case 'M': {
            no_mcast = 1;
            break;
        }
        default: {
            usage();
        }
        }
    }
#ifndef SAVE_DESCRIPTORS
    if (no_syslog == 0) {
        openlog("ucarp", LOG_PID, syslog_facility);
    }
#endif
    if (interface == NULL || *interface == 0) {
        interface = pcap_lookupdev(NULL);
        if (interface == NULL || *interface == 0) {
            logfile(LOG_ERR, _("You must supply a network interface"));
            return 1;
        }
        logfile(LOG_INFO, _("Using [%s] as a network interface"), interface);
    }
    if (vhid == 0) {
        logfile(LOG_ERR, _("You must supply a valid virtual host id"));
        return 1;
    }
    if (pass == NULL || *pass == 0) {
        logfile(LOG_ERR, _("You must supply a password"));
        return 1;
    }
    if (advbase == 0 && advskew == 0) {
        logfile(LOG_ERR, _("You must supply an advertisement time base"));
        return 1;
    }
#ifdef INET6
    if (address_family == AF_INET6) {
        /* IPv6 validation */
        if (IN6_IS_ADDR_UNSPECIFIED(&srcip6)) {
            logfile(LOG_ERR, _("You must supply a persistent source address"));
            return 1;
        }
        if (IN6_IS_ADDR_UNSPECIFIED(&vaddr6)) {
            logfile(LOG_ERR, _("You must supply a virtual host address"));
            return 1;
        }
    } else {
#endif
        /* IPv4 validation */
        if (srcip.s_addr == 0) {
            logfile(LOG_ERR, _("You must supply a persistent source address"));
            return 1;
        }
        if (vaddr.s_addr == 0) {
            logfile(LOG_ERR, _("You must supply a virtual host address"));
            return 1;
        }
#ifdef INET6
    }
#endif
    if (upscript == NULL) {
        logfile(LOG_WARNING, _("Warning: no script called when going up"));
    }
    if (downscript == NULL) {
        logfile(LOG_WARNING, _("Warning: no script called when going down"));
    }
    if (dead_ratio <= 0U) {
        logfile(LOG_ERR, _("Dead ratio can't be zero"));
        return 1;
    }
    dodaemonize();
    init_rand();
    if (docarp() != 0) {
        return 2;
    }

#ifndef SAVE_DESCRIPTORS
    if (no_syslog == 0) {
        closelog();
    }
#endif

    return 0;
}
