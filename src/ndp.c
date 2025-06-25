/*
 * IPv6 Neighbor Discovery Protocol support for UCarp
 */

#include <config.h>
#include "ucarp.h"
#include "ndp.h"
#include "log.h"

#ifdef INET6
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

void send_na(int fd)
{
    struct ether_header eh;
    struct ip6_hdr ip6;
    struct nd_neighbor_advert na;
    struct nd_opt_hdr opt_hdr;
    unsigned char *pkt;
    size_t eth_len;
    int rc;

    logfile(LOG_DEBUG, "-> send_na() for IPv6");

    /* Calculate total packet size */
    eth_len = sizeof(eh) + sizeof(ip6) + sizeof(na) + sizeof(opt_hdr) + 6; /* 6 bytes for MAC address */

    pkt = malloc(eth_len);
    if (pkt == NULL) {
        logfile(LOG_ERR, _("Out of memory to create IPv6 NA packet"));
        return;
    }

    /* Build Ethernet header - use CARP virtual MAC (FreeBSD compatible) */
    eh.ether_shost[0] = 0x00;
    eh.ether_shost[1] = 0x00;
    eh.ether_shost[2] = 0x5e;
    eh.ether_shost[3] = 0x00;
    eh.ether_shost[4] = 0x01;  /* CARP uses 0x01 for virtual MAC */
    eh.ether_shost[5] = vhid;

    /* All-nodes multicast MAC address (33:33:00:00:00:01) */
    eh.ether_dhost[0] = 0x33;
    eh.ether_dhost[1] = 0x33;
    eh.ether_dhost[2] = 0x00;
    eh.ether_dhost[3] = 0x00;
    eh.ether_dhost[4] = 0x00;
    eh.ether_dhost[5] = 0x01;
    eh.ether_type = htons(ETHERTYPE_IPV6);

    /* Build IPv6 header */
    memset(&ip6, 0, sizeof(ip6));
    ip6.ip6_vfc = IPV6_VERSION;
    ip6.ip6_plen = htons(sizeof(na) + sizeof(opt_hdr) + 6);
    ip6.ip6_nxt = IPPROTO_ICMPV6;
    ip6.ip6_hlim = 255; /* Must be 255 for NDP */
    memcpy(&ip6.ip6_src, &vaddr6, sizeof(ip6.ip6_src)); /* Source is the VIP */
    inet_pton(AF_INET6, "ff02::1", &ip6.ip6_dst); /* All-nodes multicast */

    /* Build Neighbor Advertisement */
    memset(&na, 0, sizeof(na));
    na.nd_na_type = ND_NEIGHBOR_ADVERT;
    na.nd_na_code = 0;
    na.nd_na_cksum = 0; /* Will be calculated by kernel */
    na.nd_na_flags_reserved = ND_NA_FLAG_SOLICITED | ND_NA_FLAG_OVERRIDE;
    memcpy(&na.nd_na_target, &vaddr6, sizeof(na.nd_na_target));

    /* Build Target Link-Layer Address option */
    opt_hdr.nd_opt_type = ND_OPT_TARGET_LINKADDR;
    opt_hdr.nd_opt_len = 1; /* Length in units of 8 bytes */

    /* Assemble the packet */
    memcpy(pkt, &eh, sizeof(eh));
    memcpy(pkt + sizeof(eh), &ip6, sizeof(ip6));
    memcpy(pkt + sizeof(eh) + sizeof(ip6), &na, sizeof(na));
    memcpy(pkt + sizeof(eh) + sizeof(ip6) + sizeof(na), &opt_hdr, sizeof(opt_hdr));
    /* Copy MAC address after the option header */
    memcpy(pkt + sizeof(eh) + sizeof(ip6) + sizeof(na) + sizeof(opt_hdr), eh.ether_shost, 6);

    /* Send the packet */
    do {
        rc = write(fd, pkt, eth_len);
    } while (rc < 0 && errno == EINTR);
    
    if (rc < 0) {
        logfile(LOG_WARNING, _("write() has failed for IPv6 NA: %s"), strerror(errno));
    } else {
        logfile(LOG_DEBUG, _("* IPv6 Neighbor Advertisement sent *"));
        logfile(LOG_INFO, _("IPv6 CARP takeover: sent unsolicited NA - may take up to 30s for routers to update neighbor tables"));
    }

    free(pkt);
}
#endif /* INET6 */
