#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
// Below include files are used to use network interface and datalink layer.
#include <linux/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd
#endif

int PrintArp(struct ether_arp *arp, FILE *fp)
{
    static char *hrd[] = {
        "From KA9Q: NET/ROM pseudo.",
        "Ethernet 10/100Mbps.",
        "Experimental Ethernet.",
        "AX.25 Level 2.",
        "PROnet token ring.",
        "Chaosnet.",
        "IEEE 802.2 Ethernet/TR/TB.",
        "ARCnet.",
        "APPLEtalk.",
        "undefine",
        "undefine",
        "undefine",
        "undefine",
        "undefine",
        "undefine",
        "Frame Relay DLCI.",
        "undefine",
        "undefine",
        "undefine",
        "ATM.",
        "undefine",
        "undefine",
        "undefine",
        "Metricom STRIP (new IANA id)."};
    static char *op[] = {
        "undefined",
        "ARP request.",
        "ARP reply.",
        "RARP request.",
        "RARP reply.",
        "undefined",
        "undefined",
        "undefined",
        "InARP request.",
        "InARP reply.",
        "(ATM)ARP NAK."};
    char buf[80];
}