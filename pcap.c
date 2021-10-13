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
#include "analyze.h"
#include "checksum.h"
#include "print.h"

/* Ethernet protocol ID's */
#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd
#endif

int InitRawSocket(char *device, int promiscFlag, int ipOnly)
{
    struct ifreq ifreq;
    struct sockaddr_ll sa;
    int soc;

    if (ipOnly)
    {
        // First argument of socket() specified protocol family.
        // If we use TCP or UDP, then we set PF_INET or PF_INET6.
        //  For datalink layer, we specify PF_PACKET.
        if ((soc = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)
        {
            perror("socket");
            return -1;
        }
    }
    else
    {
        if ((soc = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
        {
            perror("socket");
            return -1;
        }
    }

    memset(&ifreq, 0, sizeof(struct ifreq));
    strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name) - 1);

    if (ioctl(soc, SIOCGIFINDEX, &ifreq) < 0)
    {
        perror("ioctl");
        close(soc);
        return -1;
    }

    sa.sll_family = PF_PACKET;

    if (ipOnly)
    {
        sa.sll_protocol = htons(ETH_P_IP);
    }
    else
    {
        sa.sll_protocol = htons(ETH_P_ALL);
    }
    sa.sll_ifindex = ifreq.ifr_ifindex;
    if (bind(soc, (struct sockaddr *)&sa, sizeof(sa)) < 0)
    {
        perror("bind");
        close(soc);
        return -1;
    }

    if (promiscFlag)
    {
        if (ioctl(soc, SIOCGIFFLAGS, &ifreq) < 0)
        {
            perror("ioctl");
            close(soc);
            return -1;
        }
    }

    ifreq.ifr_flags = ifreq.ifr_flags | IFF_PROMISC;

    if (ioctl(soc, SIOCGIFFLAGS, &ifreq) < 0)
    {
        perror("ioctl");
        close(soc);
        return -1;
    }

    return soc;
}

int AnalyzeArp(u_char *data, int size)
{
    u_char *ptr;
    int lest;
    struct ether_arp *arp;

    ptr = data;
    lest = size;

    if (lest < sizeof(struct ether_arp))
    {
        fprintf(stderr, "lest(%d) < sizeof(struct eher_arp)¥n", lest);
        return -1;
    }
    arp = (struct ether_arp *)ptr;
    ptr+=sizeof(struct ether_arp);
    lest -= sizeof(struct ether_arp);

    PrintArp(arp, stdout);

    return 0;
}