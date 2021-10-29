#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>

extern int DebugPrintf(char *fmt, ...);
extern int DebugPerror(char *msg);

int InitRawSocket(char *device, int promiscFlag, int ipOnly)
{
    struct ifreq ifreq;
    struct sockaddr_ll sa;
    int soc;

    int targetPacket;
    if (ipOnly)
    {
        targetPacket = ETH_P_IP;
    }
    else
    {
        targetPacket = ETH_P_ALL;
    }

    if ((soc = socket(PF_PACKET, SOCK_RAW, htons(targetPacket))) < 0)
    {
        perror("socket");
        return -1;
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

int GetDeviceInfo(char *device, u_char hwaddr[6], struct in_addr *uaddr, struct in_addr *subnet, struct in_addr *mask)
{
    struct ifreq ifreq;
    struct sockaddr_in addr;
    int soc;
    u_char *p;

    if ((soc = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
    {
        DebugPerror("socket");
        return -1;
    }

    memset(&ifreq, 0, sizeof(struct ifreq));
    strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name) - 1);

    DebugPrintf("%s\n", ifreq.ifr_name);
    DebugPrintf("%s\n", device);
    // hwaddr is not assigned
    DebugPrintf("%s\n", hwaddr);

    if (ioctl(soc, SIOCGIFHWADDR, &ifreq) == -1)
    {
        DebugPerror("ioctl");
        close(soc);
        return -1;
    }
    else
    {
        p = (u_char *)&ifreq.ifr_hwaddr.sa_data;
        memcpy(hwaddr, p, 6);
    }

    if (ioctl(soc, SIOCGIFADDR, &ifreq) == -1)
    {
        // If "Cannot assign requested address" is occured, 
        // then we does not assign IP address to device.
        DebugPrintf("get PA address error\n");
        DebugPerror("ioctl");
        close(soc);
        return -1;
    }
    else if (ifreq.ifr_addr.sa_family != PF_INET)
    {
        DebugPrintf("%s not PF_INET\n", device);
        close(soc);
        return -1;
    }
    else
    {
        memcpy(&addr, &ifreq.ifr_addr, sizeof(struct sockaddr_in));
        *uaddr = addr.sin_addr;
    }

    if (ioctl(soc, SIOCGIFNETMASK, &ifreq) == -1)
    {
        DebugPrintf("ioctl");
        close(soc);
        return -1;
    }
    else
    {
        memcpy(&addr, &ifreq.ifr_addr, sizeof(struct sockaddr_in));
        *mask = addr.sin_addr;
    }

    subnet->s_addr = ((uaddr->s_addr) & (mask->s_addr));
    close(soc);
    return 0;
}

char *my_ether_ntoa_r(u_char *hwaddr, char *buf, socklen_t size)
{
    snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x", hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
    return (buf);
}

char *my_inet_ntoa_r(struct in_addr *addr, char *buf, socklen_t size)
{
    inet_ntop(PF_INET, addr, buf, size);
    return buf;
}

char *in_addr_t2str(in_addr_t addr, char *buf, socklen_t size)
{
    struct in_addr a;
    a.s_addr = addr;
    inet_ntop(PF_INET, &a, buf, size);

    return buf;
}

int PrintEtherHeader(struct ether_header *eh, FILE *fp)
{
    char buf[80];
    fprintf(fp, "ether_header------------------------------\n");
    fprintf(fp, "ether_dhost%s\n", my_ether_ntoa_r(eh->ether_dhost, buf, sizeof(buf)));
    fprintf(fp, "ether_shost%s\n", my_ether_ntoa_r(eh->ether_shost, buf, sizeof(buf)));
    fprintf(fp, "ether_type=%02X", ntohs(eh->ether_type));

    // Ethernet Protocol ID's
    switch (ntohs(eh->ether_type))
    {
    case ETH_P_IP:
        fprintf(fp, "(IP)\n");
        break;
    case ETH_P_ARP:
        fprintf(fp, "(ARP)\n");
        break;
    default:
        fprintf(fp, "(unknown or not supported)\n");
        break;
    }

    return 0;
}

typedef struct
{
    struct ether_header eh;
    struct ether_arp arp;
} PACKET_ARP;

int SendArpRequestB(int soc, in_addr_t target_ip, unsigned char target_mac[6], in_addr_t my_ip, unsigned char my_mac[6])
{
    PACKET_ARP arp;
    int total;
    u_char *p;
    u_char buf[sizeof(struct ether_header) + sizeof(struct ether_arp)];
    union
    {
        unsigned long l;
        u_char c[4];
    } lc;

    int i;

    arp.arp.arp_hrd = htons(ARPHRD_ETHER);
    arp.arp.arp_pro = htons(ETHERTYPE_IP);
    arp.arp.arp_hln = 6;
    arp.arp.arp_pln = 4;
    arp.arp.arp_op = htons(ARPOP_REQUEST);

    for (i = 0; i < 6; i++)
    {
        arp.arp.arp_sha[i] = my_mac[i];
    }

    for (i = 0; i < 6; i++)
    {
        arp.arp.arp_tha[i] = 0;
    }

    lc.l = my_ip;
    for (i = 0; i < 4; i++)
    {
        arp.arp.arp_spa[i] = lc.c[i];
    }

    lc.l = target_ip;
    for (i = 0; i < 4; i++)
    {
        arp.arp.arp_tpa[i] = lc.c[i];
    }

    for (i = 0; i < 6; i++)
    {
        arp.eh.ether_dhost[i] = target_mac[i];
    }

    for (i = 0; i < 6; i++)
    {
        arp.eh.ether_shost[i] = my_mac[i];
    }

    arp.eh.ether_type = htons(ETHERTYPE_ARP);
    memset(buf, 0, sizeof(buf));
    p = buf;

    memcpy(p, &arp.eh, sizeof(struct ether_header));
    p += sizeof(struct ether_header);

    memcpy(p, &arp.arp, sizeof(struct ether_arp));
    p += sizeof(struct ether_arp);

    total = p - buf;

    write(soc, buf, total);
    return 0;
}