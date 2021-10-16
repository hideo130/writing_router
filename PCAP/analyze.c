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
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "checksum.h"
#include "print.h"

int AnalyzeArp(u_char *data, int size)
{
    u_char *ptr;
    int rest;
    struct ether_arp *arp;

    ptr = data;
    rest = size;
    // check whether we get data enough size of structure.
    if (rest < sizeof(struct ether_arp))
    {
        fprintf(stderr, "rest(%d) < sizeof(struct eher_arp)\n", rest);
        return -1;
    }
    arp = (struct ether_arp *)ptr;
    ptr += sizeof(struct ether_arp);
    rest -= sizeof(struct ether_arp);

    PrintArp(arp, stdout);

    return 0;
}

int AnalyzeIcmp(u_char *data, int size)
{
    u_char *ptr;
    int rest;
    struct icmp *icmp;

    ptr = data;
    rest = size;
    if (rest < sizeof(struct icmp))
    {
        fprintf(stderr, "rest(%d)<sizeof(struct icmp)\n", rest);
        return -1;
    }
    icmp = (struct icmp *)ptr;
    ptr += sizeof(struct icmp);
    rest -= sizeof(struct icmp);
    PrintIcmp(icmp, stdout);

    return 0;
}

int AnalyzeIcmp6(u_char *data, int size)
{
    u_char *ptr;
    int rest;
    struct icmp6_hdr *icmp6;

    ptr = data;
    rest = size;

    if (rest < sizeof(struct icmp6_hdr))
    {
        fprintf(stderr, "rest(%d) < sizeof(struct icmp6_hdr)", rest);
        return -1;
    }

    icmp6 = (struct icmp6_hdr *)ptr;
    ptr += sizeof(struct icmp6_hdr);
    rest -= sizeof(struct icmp6_hdr);

    PrintIcmp6(icmp6, stdout);

    return 0;
}

int AnalyzeIp(u_char *data, int size)
{
    u_char *ptr;
    int rest;
    struct iphdr *iphdr;
    u_char *option;
    int optionLen, len;
    unsigned short sum;

    ptr = data;
    rest = size;

    if (rest < sizeof(struct iphdr))
    {
        fprintf(stderr, "rest(%d) <sizeof(struct iphdr)\n", rest);
        return -1;
    }

    iphdr = (struct iphdr *)ptr;
    ptr += sizeof(struct iphdr);
    rest -= sizeof(struct iphdr);

    // unsigned int ihl:4;
    // Number after colon indicates bit size.So ihl is 4bit instead of 32 bit.
    // unsigned int is 4byte so 32bit.
    // Should I multiply 8 instead of 4. If uint is 2byte(16 bit), then I multiply 4.
    optionLen = iphdr->ihl * 4 - sizeof(struct iphdr);
    if (optionLen > 0)
    {
        if (optionLen >= 1500)
        {
            fprintf(stderr, "IP optionLen(%d):too bit\n", optionLen);
            return -1;
        }
        option = ptr;
        ptr += optionLen;
        rest -= optionLen;
    }
    if (checkIPchecksum(iphdr, option, optionLen) == 0)
    {
        fprintf(stderr, "bad ip checksum\n");
        return -1;
    }

    PrintIpHeader(iphdr, option, optionLen, stdout);

    if (iphdr->protocol == IPPROTO_ICMP)
    {
        len = ntohs(iphdr->tot_len) - iphdr->ihl * 4;
        sum = checksum(ptr, len);
        if (sum != 0 && sum != 0xFFFF)
        {
            fprintf(stderr, "bad icmp checksum\n");
            return -1;
        }
        AnalyzeIcmp(ptr, rest);
    }
    else if (iphdr->protocol == IPPROTO_TCP)
    {
        len = ntohs(iphdr->tot_len) - iphdr->ihl * 4;
        if (checkIPDATAchecksum(iphdr, ptr, len) == 0)
        {
            fprintf(stderr, "bad tcp checksum\n");
            return -1;
        }
        AnalyzeTcp(ptr, len);
    }
    else if (iphdr->protocol == IPPROTO_UDP)
    {
        struct udphdr *udphdr;
        udphdr = (struct udphdr *)ptr;
        len = ntohs(iphdr->tot_len) - iphdr->ihl * 4;
        if (udphdr->check != 0 && checkIPDATAchecksum(iphdr, ptr, len) == 0)
        {
            fprintf(stderr, "bad udp check sum");
            return -1;
        }
        AnalyzeUdp(ptr, rest);
    }

    return 0;
}

int AnalyzeIpv6(u_char *data, int size)
{
    u_char *ptr;
    int rest;
    struct ip6_hdr *ip6;
    int len;

    ptr = data;
    rest = size;

    if (rest < sizeof(struct ip6_hdr))
    {
        fprintf(stderr, "rest(%d) < sizeof(struct ip6_hdr)¥n", rest);
        return -1;
    }

    ip6 = (struct ip6_hdr *)ptr;
    ptr += sizeof(struct ip6_hdr);
    rest -= sizeof(struct ip6_hdr);

    PrintIp6Header(ip6, stdout);

    if (ip6->ip6_nxt == IPPROTO_ICMPV6)
    {
        len = ntohs(ip6->ip6_plen);
        if (checkIP6DATAchecksum(ip6, ptr, len) == 0)
        {
            fprintf(stderr, "bad icmp6 checksum\n");
            return -1;
        }
        AnalyzeIcmp6(ptr, rest);
    }
    else if (ip6->ip6_nxt == IPPROTO_TCP)
    {
        len = ntohs(ip6->ip6_plen);
        if (checkIP6DATAchecksum(ip6, ptr, len) == 0)
        {
            fprintf(stderr, "bad tcp6 checksum\n");
            return -1;
        }
        AnalyzeTcp(ptr, rest);
    }
    else if (ip6->ip6_nxt == IPPROTO_UDP)
    {
        len = ntohs(ip6->ip6_plen);
        if (checkIP6DATAchecksum(ip6, ptr, len) == 0)
        {
            fprintf(stderr, "bad udp checksum\n");
            return -1;
        }
        AnalyzeUdp(ptr, rest);
    }
    return 0;
}

int AnalyzeTcp(u_char *data, int size)
{
    u_char *ptr;
    int rest;
    struct tcphdr *tcphdr;

    ptr = data;
    rest = size;

    if (rest < sizeof(struct tcphdr))
    {
        fprintf(stderr, "rest(%d)<sizeof(struct tcphdr)\n", rest);
        return -1;
    }
    tcphdr = (struct tcphdr *)ptr;
    ptr += sizeof(struct tcphdr);
    rest -= sizeof(struct tcphdr);

    PrintTcp(tcphdr, stdout);

    return 0;
}

int AnalyzeUdp(u_char *data, int size)
{
    u_char *ptr;
    int rest;
    struct udphdr *udphdr;

    ptr = data;
    rest = size;
    if (rest < sizeof(struct udphdr))
    {
        fprintf(stderr, "rest(%d) < sizeof(struct udphdr)\n", rest);
        return -1;
    }

    udphdr = (struct udphdr *)ptr;
    ptr += sizeof(struct udphdr);
    rest -= sizeof(struct udphdr);

    PrintUdp(udphdr, stdout);

    return 0;
}

int AnalyzePacket(u_char *data, int size)
{
    u_char *ptr;
    int rest;
    struct ether_header *eh;

    ptr = data;
    rest = size;

    if (rest < sizeof(struct ether_header))
    {
        fprintf(stderr, "rest(%d) < sizeof(struct ether_header)\n", rest);
        return -1;
    }

    eh = (struct ether_header *)ptr;
    ptr += sizeof(struct ether_header);
    rest -= sizeof(struct ether_header);

    if (ntohs(eh->ether_type) == ETHERTYPE_ARP)
    {
        fprintf(stdout, "Packet[%dbytes]\n", size);
        PrintEtherHeader(eh, stdout);
        AnalyzeArp(ptr, rest);
    }
    else if (ntohs(eh->ether_type) == ETHERTYPE_IP)
    {
        fprintf(stderr, "Packet[%dbytes]\n", size);
        PrintEtherHeader(eh, stdout);
        AnalyzeIp(ptr, rest);
    }
    else if (ntohs(eh->ether_type) == ETHERTYPE_IPV6)
    {
        fprintf(stderr, "Packet[%dbytes]\n", size);
        PrintEtherHeader(eh, stdout);
        AnalyzeIpv6(ptr, rest);
    }
    return 0;
}
