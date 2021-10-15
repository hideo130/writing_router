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

struct pseudo_ip
{
    struct in_addr ip_src;
    struct in_addr ip_dst;
    unsigned char dummy;
    unsigned char ip_p;
    unsigned short ip_len;
};

u_int16_t checksum(u_char *data, int len)
{
    register u_int32_t sum;
    register u_int16_t *ptr;
    register int c;

    sum = 0;
    ptr = (u_int16_t *)data;

    for (c = len; c > 1; c -= 2)
    {
        sum += (*ptr);
        if (sum & 0x80000000)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        ptr++;
    }
    if (c == 1)
    {
        u_int16_t val;
        val = 0;
        memcpy(&val, ptr, sizeof(u_int8_t));
        sum += val;
    }
    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

u_int16_t checksum2(u_char *data1, int len1, u_char *data2, int len2)
{
    register u_int32_t sum;
    register u_int16_t *ptr;
    register int c;

    sum = 0;
    ptr = (u_int16_t *)data1;
    for (c = len1; c > 1; c -= 2)
    {
        sum += (*ptr);
        if (sum & 0x80000000)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        ptr++;
    }
    if (c == 1)
    {
        u_int16_t val;
        val = ((*ptr) << 8) + (*data2);
        sum += val;
        if (sum & 0x80000000)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        // why add 1, and in else statement we don't?
        ptr = (u_int16_t *)(data2 + 1);
        len2--;
    }
    else
    {
        ptr = (u_int16_t *)data2;
    }
    for (c = len2; c > 1; c -= 2)
    {
        sum += (*ptr);
        if (sum & 0x80000000)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        ptr++;
    }
    if (c == 1)
    {
        u_int16_t val;
        val = 0;
        memcpy(&val, ptr, sizeof(u_int8_t));
        sum += val;
    }

    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

int checkIPchecksum(struct iphdr *iphdr, u_char *option, int optionLen)
{
    unsigned short sum;
    if (optionLen == 0)
    {
        sum = checksum((u_char *)iphdr, sizeof(struct iphdr));
        if (sum == 0 || sum == 0xFFFF)
        {
            return 1;
        }
        else
        {
            return 0;
        }
    }
    else
    {
        sum = checksum2((u_char *)iphdr, sizeof(struct iphdr), option, optionLen);
        if (sum == 0 || sum == 0xFFFF)
        {
            return 1;
        }
        else
        {
            return 0;
        }
    }
}

int checkIPDATAchecksum(struct iphdr *iphdr, unsigned char *data, int len)
{
    struct pseudo_ip p_ip;
    unsigned short sum;

    memset(&p_ip, 0, sizeof(struct pseudo_ip));
    p_ip.ip_src.s_addr = iphdr->saddr;
    p_ip.ip_dst.s_addr = iphdr->daddr;
    p_ip.ip_p = iphdr->protocol;
    p_ip.ip_len = htons(len);

    sum = checksum2((unsigned char *)&p_ip, sizeof(struct pseudo_ip), data, len);
    // 0 of 1 complement is 0 and 0xFFFF
    if (sum == 0 || sum == 0xFFFF)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}
