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
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "checksum.h"
#include "print.h"

int AnalyzeArp(u_char *data, int size)
{
    u_char *ptr;
    int lest;
    struct ether_arp *arp;

    ptr = data;
    lest = size;
    // check whether we get data enough size of structure.
    if (lest < sizeof(struct ether_arp))
    {
        fprintf(stderr, "lest(%d) < sizeof(struct eher_arp)¥n", lest);
        return -1;
    }
    arp = (struct ether_arp *)ptr;
    ptr += sizeof(struct ether_arp);
    lest -= sizeof(struct ether_arp);

    PrintArp(arp, stdout);

    return 0;
}

int AnalyzePacket(u_char *date, int size){
    return 0;
}
