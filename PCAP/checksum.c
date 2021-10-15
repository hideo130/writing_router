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


u_int16_t checksum(u_char *data, int len){
    register u_int32_t sum;
    register u_int16_t *ptr;
    register int c;

    sum=0;
    ptr =(u_int16_t *)data;

    for(c=len;c>1;c-=2){
        sum+=(*ptr);
        if(sum & 0x80000000){
            sum = (sum & 0xFFFF) + (sum >>16);
        }
        ptr++;
    }
    if(c==1){
        u_int16_t val;
        val=0;
        memcpy(&val, ptr, sizeof(u_int8_t));
        sum+=val;
    }
    while (sum>>16)
    {       
        sum = (sum&0xFFFF)+ (sum>>16);
    }
    
    return ~sum;
}
