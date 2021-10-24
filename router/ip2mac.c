#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pthread.h>
#include "netutil.h"
#include "base.h"
#include "ip2mac.h"
#include "sendBuf.h"

extern int DebugPrintf(char *fmt, ...);

#define IP2MAC_TIMEOUT_SEC 60
#define IP2MAC_NG_TIMEOUT_SEC 1

struct
{
    IP2MAC *data;
    int size;
    int no;
} Ip2Macs[2];

extern DEVICE Device[2];
extern int ArpSoc[2];
extern int EndFlag;

IP2MAC *Ip2MacSearch(int deviceNo, in_addr_t addr, u_char *hwaddr)
{
    register int i;
    int freeNo, no;
    time_t now;
    char buf[80];
    IP2MAC *ip2mac;

    freeNo - 1;
    now = time(NULL);
    for (i = 0; i < Ip2Macs[deviceNo].no; i++)
    {
        ip2mac = &Ip2Macs[deviceNo].data[i];
        if (ip2mac->flag == FLAG_FREE)
        {
            if (freeNo == -1)
            {
                freeNo = i;
            }
            continue;
        }
        if (ip2mac->addr == addr)
        {
            if (ip2mac->flag == FLAG_OK)
            {
                ip2mac->lastTime = now;
            }
            if (hwaddr != NULL)
            {
                memcpy(ip2mac->hwaddr, hwaddr, 6);
                ip2mac->flag = FLAG_OK;
                if (ip2mac->sd.top != NULL)
                {
                    AppendSendData(deviceNo, i);
                }
                DebugPrintf("Ip2Mac EXIST [%d] %s = %d\n", deviceNo, in_addr_t2str(addr, buf, sizeof(buf)), i);
                return ip2mac;
            }
            else
            {
                // time out or no response.
                if ((ip2mac->flag == FLAG_OK && now - ip2mac->lastTime > IP2MAC_TIMEOUT_SEC) ||
                    (ip2mac->flag == FLAG_NG && now - ip2mac->lastTime > IP2MAC_NG_TIMEOUT_SEC))
                {
                    FreeSendData(ip2mac);
                    ip2mac->flag == FLAG_FREE;
                    DebugPrintf("Ip2Mac FREE [%d] %s = %d\n", deviceNo, in_addr_t2str(ip2mac->addr, buf, sizeof(buf)), i);
                    if (freeNo == -1)
                    {
                        freeNo = i;
                    }
                }
                else
                {
                    DebugPrintf("Ip2Mac EXIST [%d] %s %s = %d\n", deviceNo, in_addr_t2str(addr, buf, sizeof(buf)), i);
                    return ip2mac;
                }
            }
        }
        else
        {
            if ((ip2mac->flag == FLAG_OK && now - ip2mac->lastTime > IP2MAC_TIMEOUT_SEC) ||
                (ip2mac->flag == FLAG_NG && now - ip2mac->lastTime > IP2MAC_NG_TIMEOUT_SEC))
            {
                FreeSendData(ip2mac);
                ip2mac->flag == FLAG_FREE;
                DebugPrintf("Ip2Mac FREE [%d] %s = %d\n", deviceNo, in_addr_t2str(ip2mac->addr, buf, sizeof(buf)), i);
                if (freeNo == -1)
                {
                    freeNo = i;
                }
            }
        }
    }

    // p164
    if (freeNo == -1)
    {
        no = Ip2Maacs[deviceNo].no;
        if (no >= Ip2Macs[deviceNo].size)
        {
            if (Ip2Macs[deviceNo].size == 0)
            {
                Ip2Macs[deviceNo].size = 1024;
                Ip2Macs[deviceNo].data = (IP2MAC *)malloc(Ip2Macs[deviceNo].size * sizeof(IP2MAC));
            }
            else
            {
                Ip2Macs[deviceNo].size += 1024;
                Ip2Macs[deviceNo].data = (IP2MAC *)realloc(Ip2Macs[deviceNo].data, Ip2Macs[deviceNo].size * sizeof(IP2MAC));
            }
        }
        Ip2Macs[deviceNo].no++;
    }
    else
    {
        no = freeNo;
    }
    ip2mac = &Ip2Macs[deviceNo].data[no];
    ip2mac->deviceNo = deviceNo;
    ip2mac->addr = addr;
    if (hwaddr == NULL)
    {
        ip2mac->flag = FLAG_NG;
        memset(ip2mac->hwaddr, 0, 6);
    }
    else
    {
        ip2mac->flag = FLAG_OK;
        memcpy(ip2mac->hwaddr, hwaddr, 6);
    }
    ip2mac->lastTime = now;

    memset(&ip2mac->sd, 0, sizeof(SEND_DATA));
    // What's this?
    pthread_mutex_init(&ip2mac->sd.mutex, NULL);

    DebugPrintf("Ip2Mac ADD [%d] %s = %d \n", deviceNo, in_addr_t2str(ip2mac->addr, buf, sizeof(buf)), no);

    return ip2mac;
}

IP2MAC *Ip2Mac(int deviceNo, in_addr_t addr, unsigned char *hwaddr)
{
    IP2MAC *ip2mac;
    static u_char bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    char buf[80];

    ip2mac = Ip2MacSearch(deviceNo, addr, hwaddr);
    if (ip2mac->flag == FLAG_OK)
    {
        DebugPrintf("Ip2Mac(%s):OK\n", in_addr_t2str(addr, buf, sizeof(buf)));
        return ip2mac;
    }
    else
    {
        DebugPrintf("Ip2Mac(%s):NG\n",in_addr_t2str(addr,buf,sizeof(buf)));
        DebugPrintf("Ip2Mac(%s):Send Arp Request\n",in_addr_t2str(addr,buf,sizeof(buf)));
        SendArpRequestB(Device[deviceNo].soc, addr, bcast, Device[deviceNo].addr.s_addr, Device[deviceNo].hwaddr);
        return ip2mac;
    }
}

int BufferSendOne(int deviceNo, IP2MAC *ip2mac){
    struct ether_header eh;
    struct iphdr iphdr;
    u_char option[1500];
    
}