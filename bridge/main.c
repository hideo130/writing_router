#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include "netutil.h"

typedef struct
{
    char *Device1;
    char *Device2;
    int DebugOut;
} PARAMS;

PARAMS Param = {"eth0", "eth1", 0};

typedef struct
{
    int soc;
} DEVICE;

DEVICE Device[2];

int EndFlag = 0;

int DebugPrintf(char *fmt, ...)
{
    if (Param.DebugOut)
    {
        // va_list is variable length list, in Japanese "可変長リスト"
        va_list args;

        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);
    }

    return 0;
}

int main(int argc, char *argv[], char *envp[])
{
}