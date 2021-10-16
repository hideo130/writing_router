#include <stdint.h>

#include <sys/socket.h>
#define TCPDUMP_MAGIC 0xa1b2c3d4
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4
#define DLT_EN10MB 1 /*Ethernet(10Mb) */
int InitServerSocket();
struct pcap_file_header
{
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t linktype;
};

struct pcap_pkthdr
{
    struct timeval ts; //timestanp
    uint32_t caplen;   /* got packet length */
    uint32_t len;
};
