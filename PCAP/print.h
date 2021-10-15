char *my_ether_ntoa_r(u_char *hwaddr, char *buf, socklen_t size);
char *arp_ip2str(uint8_t *ip, char *buf, socklen_t size);
char *ip_ip2str(u_int32_t ip, char *buf, socklen_t size);
int PrintArp(struct ether_arp *arp, FILE *fp);
int PrintEtherHeader(struct ether_header *eh, FILE *fp);
int PrintIpHeader(struct iphdr *iphdr, u_char *option, int optionLen, FILE *fp);
int PrintIcmp(struct icmp *icmp, FILE *fp);