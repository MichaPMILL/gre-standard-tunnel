#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <linux/if_tun.h>

#define TUN_NAME "GRE_REIMS"
#define TUN_IP4 "10.0.0.0"
#define TUN_IP6 "2001::"
#define REMOTE_OUTER_IP "100.64.0.0"
#define LOCAL_OUTER_IP "10.64.0.1"
#define OUTER_TTL 25
#define ETH0_MTU 1500

int tun_alloc(char *dev) {
    struct ifreq ifr;
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) { perror("open /dev/net/tun"); exit(1); }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        perror("ioctl TUNSETIFF"); close(fd); exit(1);
    }

    printf("TUN interface %s created\n", ifr.ifr_name);
    return fd;
}

unsigned short ip_checksum(void *vdata, size_t length) {
    char *data = vdata;
    uint32_t acc = 0xffff;
    for (size_t i = 0; i + 1 < length; i += 2) {
        uint16_t word;
        memcpy(&word, data + i, 2);
        acc += ntohs(word);
        if (acc > 0xffff) acc -= 0xffff;
    }
    if (length & 1) {
        uint16_t word = 0;
        memcpy(&word, data + length - 1, 1);
        acc += ntohs(word);
        if (acc > 0xffff) acc -= 0xffff;
    }
    return htons(~acc);
}

int build_gre_packet(unsigned char *outbuf, unsigned char *inner_pkt, int inner_len,
                     const char *src_ip, const char *dst_ip, unsigned char **inner_ptr) {
    struct iphdr *iph = (struct iphdr *)outbuf;
    unsigned char *gre = outbuf + sizeof(struct iphdr);

    gre[0] = 0x00; gre[1] = 0x00;
    if ((inner_pkt[0] >> 4) == 6) { 
        gre[2] = 0x86; gre[3] = 0xdd;
    } else { 
        gre[2] = 0x08; gre[3] = 0x00;
    }

    memcpy(gre + 4, inner_pkt, inner_len);
    if (inner_ptr) *inner_ptr = gre + 4;

    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + inner_len + 4);
    iph->id = htons(rand() % 65535);
    iph->frag_off = 0;
    iph->ttl = OUTER_TTL;
    iph->protocol = IPPROTO_GRE;
    iph->saddr = inet_addr(src_ip);
    iph->daddr = inet_addr(dst_ip);
    iph->check = ip_checksum(iph, sizeof(struct iphdr));

    return sizeof(struct iphdr) + inner_len + 4;
}

void send_gre_fragmented(int raw_sock, unsigned char *packet, int total_pkt_len, struct sockaddr_in *dst) {
    
    int payload_len = total_pkt_len - sizeof(struct iphdr);

    int max_payload = ETH0_MTU - sizeof(struct iphdr);
    max_payload = (max_payload / 8) * 8; 

    int offset = 0; 

    while (offset < payload_len) {
        
        int chunk = payload_len - offset;
        
        if (chunk > max_payload) {
            chunk = max_payload;
        }

        struct iphdr iph;
        memcpy(&iph, packet, sizeof(struct iphdr)); 

        iph.frag_off = htons((offset / 8) & 0x1FFF);
        
        if (offset + chunk < payload_len) {
            iph.frag_off |= htons(IP_MF);
        }

        iph.tot_len = htons(sizeof(struct iphdr) + chunk);
        iph.check = 0; 
        
        iph.check = ip_checksum(&iph, sizeof(struct iphdr));

        unsigned char buf[ETH0_MTU];
        memcpy(buf, &iph, sizeof(struct iphdr));
        
        memcpy(buf + sizeof(struct iphdr), packet + sizeof(struct iphdr) + offset, chunk);

        if (sendto(raw_sock, buf, sizeof(struct iphdr) + chunk, 0,
                   (struct sockaddr *)dst, sizeof(*dst)) < 0) {
            perror("sendto fragment");
        }

        offset += chunk;
    }
}

void send_ipv6_overlay_fragmented(int raw_sock, unsigned char *inner_pkt, int inner_len,
                                  struct sockaddr_in *dst, const char *src_ip, const char *dst_ip) {
    
    unsigned char gre_pkt[9050]; 

    int total_gre_pkt_len = build_gre_packet(gre_pkt, inner_pkt, inner_len, 
                                             src_ip, dst_ip, NULL);
    send_gre_fragmented(raw_sock, gre_pkt, total_gre_pkt_len, dst);
}

int main() {
    int tun_fd = tun_alloc(TUN_NAME);

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip addr add %s/31 dev %s", TUN_IP4, TUN_NAME);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "ip -6 addr add %s/127 dev %s", TUN_IP6, TUN_NAME);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "ip link set %s up", TUN_NAME);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "ip link set mtu 9000 dev %s", TUN_NAME);
    system(cmd);

    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sock < 0) { perror("socket"); exit(1); }

    int recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_GRE);
    if (recv_sock < 0) { perror("recv socket"); exit(1); }

    struct sockaddr_in dst;
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = inet_addr(REMOTE_OUTER_IP);

    unsigned char buf[9000], gre_pkt[9050];
    fd_set readfds;
    int maxfd = (tun_fd > recv_sock ? tun_fd : recv_sock) + 1;

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(tun_fd, &readfds);
        FD_SET(recv_sock, &readfds);

        if (select(maxfd, &readfds, NULL, NULL, NULL) < 0) { perror("select"); continue; }

        if (FD_ISSET(tun_fd, &readfds)) {
            int nread = read(tun_fd, buf, sizeof(buf));
            if (nread < 0) { perror("read tun"); continue; }

            if ((buf[0] >> 4) == 6) {
                send_ipv6_overlay_fragmented(raw_sock, buf, nread, &dst, LOCAL_OUTER_IP, REMOTE_OUTER_IP);
            } else {
                int gre_len = build_gre_packet(gre_pkt, buf, nread, LOCAL_OUTER_IP, REMOTE_OUTER_IP, NULL);
                send_gre_fragmented(raw_sock, gre_pkt, gre_len, &dst);
            }
        }

        if (FD_ISSET(recv_sock, &readfds)) {
            int nread = recv(recv_sock, gre_pkt, sizeof(gre_pkt), 0);
            if (nread < (int)(sizeof(struct iphdr) + 4)) continue;

            struct iphdr *outer_ip = (struct iphdr *)gre_pkt;
            unsigned char *gre_payload = gre_pkt + outer_ip->ihl*4;
            int inner_len = nread - outer_ip->ihl*4 - 4;
            if (inner_len > 0 && write(tun_fd, gre_payload + 4, inner_len) < 0) {
                perror("write tun");
            }
        }
    }
}

