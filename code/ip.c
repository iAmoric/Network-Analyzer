#include "ip.h"

void handle_ip(const u_char* packet) {
    struct ip* ip_hdr;
    ip_hdr = (struct ip*) (packet);

    int version;                //ip version
    int header_length;          //header length
    int type_service;           //type of service
    short total_length;         //total length
    unsigned short identifier;  //identifier
    int fragment_offset;        //fragment offset
    int time_to_live;           //time to live
    int checksum;               //checksum
    char* ip_addr;              //ip addresses, for dest and src
    int protocol;               //protocol



    version = ip_hdr->ip_v;
    //Continue only if IPv4
    if (version == 6) {
        fprintf(stdout,"\tIPv6\n");
        return;
    }
    fprintf(stdout,"\tIPv4\n");

    header_length = ip_hdr->ip_hl;
    printf("\t\thl: %d | ", header_length);

    type_service = ip_hdr->ip_tos;
    printf("tos: %d | ", type_service);

    total_length = ip_hdr->ip_len;
    printf("len: %d | ", ntohs(total_length));

    identifier = ip_hdr->ip_id;
    printf("id: %d | ", ntohs(identifier));

    //TODO check it
    fragment_offset = ip_hdr->ip_off;
    printf("off: %d | ", fragment_offset);

    time_to_live = ip_hdr->ip_ttl;
    printf("ttl: %d | ", time_to_live);

    checksum = ip_hdr->ip_sum;
    printf("sum: 0x%x\n", ntohs(ip_hdr->ip_sum));

    ip_addr = inet_ntoa(ip_hdr->ip_src);
    printf("\t\t@Src: %s\n", ip_addr);

    ip_addr = inet_ntoa(ip_hdr->ip_dst);
    printf("\t\t@Dest: %s\n", ip_addr);

    protocol = ip_hdr->ip_p;

    packet += header_length*4;
    switch (protocol) {
        case 0x06:
            handle_tcp(packet);
        break;
        case 0x11:
            handle_udp(packet);
        break;
        default:
            printf("\t\tUnsupported protocol : 0x%x\n", protocol);
        break;
    }





}
