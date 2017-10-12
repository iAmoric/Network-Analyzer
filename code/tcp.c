#include "tcp.h"

void handle_tcp(const u_char* packet) {
	struct tcphdr* tcp_hdr;
    tcp_hdr = (struct tcphdr*) (packet);

    int sport;
    int dport;
    u_char flag;

    fprintf(stdout, "\t\tTCP\n");

    sport = ntohs(tcp_hdr->th_sport);
    fprintf(stdout, "\t\t\tSrc port: %d | ", sport);

    dport = ntohs(tcp_hdr->th_dport);
    fprintf(stdout, "Dest port: %d\n", dport);

    flag = tcp_hdr->th_flags;
    printf("\t\t\tFlags : ");

    if (flag & TH_FIN)
    	printf("FIN ");
    if (flag & TH_SYN)
    	printf("SYN ");
   	if (flag & TH_RST)
    	printf("RST ");
   	if (flag & TH_PUSH)
    	printf("PUSH ");
    if (flag & TH_ACK)
    	printf("ACK ");
    if (flag & TH_URG)
    	printf("URG ");
    printf("\n");

}