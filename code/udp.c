#include "udp.h"

void handle_udp(const u_char* packet, int payload_size) {
	printf("\t\tUDP\n" );

	struct udphdr *udp_hdr;
	udp_hdr = (struct udphdr*) (packet);
	u_short sport;
	u_short dport;
	short length;
	u_short checksum;

	//src port
	sport = ntohs(udp_hdr->source);
	fprintf(stdout, "\t\t\tSrc port: %d\n", sport);

	//dest port
	dport = ntohs(udp_hdr->dest);
	fprintf(stdout, "\t\t\tDest port: %d\n", dport);

	//length
	length = ntohs(udp_hdr->len);
	fprintf(stdout, "\t\t\tlen: %d | ", length);

	//Checksum
	checksum = ntohs(udp_hdr->check);
	printf("sum: 0x%x\n", checksum);



}
