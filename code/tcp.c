#include "tcp.h"

void handle_tcp(const u_char* packet) {
	struct tcphdr* tcp_hdr;
	tcp_hdr = (struct tcphdr*) (packet);

	int sport;
	int dport;
	u_char flag;
	u_long seq;
	u_long ack;
	int hlen;
	int wsize;

	fprintf(stdout, "\t\tTCP\n");

	//src port
	sport = ntohs(tcp_hdr->th_sport);
	fprintf(stdout, "\t\t\tSrc port: %d\n", sport);

	//dest port
	dport = ntohs(tcp_hdr->th_dport);
	fprintf(stdout, "\t\t\tDest port: %d\n", ntohs(tcp_hdr->th_dport));

	//seq number
	printf("\t\t\tSeq: %d | ", ntohs(tcp_hdr->th_seq));

	//ack number
	printf("Ack: %d | ", ntohs(tcp_hdr->th_ack));

	//header length
	hlen = (int)tcp_hdr->th_off;
	printf("Header length: %d | ", hlen);

	//flag
	flag = tcp_hdr->th_flags;
	printf("Flags: ");

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
		printf("URG");
	printf("| ");

	// window size
	wsize = tcp_hdr->th_win;
	printf("Window size: %u | \n", ntohs(wsize));

	// options;
	if (hlen > 5) {
		printf("\t\t\tOptions: ");
		int data_offset = 4 * hlen; 				// number of bytes (32 bits = 4 bytes)
		const u_char* end = packet + data_offset; 	// end of the options
		packet += sizeof(struct tcphdr);			// shift the start (20 bytes)

		while(packet < end) {
			int type = *packet++; 	// type of the option
			int length = 0;			// size of the options

			//size is null for options 0 & 1
			if(type != 0 && type != 1)
				length = *packet++;

			printf("%d - ", type);
			switch(type) {
				case 0:
					printf("End of options" );
					break;
				case 1:
					printf("No operation");
					break;
				case 2:
					printf("MSS ");
					break;
				case 3:
					printf("Window scale ");
					break;
				case 4:
					printf("SACK permited ");
					break;
				case 5:
					printf("SACK ");
					break;
				case 8:
					printf("Timestamps ");
					break;
				default:
					printf("Unknown ");
					break;
			}
			printf(" | " );

			// shift the size of the option
			if(type != 0 && type != 1)
				packet += length - 2;
		}
		printf("\n");
	}

	// 80 : HTTP
	// 443 : HTTPS
	// 23 : Telnet
	// 587 : SMTPS
	// 25 : SMTPS
	// 22 : FTP data
	// 21 : FTP requetes
	// 110 : POP3
	// 143 : IMAP
	printf("\t\t\t");
	if (sport == 80 || dport == 80)
		printf("HTTP\n");
	else if (sport == 443 || dport == 443)
		printf("HTTPS\n");
	else if (sport == 23 || dport == 23)
		printf("TELNET\n");
	else if (sport == 587 || dport == 587)
		printf("SMTPS\n");
	else if (sport == 25 || dport == 25)
		printf("SMTP\n");
	else if (sport == 22 || dport == 22)
		printf("FTP data\n");
	else if (sport == 21 || dport == 21)
		printf("FTP requetes\n");
	else if (sport == 110 || dport == 110)
		printf("POP3\n");
	else if (sport == 143 || dport == 143)
		printf("IMAP\n");
	else
		printf("Unknown protocol\n");

}
