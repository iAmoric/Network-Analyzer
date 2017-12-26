#include "transportLayer.h"

void handle_tcp(const u_char* packet, int payload_size, int verbosity) {
	struct tcphdr* tcp_hdr;
	tcp_hdr = (struct tcphdr*) (packet);

	u_char flag;

	int data_offset = tcp_hdr->th_off * 4;
	payload_size = payload_size - data_offset;

	switch (verbosity) {

		case HIGH:
			printf("\t\tTCP\n");
			printf("\t\t\tSrc port: %d\n", ntohs(tcp_hdr->th_sport));
			printf("\t\t\tDst port: %d\n", ntohs(tcp_hdr->th_dport));
			printf("\t\t\tSeq: %d | ", ntohs(tcp_hdr->th_seq));
			printf("Ack: %d | ", ntohs(tcp_hdr->th_ack));
			printf("Header length: %d | ", tcp_hdr->th_off * 4);

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

			printf("Window size: %d | ", ntohs(tcp_hdr->th_win));
			printf("Urgent pointer: %d\n", tcp_hdr->th_urp);

			//options
			printf("\t\t\tOptions: ");
			const u_char* end = packet + data_offset; 	// end of the options
			packet += sizeof(struct tcphdr);			// shift the start (20 bytes)

			while(packet < end) {
				int type = *packet++; 					// type of the option
				int length = 0;							// size of the options

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
			break;

		case MEDIUM:
			printf("TCP, ");
			printf("Src port: %d, ", ntohs(tcp_hdr->th_sport));
			printf("Dst port: %d, ", ntohs(tcp_hdr->th_dport));
			printf("Seq: %d, ", ntohs(tcp_hdr->th_seq));
			printf("Ack: %d, ", ntohs(tcp_hdr->th_ack));
			printf("Len: %d\n", payload_size);
			packet += data_offset;
			break;

		case LOW:
			printf("TCP");
			if (ntohs(tcp_hdr->th_sport) == HTTP || ntohs(tcp_hdr->th_dport) == HTTP)
				printf("/HTTP\t");
			else if (ntohs(tcp_hdr->th_sport) == HTTPS || ntohs(tcp_hdr->th_dport) == HTTPS)
				printf("/HTTPS\t");
			else if (ntohs(tcp_hdr->th_sport) == TELNET || ntohs(tcp_hdr->th_dport) == TELNET)
				printf("/TELNET\t");
			else if (ntohs(tcp_hdr->th_sport) == SMTPS || ntohs(tcp_hdr->th_dport) == SMTPS)
				printf("/SMTPS\t");
			else if (ntohs(tcp_hdr->th_sport) == SMTP || ntohs(tcp_hdr->th_dport) == SMTP)
				printf("/SMTP\t");
			else if (ntohs(tcp_hdr->th_sport) == FTP_DATA || ntohs(tcp_hdr->th_dport) == FTP_DATA)
				printf("/FTP Dat\t");
			else if (ntohs(tcp_hdr->th_sport) == FTP_REQUEST || ntohs(tcp_hdr->th_dport) == FTP_REQUEST)
				printf("/FTP Req\t");
			else if (ntohs(tcp_hdr->th_sport) == POP3 || ntohs(tcp_hdr->th_dport) == POP3)
				printf("/POP3\t");
			else if (ntohs(tcp_hdr->th_sport) == IMAP || ntohs(tcp_hdr->th_dport) == 143)
				printf("/IMAP\t");

			//do not print the rest if HTTP and if there is data
			if ((ntohs(tcp_hdr->th_sport) == HTTP || ntohs(tcp_hdr->th_dport) == HTTP) && payload_size != 0) {
				packet += data_offset;
				break;
			}

			if ((ntohs(tcp_hdr->th_sport) == TELNET || ntohs(tcp_hdr->th_dport) == TELNET) && payload_size != 0) {
				packet += data_offset;
				break;
			}




			printf("%d -> %d ", ntohs(tcp_hdr->th_sport), ntohs(tcp_hdr->th_dport));

			//flags
			printf("[ ");
			flag = tcp_hdr->th_flags;
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
			printf("] ");

			printf("Seq=%d ", ntohs(tcp_hdr->th_seq));
			printf("Ack=%d ", ntohs(tcp_hdr->th_ack));
			printf("Len=%d ", payload_size);
			printf("Win=%d\n", ntohs(tcp_hdr->th_win));
			packet += data_offset;
			break;

		default:
			break;
	}

	if (ntohs(tcp_hdr->th_sport) == HTTP || ntohs(tcp_hdr->th_dport) == HTTP)
		handle_http(packet, payload_size, 0, verbosity);

	else if (ntohs(tcp_hdr->th_sport) == HTTPS || ntohs(tcp_hdr->th_dport) == HTTPS)
		handle_http(packet, payload_size, 1, verbosity);

	else if (ntohs(tcp_hdr->th_sport) == TELNET || ntohs(tcp_hdr->th_dport) == TELNET)
		handle_telnet(packet, payload_size, verbosity);

	else if (ntohs(tcp_hdr->th_sport) == SMTPS || ntohs(tcp_hdr->th_dport) == SMTPS)
		handle_smtp(packet, payload_size, 1, verbosity);

	else if (ntohs(tcp_hdr->th_sport) == SMTP || ntohs(tcp_hdr->th_dport) == SMTP)
		handle_smtp(packet, payload_size, 0, verbosity);

	else if (ntohs(tcp_hdr->th_sport) == FTP_DATA || ntohs(tcp_hdr->th_dport) == FTP_DATA)
		handle_ftp(packet, payload_size, 0, verbosity);

	else if (ntohs(tcp_hdr->th_sport) == FTP_REQUEST || ntohs(tcp_hdr->th_dport) == FTP_REQUEST)
		handle_ftp(packet, payload_size, 1, verbosity);

	else if (ntohs(tcp_hdr->th_sport) == POP3 || ntohs(tcp_hdr->th_dport) == POP3)
		handle_pop(packet, payload_size, verbosity);

	else if (ntohs(tcp_hdr->th_sport) == IMAP || ntohs(tcp_hdr->th_dport) == 143)
		handle_imap(packet, payload_size, verbosity);

	else
		printf("\t\t\tUnknown protocol\n");
}


void handle_udp(const u_char* packet, int payload_size, int verbosity) {

	struct udphdr *udp_hdr = (struct udphdr*) packet;

	switch (verbosity) {
		case HIGH:
			printf("\t\tUDP\n" );
			fprintf(stdout, "\t\t\tSrc port: %d\n", ntohs(udp_hdr->uh_sport));
			fprintf(stdout, "\t\t\tDest port: %d\n", ntohs(udp_hdr->uh_dport));
			fprintf(stdout, "\t\t\tlen: %d | ", ntohs(udp_hdr->uh_ulen));
			printf("sum: 0x%x\n", ntohs(udp_hdr->uh_sum));
			break;

		case MEDIUM:
			printf("UDP, ");
			printf("Src Port: %d, ", ntohs(udp_hdr->uh_sport));
			printf("Dst Port: %d\n", ntohs(udp_hdr->uh_dport));
			break;

		case LOW:
			break;

		default:
			break;
	}

	packet += sizeof(struct udphdr);

	if(ntohs(udp_hdr->uh_sport) == DNS || ntohs(udp_hdr->uh_dport) == DNS) {
        handle_dns(packet, verbosity);
    }
	if(ntohs(udp_hdr->uh_sport) == BOOTPC || ntohs(udp_hdr->uh_dport) == BOOTPC ||
	   ntohs(udp_hdr->uh_sport) == BOOTPS || ntohs(udp_hdr->uh_dport) == BOOTPS) {
        handle_bootp(packet, verbosity);
    }

}
