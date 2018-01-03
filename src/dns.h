/**
 * from
 *    https://opensource.apple.com/source/ChatServer/ChatServer-260/jabberd2/resolver/dns.c
 */

#ifndef NETWORK_ANALYZER_DNS_H
#define NETWORK_ANALYZER_DNS_H


// this file contains the dns structure for the main fields

//max size of the url in queries/answers
#define MAX_URL_SIZE 256


struct dns_header {
    unsigned        tid :16;         /* query identification number */
#if BYTE_ORDER == BIG_ENDIAN
    /* fields in third byte */
    unsigned        qr: 1;          /* response flag */
    unsigned        opcode: 4;      /* purpose of message */
    unsigned        aa: 1;          /* authoritive answer */
    unsigned        tc: 1;          /* truncated message */
    unsigned        rd: 1;          /* recursion desired */
    /* fields in fourth byte */
    unsigned        ra: 1;          /* recursion available */
    unsigned        unused :3;      /* unused bits (MBZ as of 4.9.3a3) */
    unsigned        rcode :4;       /* response code */
#endif
#if BYTE_ORDER == LITTLE_ENDIAN
    /* fields in third byte */
    unsigned        rd :1;          /* recursion desired */
    unsigned        tc :1;          /* truncated message */
    unsigned        aa :1;          /* authoritive answer */
    unsigned        opcode :4;      /* purpose of message */
    unsigned        qr :1;          /* response flag */
    /* fields in fourth byte */
    unsigned        rcode :4;       /* response code */
    unsigned        unused :3;      /* unused bits (MBZ as of 4.9.3a3) */
    unsigned        ra :1;          /* recursion available */
#endif
    /* remaining bytes */
    unsigned        qdcount :16;    /* number of question entries */
    unsigned        ancount :16;    /* number of answer entries */
    unsigned        nscount :16;    /* number of authority entries */
    unsigned        arcount :16;    /* number of resource entries */
};

#endif //NETWORK_ANALYZER_DNS_H