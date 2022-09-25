#ifndef IDS_H
#define IDS_H
/**
 * Simple Intrusion Detection System (IDS)
 * Analyzes all the packets from a file and generates alearts based on
 * provided rules
 * 
 * Rule format: 
 * <src IP address> <src port> <dst IP address> <dst port> "ALERT MESSAGE"
 * 
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>

#define RULE_NUM_DEFAULT 128
#define IDS_SRC_IP 0
#define IDS_SRC_PORT 1
#define IDS_DST_IP 2
#define IDS_DST_PORT 3
#define IDS_ALERT 4
#define IDS_NO_MASK 0   //sugkrine ola ta bits
#define IDS_IGNORE_RULE -1

#define LINE_SIZE 2048

/* ethernet header size, always 14 bytes, datalink header */
#define SIZE_ETHERNET 14

/* Ethernet addresses are always 6 bytes */
#define ETHER_ADDR_LEN 6

/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
    u_short ehter_type;                 /*IP? vsk IP 8elw mono*/  
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* don't fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

/*  */
extern int custom_filter_file;

extern struct in_addr *IDS_src_ip; 

extern unsigned int *IDS_src_port;
extern struct in_addr *IDS_dst_ip;
extern unsigned int *IDS_dst_port;
extern char** alerts;


extern int *src_mask;
extern int *dst_mask;

extern int rule_counter;

void argument_check(int argc, char const *argv[]);

void IDS_packet_handler(
    u_char                   *args,
    const struct pcap_pkthdr *packet_header,        //pakcet header
    const u_char             *packet_body    //first byte of the packet
);

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);

/**
 * Parses the Rule file and stores the rules into an array of strings
 * The number of rules is stored into rule_count arg 
 */
void parse_rules(FILE** fp);

      
/**
 * Set the by assigning the values from the format to arrays 
 * thus making it easier to compare
 */
void setRule(const char* line, int size);

void init();

void compare_with_rules(char* src_ip, char* dst_ip, uint16_t src_port, uint16_t dst_port);

//debug
void print_rules();

#endif