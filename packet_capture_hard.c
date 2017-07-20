#include<stdio.h>
#include<pcap.h>
#include "netinet/ip.h"
#include "netinet/tcp.h"
#include "arpa/inet.h"
#include <netinet/in.h>
#include <net/ethernet.h>

int main(){
    pcap_t *handle;
    char* dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    struct pcap_pkthdr *header;
    struct ip *iph;
    struct tcphdr *tcph;
    struct ether_header *ep;

    dev = pcap_lookupdev(errbuf);
    printf("interface name : %s\n",dev);

    handle = pcap_open_live(dev, 1000, 0, -1, errbuf);
    if(handle == NULL) {
     return 0;
    }
    
    int packet_status = 0;
    int cnt = 0;

    while(1){
    packet_status = pcap_next_ex(handle, &header, &packet);
    if(packet_status == 0)
      continue;
    else if(packet_status == -1 || packet_status == -2)
      return 0;
    
    if((packet[12] == 0x08)&&(packet[23] == 6)){
    ++cnt;
    printf("Packet #%d\n",cnt);

    
    packet += sizeof(struct ether_header);
    ep = (struct ether_header *)packet;
    iph = (struct ip *)packet;
    
    printf("Src MAC : ");
    for(int i=0;i<6;i++){
      printf("%.02x",packet[i]);
    }
    printf("\nDst MAC : ");
    for(int i=6;i<12;i++){
      printf("%.02x",packet[i]);
    }

    printf("\nSrc IP : ");
    for(int i=26;i<30;i++){
      printf("%d",packet[i]);
    }
    printf("\nDst IP : ");
    for(int i=30;i<34;i++){
      printf("%d",packet[i]);
    }
    
    tcph = (struct tcphdr *)(packet+iph->ip_hl*4);
    printf("\nSrc PORT : %d\n", ntohs(tcph->source));
    printf("Dst PORT : %d\n", ntohs(tcph->dest));

    printf("\n");
    }
    }

    return 0;
}

