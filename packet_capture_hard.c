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
    int datasize;
    unsigned short ether_type;
   
    dev = pcap_lookupdev(errbuf);
    printf("interface name : %s\n",dev);

    handle = pcap_open_live(dev, 1000, 0, -1, errbuf);
    if(handle == NULL) {
     return 0;
    }
    
    int packet_status = 0;
    int cnt = 0;

    while(1){
    packet += sizeof(struct ether_header);
    packet_status = pcap_next_ex(handle, &header, &packet);
    if(packet_status == 0)
      continue;
    else if(packet_status == -1 || packet_status == -2)
      return 0;

    ep = (struct ether_header *)packet;
    iph = (struct ip *)packet;
    ether_type = ntohs(ep->ether_type);

    if( ether_type == ETHERTYPE_IP && packet[23] == IPPROTO_TCP ){
    ++cnt;
    printf("=====Packet #%d=====\n",cnt);
    
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

    printf("DATA\n");
    datasize = iph->ip_len - (iph->ip_hl - packet[12+iph->ip_hl+12]);
    for(int i=(iph->ip_len - datasize);i<30;i++){
      printf("%.02x",packet[i]);
    }

    printf("\n\n");
    }
    }

    return 0;
}

