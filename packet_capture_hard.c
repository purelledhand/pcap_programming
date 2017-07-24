#include<stdio.h>
#include<pcap.h>
#include "netinet/ip.h"
#include "netinet/tcp.h"
#include "arpa/inet.h"
#include <net/ethernet.h>
#include <stdint.h>

int main(int argc, char* argv[]){
    struct ether_header *ep;
    struct ip *iph;
    struct tcphdr *tcph;
    char *data;
    char src_ip_buf[50];
    char dst_ip_buf[50];
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    struct pcap_pkthdr *header;
    int data_offset;
    uint16_t ether_type;
   
    handle = pcap_open_live(argv[1], 1000, 0, -1, errbuf);
    if(argv[1] == NULL) {
     printf("you haven't inputted interface name\n");
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

    ep = (struct ether_header *)packet;
    iph = (struct ip *)(packet+14); // 14 is ethernet header size
    tcph = (struct tcphdr *)(packet+14+iph->ip_hl*4);

    ether_type = ntohs(ep->ether_type);
    if(iph->ip_p != IPPROTO_TCP) continue;
    if( ether_type == ETHERTYPE_IP ){
    ++cnt;
    printf("=====Packet #%d=====\n",cnt);
    
    printf("Src MAC : ");
    for(int i=0;i<6;i++){
      printf("%.02x ", ep->ether_shost[i]);
    }
    printf("\nDst MAC : ");
    for(int i=0;i<6;i++){
      printf("%.02x ", ep->ether_dhost[i]);
    }

    inet_ntop(AF_INET,(&iph->ip_src),src_ip_buf,sizeof(src_ip_buf));
    inet_ntop(AF_INET,(&iph->ip_dst),dst_ip_buf,sizeof(dst_ip_buf));
    printf("\nSrc IP : %s",src_ip_buf);
    printf("\nDst IP : %s",dst_ip_buf);
    
    printf("\nSrc PORT : %d\n", ntohs(tcph->source));
    printf("Dst PORT : %d\n", ntohs(tcph->dest));

    printf("=========DATA=========\n");
    data_offset = iph->ip_len - (iph->ip_hl*4 + tcph->th_off*4);
    for(int i=(iph->ip_len - data_offset);i<150;i++){
      printf("%.02x",packet[i]);
      if(i%16==0) printf("\n");
    }

    printf("\n\n");
    }
    }

    return 0;
}

