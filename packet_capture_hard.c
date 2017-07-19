#include<stdio.h>
#include<pcap.h>

int main(){
    pcap_t *handle;
    char* dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    struct pcap_pkthdr *header;

    dev = pcap_lookupdev(errbuf);
    printf("interface name : %s\n",dev);

    handle = pcap_open_live(dev, 1000, 0, -1, errbuf);
    if(handle == NULL) {
     return 0;
    }
    
    int packet_status = 0;
    while(1){
   
    packet_status = pcap_next_ex(handle, &header, &packet);
    if(packet_status == 0)
      continue;
    else if(packet_status == -1 || packet_status == -2)
      return 0;
    
    printf("%.02x\n",packet[12]);


    }

    return 0;
}

