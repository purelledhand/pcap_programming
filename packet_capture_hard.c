#include<stdio.h>
#include<pcap.h>

int main(){

    char* dev;
    char errbuf[PCAP_ERRBUF_SIZE];

    dev = pcap_lookupdev(errbuf);
    printf("%s\n",dev);

    return 0;
}
