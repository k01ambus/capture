#include <stdio.h>
#include <time.h>
#include "pcap/pcap.h"
#include <netinet/if_ether.h>
#include "sqltools.h"
#include "iptools.h"

extern char* device;

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int capture() {

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int timeout_limit = 10000; /* In milliseconds */
	struct bpf_program filter;	
	char *filter_exp = concat(2, "dst ", ip_from_name(device));

	bpf_u_int32 subnet_mask, ip;
	
	//IP and Interface init


    /* Open device for live capture */
    handle = pcap_open_live(device, BUFSIZ, 0, timeout_limit, error_buffer);
    if (handle == NULL) {
         fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
         return 2;
    }

	/*Filter creation*/
	if (pcap_compile(handle, &filter, filter_exp, 0, ip)==-1){
		printf("Invalid filter: %s\n", pcap_geterr(handle));
		return 2;
	}

	if(pcap_setfilter(handle, &filter)==-1){
		printf("Cannot set filter: %s\n", pcap_geterr(handle));
		return 2;
	}

    pcap_loop(handle, 0, packet_handler, NULL);

    return 0;
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    struct ether_header *eth_header;
	eth_header = (struct ether_header *) packet;
	if (ntohs((*eth_header).ether_type) != ETHERTYPE_IP) {
		printf("Not an IP packet captured\n");
		return;
	}

	const u_char *ip_source;
	int ethernet_header_length = 14;
	int ip_header_source = 12;
	ip_source = packet + ethernet_header_length + ip_header_source;


	printf("IP packet captured | Source: ");
	for(int i=0;i<=3;i++){
	if(i==3) printf("%u | ",*(ip_source+i));
	else printf("%u.",*(ip_source+i));
	}
	
	printf("Destination: ");

	for(int i=4;i<=7;i++){	
	if(i==7) printf("%u\n",*(ip_source+i));
	else printf("%u.",*(ip_source+i));
	}

    char buf[16];
	sprintf(buf,"%u.%u.%u.%u",*ip_source, *(ip_source+1),*(ip_source+2),*(ip_source+3));
    put_packet_to_db(&buf[0],device);
}
