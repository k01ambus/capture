#include <stdio.h>
#include "pcap/pcap.h"
#include <unistd.h>
#include <string.h> /* for strncpy */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

char* ip_from_name(char *device)
{
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, device, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    return (inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
}

void show_devices()
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces,*temp;
    int i=0;
    pcap_findalldevs(&interfaces,error_buffer);

    printf("The interfaces present on the system are:\n\n");
    for(temp=interfaces;temp;temp=(*temp).next)
    {   
        printf("%d :%15s | %s \n",i,ip_from_name((*temp).name),(*temp).name);
        i++;
    }

}