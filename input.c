#include <stdio.h>
#include <string.h>
#include "capture.h"
#include <unistd.h>

#define CONFIG_BUFF_SIZE 256
char *device;

int main(int argc, char *argv[]){

    FILE *fp_config;
    pcap_if_t *interfaces;
    char error_buffer[PCAP_ERRBUF_SIZE];
    char config_buff[CONFIG_BUFF_SIZE];
    
    //Input check
    if((argc<2)||(argc>4)){
        printf("Invalid input. --help to see tips\n");
        return 2;
    }
    
    //"start" handler
    if(!strcmp (argv[1], "start")){
        if( access("capture_config", F_OK ) == 0 ) {
            //exists
            fp_config  = fopen ("capture_config", "r");
            fgets(config_buff, CONFIG_BUFF_SIZE-1, fp_config);
            device=config_buff;
            fclose(fp_config);
        } 
        else {
            //doesnt exist
            pcap_findalldevs(&interfaces,error_buffer); 
            device=(*interfaces).name;
            fp_config  = fopen ("capture_config", "w");
            fputs(device, fp_config);
            fclose(fp_config);
        }

        printf("Starting capture %s\n",device);
        capture();

       return 0;
    }

    // "show count" handler
    if((!strcmp (argv[1], "show"))&&(!strcmp (argv[3], "count"))&&(argc==4)){

        if( access("ip_stats.db", F_OK ) == 0 ) {
            //exists
            printf("Statistics for %s\n\n",argv[2]);
            show_ip_count(argv[2]);
            return 0;

        } 
        else {
            //doesnt exist
            printf("No database found. Collect statistics first.\n");
            return 2;
        }        
    }

    // "iflist" handler
    if(!strcmp (argv[1], "iflist")){
        show_devices();
        return 0;
    }

    // "current" handler
    if(!strcmp (argv[1], "current")){
        if( access("capture_config", F_OK ) == 0 ) {
            //exists
            fp_config  = fopen ("capture_config", "r");
            fgets(config_buff, CONFIG_BUFF_SIZE, fp_config);
            device=&config_buff[0];
            fclose(fp_config);
            printf("Current interface is %s\n", device);
        } else {
            //doesnt exist
            pcap_findalldevs(&interfaces,error_buffer); 
            device=(*interfaces).name;
            printf("No config found. Current interface is %s (default)\n", device);
        }
        return 0;
    }

    // "select iface" handler
    if((!strcmp (argv[1], "select"))&&(!strcmp (argv[2], "iface"))){
        
        device=argv[3];
        fp_config  = fopen ("capture_config", "w");
        char *query;
        query=concat(2,device,"");
        fputs(query, fp_config);
        fclose(fp_config);
        free(query);
        printf("Interface set as %s\n", device);
        return 0;
    }

    // "stat iface" handler
    if(!strcmp (argv[1], "stat")){

        if( access("ip_stats.db", F_OK ) == 0 ) {
            //exists
            if(argc==2){
                printf("All interfaces ststistics:\n\n");
                show_all_if_stat();
            return 0;
            }
            if(argc==3){
                printf("Statistics for %s\n\n",argv[2]);
                show_if_stat(argv[2]);
            return 0;
            }
            printf("Invalid input. --help to see tips\n");
            return 2;  
        }
        else {
            //doesnt exist
            printf("No database found. Collect statistics first.\n");
            return 2;
        }  


    }

    // "clrstat" handler
    if(!strcmp (argv[1], "clrstat")){
        clear_db();
        return 0; 
    }

    // "--help" handler
    if(!strcmp (argv[1], "--help")){
        printf("Options:\nstart - starts incoming packets capturing\nshow [IP] count - print number of packets recived from IP adress\niflist - show list of available interfaces\ncurrent - show selected interface\nselect iface [iface] - select interface for sniffing\nstat - show all colected statistics for all interfaces\nstat [iface] - show all collected statistics for interface\nclrstat - clear collected statistics\n--help  - show help information\n");    
        return 0;    
    }
    printf("Invalid input. --help to see tips\n");
    return 2;
}
