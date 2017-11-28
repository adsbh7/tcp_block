#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <libnet.h>
#include <netinet/ether.h>
#include <libnet/libnet-headers.h>

 int main(int argc, char *argv[])
 {
        int i,len;
      	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); 

        if (handle == NULL) {
                fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
                return -1;
        }

        while(1)
        {
                struct pcap_pkthdr* header;
                const u_char* packet;
		u_char* rpacket;
                int res = pcap_next_ex(handle, &header, &packet); // packet capture
		rpacket = packet;

		uint8_t ip_protocol;
		uint8_t ip_hsize;
		uint8_t tcp_hsize;
		uint16_t tcp_tmp;
		uint32_t ack_tmp;
		uint8_t flag;
		uint8_t rst_flag;
		uint8_t fin_flag;
		uint8_t data_size;
		uint16_t total_len;
		uint16_t ether_len = 0x000e;
		int check, cnt=0;

		if(res == 0) continue;
                else if(res > 0)
                {
                   
			struct libnet_ipv4_hdr * iphdr;
			struct libnet_tcp_hdr *tcphdr;
			struct libnet_ethernet_hdr * ethhdr;

			struct in_addr ip_tmp;

			ethhdr = (struct libnet_ethernet_hdr *)packet;
			iphdr = (struct libnet_ipv4_hdr *)(packet + ether_len); 

			ip_protocol = iphdr->ip_p;
			ip_hsize = iphdr->ip_hl*4;
			//printf("ip_protocol : %x\n",ip_protocol);
			if(ip_protocol == 0x6) // tcp인 경우
			{
				tcphdr = (struct libnet_tcp_hdr *)(packet + ether_len + ip_hsize);
				tcp_hsize = tcphdr->th_off*4;
				printf("---------------------------\n");
				printf("This is TCP\n");
				for(i=0;i<ether_len+ip_hsize+tcp_hsize;i++)
					printf("%x ", packet[i]);

				printf("\n");	
				
				flag = tcphdr->th_flags;
				printf("original flag : %x\n", flag);
				
				rst_flag = flag | 0x4;
				fin_flag = flag | 0x1;
				printf("rst flag : %x\n", rst_flag);
				printf("fin flag : %x\n", fin_flag);

				data_size = iphdr->ip_len - ip_hsize - tcp_hsize;
				printf("data_size : %x\n",data_size);
				
				// syn flag on			
				if (data_size == 0)	
					if(flag & 0x2 == 0x2)					
						data_size = 1;
				printf("ip_len : %x\n", iphdr->ip_len);
				total_len = iphdr->ip_len + ether_len;
				printf("total_len : %x\n",total_len);

				tcphdr->th_flags = rst_flag;
				tcphdr->th_seq += data_size;
				ack_tmp = tcphdr->th_ack;
				
				printf("seq : %x\n", tcphdr->th_seq);
				printf("ack : %x\n", tcphdr->th_ack); 			
								 
				memcpy(packet+ether_len+ip_hsize, tcphdr, sizeof(struct libnet_tcp_hdr));
				printf("-------------rst------------\n");
				
				for(i=0;i<ether_len+ip_hsize+tcp_hsize;i++)
					printf("%x ", packet[i]);
				printf("\n");
					
				check = pcap_sendpacket(handle, packet, total_len);
			
				if(check == -1)
				{
					pcap_perror(handle,0);
					pcap_close(handle);
				}

				printf("Send forward RST\n");
	
				if(strstr(packet, "GET") || strstr(packet, "POST") || strstr(packet, "HEAD") || strstr(packet, "PUT") || strstr(packet, "DELETE") || strstr(packet, "OPTIONS") != NULL)
				{
					tcphdr->th_flags = fin_flag;
					cnt = 1;
				}

				
				ip_tmp = iphdr->ip_src;
				iphdr->ip_src = iphdr->ip_dst;
				iphdr->ip_dst = ip_tmp;

				tcp_tmp = tcphdr->th_sport;
				tcphdr->th_sport = tcphdr->th_dport;
				tcphdr->th_dport = tcp_tmp;

				tcphdr->th_ack = tcphdr->th_seq;
				tcphdr->th_seq = ack_tmp;
				
		
				memcpy(rpacket+ether_len, iphdr, sizeof(struct libnet_ipv4_hdr));
				memcpy(rpacket+ether_len+ip_hsize, tcphdr, sizeof(struct libnet_tcp_hdr));

				printf("-------------rpacket------------\n");
				
				for(i=0;i<ether_len+ip_hsize+tcp_hsize;i++)
					printf("%x ", rpacket[i]);
				printf("\n");
				
				check = pcap_sendpacket(handle, rpacket, total_len);
			
				if(check == -1)
				{
					pcap_perror(handle,0);
					pcap_close(handle);
				}

				if(cnt == 1)	printf("Send backward FIN\n");

				else	printf("Send backward RST\n");
					

				
			}

			else printf("Not TCP Packet\n");

                        printf("\n");
                }

                else if (res == -1 || res == -2) break;

        }

        pcap_close(handle);
        return 0;
 }
