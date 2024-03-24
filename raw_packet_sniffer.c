/*
created by Rohit
*/



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/stat.h>

#define MAX_SIZE 65536
#define MAX_PACKET_SIZE 2000

void analysePacket(unsigned char* buffer, int size);

int main() {
    int sock_raw;
    int data_size;
    struct sockaddr saddr;
    int saddr_size = sizeof(saddr);
    unsigned char* buffer = (unsigned char*)malloc(MAX_PACKET_SIZE);

    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0) {
        perror("Socket Error");
        return 1;
    }

    printf("Starting packet sniffing...\n");

    // Open the file to write the output
    int fd = open("raw_packetSniffer.txt", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd < 0) {
        perror("Error opening file");
        return 1;
    }

    // Redirect stdout to the file descriptor
    if (dup2(fd, 1) < 0) {
        perror("Error redirecting stdout");
        return 1;
    }

    // Variables to track segmented packets and total length
    int segmented_packets = 0;
    int total_length = 0;


    while (total_length < MAX_SIZE) {
        data_size = recvfrom(sock_raw, buffer, MAX_PACKET_SIZE, 0, &saddr, (socklen_t*)&saddr_size);
        if (data_size < 0) {
            printf("Error in packet capture\n");
            return 1;
        }

        // Update counts
        total_length += data_size;
        analysePacket(buffer, data_size);

    }

    close(sock_raw);
    printf("Packet sniffing finished.\n");

    // Print counts
    printf("Total length of packets received: %d\n", total_length);

    // Close the file descriptor
    close(fd);

    return 0;
}



void printPayload(unsigned char* buffer, int size, int payload_offset) {
    // Calculate the payload size
    int payload_size = size - payload_offset;

    // Print the payload data
    printf("Payload Data:\n");
    for (int i = payload_offset; i < size; i++) {
        printf("%02X ", buffer[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n\n\n");
}



void printTCP(unsigned char* buffer, int size, int payload_offset) {
    struct tcphdr* tcp = (struct tcphdr*)(buffer + payload_offset);
    if (size < payload_offset + 20){
        printf("\nNo TCP Header Found\n");
    	return;
    }
        printf("\nTCP Header\n");
        printf("   |-Source Port       : %d\n", ntohs(tcp->source));
        printf("   |-Destination Port  : %d\n", ntohs(tcp->dest));
        printf("   |-Sequence Number   : %u\n", ntohl(tcp->seq));
        printf("   |-Acknowledge Number: %u\n", ntohl(tcp->ack_seq));
        printf("   |-Header Length     : %d DWORDS or %d Bytes\n", (unsigned int)tcp->doff, (unsigned int)tcp->doff * 4);
        printf("   |-Flags             :");
        printf("       |-URG: %d\n", (unsigned int)tcp->urg);
        printf("       |-ACK: %d\n", (unsigned int)tcp->ack);
        printf("       |-PSH: %d\n", (unsigned int)tcp->psh);
        printf("       |-RST: %d\n", (unsigned int)tcp->rst);
        printf("       |-SYN: %d\n", (unsigned int)tcp->syn);
        printf("       |-FIN: %d\n", (unsigned int)tcp->fin);
        printf("   |-Window Size       : %d\n", ntohs(tcp->window));
        printf("   |-Checksum          : %d\n", ntohs(tcp->check));
        printf("   |-Urgent Pointer    : %d\n", tcp->urg_ptr);
    

    // Calculate the TCP header length in bytes
    int tcp_header_length = (unsigned int)tcp->doff * 4;
    
    payload_offset += tcp_header_length;
    printPayload(buffer, size, payload_offset);
}


void printUDP(unsigned char* buffer, int size, int payload_offset) {
    struct udphdr* udp = (struct udphdr*)(buffer + payload_offset);
    if (size < payload_offset + 8){
    	printf("\nNo UDP Header Found\n");
    	return;
    }
        printf("\nUDP Header\n");
        printf("   |-Source Port       : %d\n", ntohs(udp->source));
        printf("   |-Destination Port  : %d\n", ntohs(udp->dest));
        printf("   |-Length            : %d\n", ntohs(udp->len));
        printf("   |-Checksum          : %d\n", ntohs(udp->check));
    
    
    payload_offset += sizeof(struct udphdr);
    printPayload(buffer, size, payload_offset);
}


void ip_info(unsigned char* buffer, int size){
    struct iphdr* ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    // Extract IP header if available
    if (size < sizeof(struct ethhdr) + sizeof(struct iphdr)){
    	printf("\nNo IP Header Found\n");
    	return;
    }
        // Print IP header information
        printf("\nIP Header\n");
        printf("   |-IP Version        : %d\n", (unsigned int)ip->version);
        printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n", (unsigned int)ip->ihl, ((unsigned int)(ip->ihl)) * 4);
        printf("   |-Type Of Service   : %d\n", (unsigned int)ip->tos);
        printf("   |-IP Total Length   : %d  Bytes(Size of Packet)\n", ntohs(ip->tot_len));
        printf("   |-Identification    : %d\n", ntohs(ip->id));
        printf("   |-Flags             : %d%d%d\n", (ntohs(ip->frag_off) & 0xE000) >> 15, (ntohs(ip->frag_off) & 0xE000) >> 14, (ntohs(ip->frag_off) & 0xE000) >> 13);
        printf("   |-Fragment Offset   : %d\n", ntohs(ip->frag_off) & 0x1FFF);
        printf("   |-TTL               : %d\n", (unsigned int)ip->ttl);
        printf("   |-Protocol          : %d\n", (unsigned int)ip->protocol);
        printf("   |-Checksum          : %d\n", ntohs(ip->check));
        printf("   |-Source IP         : %s\n", inet_ntoa(*(struct in_addr*)&ip->saddr));
        printf("   |-Destination IP    : %s\n", inet_ntoa(*(struct in_addr*)&ip->daddr));
        
        
        int payload_offset = sizeof(struct ethhdr) + (ip->ihl * 4);
        
        // Check the IP protocol type
        switch (ip->protocol) {
            case IPPROTO_TCP:
                printf("Packet contains a TCP header\n");
                printTCP(buffer, size, payload_offset);
                break;
            case IPPROTO_UDP:
                printf("Packet contains a UDP header\n");
                printUDP(buffer, size, payload_offset);
                break;
            default:
                printf("Unknown protocol\n");
                break;
        }
    
    
}



void arp_info(struct ethhdr* eth) {
    printf("   |-Hardware Type: %u\n", ntohs(*(unsigned short *)(eth + 6)));
    printf("   |-Protocol Type: %u\n", ntohs(*(unsigned short *)(eth + 8)));
    printf("   |-Hardware Length: %u\n", eth[10]);
    printf("   |-Protocol Length: %u\n", eth[11]);
    printf("   |-Opcode: %u\n", ntohs(*(unsigned short *)(eth + 12)));

    printf("   |-Sender MAC Address: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
	    eth[22], eth[23], eth[24], eth[25], eth[26], eth[27]);
    printf("   |-Sender IP Address: %u.%u.%u.%u\n",
	    eth[28], eth[29], eth[30], eth[31]);

    printf("   |-Target MAC Address: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
	    eth[32], eth[33], eth[34], eth[35], eth[36], eth[37]);
    printf("   |-Target IP Address: %u.%u.%u.%u\n",
	    eth[38], eth[39], eth[40], eth[41]);
    return;
}

void analysePacket(unsigned char* buffer, int size) {
    struct ethhdr* eth = (struct ethhdr*)buffer;
    // Extract the EtherType field
    uint16_t ether_type = ntohs(eth->h_proto);
    
    
    // Print separator
    if(ether_type == ETH_P_IP){
    	    printf("-----------------------------------------------------------\n");
    	    printf("-                     IP Packet                          -");
    	    printf("\n-----------------------------------------------------------\n");
    }else if(ether_type == ETH_P_ARP){
    	   printf("-----------------------------------------------------------\n");
    	   printf("-                      ARP Packet                        -");
    	   printf("\n-----------------------------------------------------------\n");
    }else{
    	   printf("-----------------------------------------------------------\n");
    	   printf("-                    unknown packet                      -");
    	   printf("\n-----------------------------------------------------------\n");
    }


    printf("\nEthernet Header\n");
    printf("   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
        eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
        eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    printf("   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
        eth->h_source[0], eth->h_source[1], eth->h_source[2],
        eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("   |-Protocol            : %u\n", (unsigned short)eth->h_proto);
    
    
    int payload_offset = 0;
    
    // Check the EtherType value to determine the protocol
    switch (ether_type) {
        case ETH_P_IP:
            printf("Packet contains an IPv4 header\n");
            ip_info(buffer, size);
            break;
        case ETH_P_ARP:
            printf("Packet contains an ARP header\n");
            arp_info(eth);
            break;
        default:
            printf("Unknown protocol in the packet\n");
            break;
    }

    
}