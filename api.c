#include <stdio.h> //for printf
#include <stdlib.h> //for exit(0);
#include <unistd.h>
#include <string.h> //memset
#include <sys/socket.h>    //for socket ofcourse
#include <sys/types.h>
#include <sys/ioctl.h>
#include <netinet/udp.h>   //Provides declarations for udp header
#include <netinet/ip.h>    //Provides declarations for ip header
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <errno.h> //For errno - the error number
#include "api.h"

void ChangeAddress(int interfaceIndex, NodeAddress newIPAddress){
	printf("ChangeAddress:\n");

	struct in_addr IPAddress;
	char DecIPAddress[20];
	newIPAddress = htonl(newIPAddress);//本机字节顺序转换成网络字节顺序
	memcpy(&IPAddress,&newIPAddress,4);
	strcpy(DecIPAddress, inet_ntoa(IPAddress));

	long len = 150;
	char * con = (char *)malloc(sizeof(char) * len);
	sprintf(con, "sudo ifconfig br0 %s", DecIPAddress);	
	//sprintf(con, "sudo ifconfig eth%d %s",  interfaceIndex, DecIPAddress);	
	printf("%ld - %s\n", strlen(con), con);
	system(con);	
}

char * GetIPAddress(char * interface){
	int fd;
	struct ifreq ifr;	
	fd = socket(AF_INET, SOCK_DGRAM, 0);	

	/* get an IPv4 IP address */
	ifr.ifr_addr.sa_family = AF_INET;	

	char inf[10];
	strcpy(inf, interface);
	/* IP address attached to interface */
	//strncpy(ifr.ifr_name, "eth0", IFNAMSIZ-1);	
	strncpy(ifr.ifr_name, inf, IFNAMSIZ-1);	
	ioctl(fd, SIOCGIFADDR, &ifr);	
	close(fd);	
	/* display result */
	printf("%s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));	

	return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}

/*
    Generic checksum calculation function
*/
unsigned short csum(unsigned short *ptr,int nbytes) 
{
    register long sum;
    unsigned short oddbyte;
    register short answer;
 
    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
 
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
     
    return(answer);
}

void NetworkIpSendRawMessage(Node *node, Message *msg, NodeAddress sourceAddress, 
                        NodeAddress destinationAddress, int outgoingInterface, 
                        unsigned char protocol, unsigned ttl){
    //Create a raw socket of type IPPROTO
    int s = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
     
    if(s == -1)
    {
        //socket creation failed, may be because of non-root privileges
        perror("Failed to create raw socket");
        exit(1);
    }
     
    //Datagram to represent the packet
    char datagram[4096] , source_ip[32] , *data , *pseudogram;
     
    //zero out the packet buffer
    memset (datagram, 0, 4096);
     
    //IP header
    struct iphdr *iph = (struct iphdr *) datagram;
     
    //UDP header
    struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct ip));
     
    struct sockaddr_in sin;
    struct pseudo_header psh;
     
    //Data part
    data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
    strcpy(data , msg->packet);

    //some address resolution
    sin.sin_family = AF_INET;
    sin.sin_port = htons(80);
    sin.sin_addr.s_addr = destinationAddress;
     
    //Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data);
    iph->id = htonl (54321); //Id of this packet
    iph->frag_off = 0;
    iph->ttl = ttl;
    iph->protocol = protocol;
    iph->check = 0;      //Set to 0 before calculating checksum
    iph->saddr = sourceAddress;   //Spoof the source ip address
    iph->daddr = sin.sin_addr.s_addr;
     
    //Ip checksum
    iph->check = csum ((unsigned short *) datagram, iph->tot_len);    
     
    //UDP header
    udph->source = htons (outgoingInterface);
    udph->dest = htons (8622);
    udph->len = htons(8 + strlen(data)); //udp header size
    udph->check = 0; //leave checksum 0 now, filled later by pseudo header
     
    //Now the UDP checksum using the pseudo header
    psh.source_address = sourceAddress;    
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = protocol;
    psh.udp_length = htons(sizeof(struct udphdr) + strlen(data) );
     
    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data);
    pseudogram = (char *)malloc(psize);
     
    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , udph , sizeof(struct udphdr) + strlen(data));
     
    udph->check = csum( (unsigned short*) pseudogram , psize);
     
    //loop if you want to flood 
    //Send the packet
    if (sendto (s, datagram, iph->tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    {
        perror("sendto failed");
    }else
    {               
        printf ("Packet Send. Length : %d \n" , iph->tot_len);         
        for (int i = 0; i < iph->tot_len; ++i)
        {            
            printf("%2d 0x%02x %3d %c\n", i, datagram[i], datagram[i], datagram[i]);
        }            
    }

}

/*
void NetworkUpdateForwardingTable(Node *node, NodeAddress destAddress, NodeAddress destAddressMask, NodeAddress nextHopAddress, int interfaceIndex, int cost){

	printf("NetworkUpdateForwardingTable:\n");



	struct in_addr DstAddress, DstAddressMask, NextHopAddress;		



	destAddress = htonl(destAddress);

	destAddressMask = htonl(destAddressMask);

	nextHopAddress = htonl(nextHopAddress);



	memcpy(&DstAddress,&destAddress,4);

	memcpy(&DstAddressMask, &destAddressMask, 4);

	memcpy(&NextHopAddress, &nextHopAddress, 4); 	



	char DecDstAddress[20], DecDstAddressMask[20], DecNextHopAddress[20];

	strcpy(DecDstAddress, inet_ntoa(DstAddress));

	strcpy(DecDstAddressMask, inet_ntoa(DstAddressMask));

	strcpy(DecNextHopAddress, inet_ntoa(NextHopAddress));



	long len = 150;

	char * con = (char *)malloc(sizeof(char) * len);

	//sprintf(con, "sudo route add -net %s netmask %s gw %s metric %d dev %d",  DecDstAddress, DecDstAddressMask, DecNextHopAddress, interfaceIndex, interfaceIndex);	

	sprintf(con, "sudo route add -net %s netmask %s gw %s metric %d dev %s",  DecDstAddress, DecDstAddressMask, DecNextHopAddress, cost, "br0");	

	printf("%ld - %s\n", strlen(con), con);

	system(con);	

}*/
