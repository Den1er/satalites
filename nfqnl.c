#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "api.h"
#include "opspf.h"

/*
    Generic checksum calculation function
*/
static u_int16_t checksum(u_int32_t init, u_int8_t *addr, size_t count){ /* Compute Internet Checksum for "count" bytes
   * beginning at location "addr". */ 
	u_int32_t sum = init; 
    while( count > 1 ) { /* This is the inner loop */ 
        sum += ntohs(* (u_int16_t*) addr);
        addr += 2;
        count -= 2;
    } /* Add left-over byte, if any */ 
    if( count > 0 ){
    	sum += * (u_int8_t *) addr; /* Fold 32-bit sum to 16 bits */	
    }
    while (sum>>16){
    	sum = (sum & 0xffff) + (sum >> 16); 	
    }      
    return (u_int16_t)~sum;
} 

static void set_ip_checksum(struct iphdr* iphdrp){
  iphdrp->check = 0;
  iphdrp->check = htons(checksum(0, (u_int8_t*)iphdrp, iphdrp->ihl<<2));
} 

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
		printf("payload_len=%d ", ret);

	struct iphdr *iph = ((struct iphdr *) data);
//    printf("iphdr_size=%u ", iph->ihl << 2);
//    printf("protocol=%u ", iph->protocol);

	fputc('\n', stdout);

	return id;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");

	int i;
	unsigned char *pktData;
	int ret = nfq_get_payload(nfa, &pktData);
	
	struct iphdr *iph = ((struct iphdr *) pktData);
	
//****************************************************************************************************************************
	//cyj added
	Node* node;
	node = (Node*)malloc(sizeof(Node));	
	node->nodeId = 17;
	node->networkData->networkVar->interfaceInfo[0]->ipAddress=inet_addr("190.0.25.2");
	node->networkData->networkVar->interfaceInfo[1]->ipAddress=inet_addr("190.0.28.2");
	node->networkData->networkVar->interfaceInfo[2]->ipAddress=inet_addr("190.0.47.1");
	node->networkData->networkVar->interfaceInfo[3]->ipAddress=inet_addr("190.0.48.1");
	node->networkData->networkVar->interfaceInfo[4]->ipAddress=inet_addr("190.0.49.1");
	node->networkData->networkVar->interfaceInfo[5]->ipAddress=inet_addr("190.0.50.1");
	node->networkData->networkVar->interfaceInfo[6]->ipAddress=inet_addr("4.0.0.1");
	NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;	
	
	//卫星收到包
	IpHeaderType *ipHeader = (IpHeaderType *)pktData;
	int inf = 6;
	if (node->nodeId <= 8 || (node->nodeId >= 41 && node->nodeId <= 48)) {
		inf = 4;
	}
	else {
		inf = 6;
	}

	//卫星收到UDP  包
	if ((ipHeader->ip_dst != ANY_ADDRESS) && (ipHeader->ip_p == IPPROTO_UDP)) {
		RegisterPacket* rpkt = (RegisterPacket*)(pktData + sizeof(IpHeaderType)+2);
		//自己是目的地址的注册卫星
		if (ipHeader->ip_dst / (256 * 256 * 256) == ip->interfaceInfo[inf]->ipAddress / (256 * 256 * 256)) {
			registerRow* rRow = FindRegisterRowByUsrIp(node, ipHeader->ip_dst);
			if (rRow != NULL) {
				rpkt->isRelay = rRow->isRelay;
				rpkt->RelaySTId = rRow->RelaySTId;
				//有中继,  路由到中继卫星上
				if (rpkt->isRelay == 1) {
					OpspfAddRoutingTableRowById(node, rpkt->RelaySTId, ipHeader->ip_dst);
				}
			}
		}
		else {//自己不是目的地址的注册卫星
			  //有中继时
			if (rpkt->isRelay == 1) {
				//自己是中继卫星
				if (node->nodeId == rpkt->RelaySTId) {
					//路由到对地端口
					OpspfAddRoutingTableRowById(node, rpkt->RelaySTId, ipHeader->ip_dst);
				}
				else {//自己不是中继卫星
					  //路由到中继卫星
					OpspfAddRoutingTableRowById(node, rpkt->RelaySTId, ipHeader->ip_dst);

				}
			}
		}
	}

	//卫星收到地面发出的注册包
	if ((ipHeader->ip_dst != ANY_ADDRESS) && (ipHeader->ip_p == 0)) {
		RegisterPacket* rpacket = (RegisterPacket*)(pktData + sizeof(IpHeaderType)+2);
		int inf = 6;
		if (node->nodeId <= 8 || (node->nodeId >= 41 && node->nodeId <= 48)) {
			inf = 4;
		}
		else {
			inf = 6;
		}
		//不是注册包分区对应的卫星
		if (ipHeader->ip_dst != ip->interfaceInfo[inf]->ipAddress) {
			if ((rpacket->isRelay == 1) && (rpacket->RelaySTId == 0)) {
				rpacket->RelaySTId = node->nodeId;
			}
		}
		else {//是注册包分区对应的卫星
			  //发送消息给OPSPF  更新注册表
			registerInfo *rInfo;
			rInfo->usrip = ipHeader->ip_src;
			rInfo->isRelay = rpacket->isRelay;
			rInfo->RelaySTId = rpacket->RelaySTId;
			AddRegisterListRow(node, rInfo->usrip, rInfo->isRelay, rInfo->RelaySTId);
		}
	}	
	//end of cyj
//****************************************************************************************************************************

	//ChangeAddress(0, inet_addr("192.168.1.1"));
	//NetworkUpdateForwardingTable(NULL, inet_addr("10.1.1.1"), inet_addr("255.255.255.255"), 0, 0, 1);
	//Ip checksum
	set_ip_checksum(iph); 

	printf("data[ %d ]:\n", ret);    
    for (i = 0; i < ret; i++)
        printf("%2d 0x%02x %3d %c\n", i, pktData[i], pktData[i], pktData[i]);

    printf("\n");

	/* issue a verdict on a packet */
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
//	printf("nfq_set_verdict:%d\n",nfq_set_verdict(qh, id, NF_ACCEPT, ret, pktData));

	//return nfq_set_verdict(qh, id, NF_ACCEPT, ret, pktData);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
//	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	/*open a nfqueue handler */
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	/*bind a nfqueue handler to a given protocol family */
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	/* Register a  callback function for our queue number */
	printf("binding this socket to queue '0'\n");
	/*create a new queue handle and return it. */
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	/*set the amount of packet data that nfqueue copies to userspace */
	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	/* See if we have received a packet and send it to our cb func */
	/*get the file descriptor associated with the nfqueue handler */
	fd = nfq_fd(h);

	/*if fd==1*/
	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");

			int i;
			printf("real bytes %d:\n", rv);
	    	for (i = 0; i < rv+1; i++)
	        	printf("%2d 0x%02x %3d %c\n", i, buf[i], buf[i], buf[i]);	//

			/*handle a packet received from the nfqueue subsystem */
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	/*destroy a queue handle */
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	/*close a nfqueue handler */
	nfq_close(h);

	exit(0);
}
