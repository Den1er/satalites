#ifndef _API_H_
#define _API_H_

#include <stdint.h>

#define 	i_max 						20

typedef uint32_t NodeAddress;
//typedef void Node;
typedef int TosType;
typedef unsigned NodeAddress;

struct IpInterfaceInfoType {
	NodeAddress ipAddress;
};

struct NetworkDataIp {
	IpInterfaceInfoType* interfaceInfo[i_max];
};

struct NetworkData {
	NetworkDataIp* networkVar;
};

struct Node {
	NodeAddress nodeId;
	NetworkData* networkData;
};

struct Message {//消息结构体定义
    char* packet;
};

/* 
    96 bit (12 bytes) pseudo header needed for udp header checksum calculation 
*/
struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
};

char * GetIPAddress(
	char * interface);

void ChangeAddress(
	int interfaceIndex, 
	NodeAddress newIPAddress);
//void NetworkUpdateForwardingTable(Node *node, NodeAddress destAddress, NodeAddress destAddressMask, NodeAddress nextHopAddress, int interfaceIndex, int cost);

void NetworkIpSendRawMessage(
	Node *node, 
	Message *msg, 
	NodeAddress sourceAddress, 
	NodeAddress destinationAddress, int outgoingInterface, 
	unsigned char protocol, 
	unsigned ttl);
	
unsigned short csum(
	unsigned short *ptr,
	int nbytes);
	
#endif
