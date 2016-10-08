#include <iostream>
#include <string>
#include <sstream>
#include <stdlib.h>
#include <malloc.h>
//***************
#include <math.h>
#include <fstream>
#include <limits>
//***************
#include "api.h"
using namespace std;

//================================================================================================================================================================================
#define 	DATA						69168//48*(24*60+1)
#define 	PI 							3.1415926
#define 	N 							10000
#define 	MAX 						0XFFFF
#define 	ANY_ADDRESS     			0xffffffff
//#define	IPPROTO_UDP	17
#define	MAX_CLOCK_STRING_LENGTH	24

typedef long long clocktype;
typedef unsigned int NodeAddress;
typedef unsigned short RandomSeed[3];

const int TotallNode = 48;
const double OpspfBeita = 70;
//================================================================================================================================================================================
enum {
	MSG_NETWORK_OPSPF_UPDATEROUTINGTABLE = 672,
	MSG_NETWORK_OPSPF_UPDATESATABLE = 673,
	MSG_NETWORK_OPSPF_BROADCAST = 675,
	MSG_NETWORK_OPSPF_RECEIVEREGISTER = 676,
};

struct Coord {
	double x;
	double y;
};

struct IpHeaderType
{
	int ip_v_hl_tos_len;//ip_v:4,        /* version */
						//ip_hl:4;       /* header length */
						//unsigned char ip_tos;       /* type of service */
						//UInt16 ip_len;      /* total length */

	short ip_id;
	short ipFragment;
	//ip_reserved:1,
	//ip_dont_fragment:1,
	//ip_more_fragments:1,
	//ip_fragment_offset:13;

	unsigned char  ip_ttl;         /* time to live */
	unsigned char  ip_p;           /* protocol */
	unsigned short ip_sum;         /* checksum */
	unsigned       ip_src, ip_dst;  /* source and dest address */

};

struct registerRow {
	NodeAddress usrip;
	bool isRelay;
	int RelaySTId;
	registerRow* next;
};

struct registerInfo {
	NodeAddress usrip;
	bool isRelay;
	int RelaySTId;
};

struct RegisterPacket {
	bool isRelay;
	int RelaySTId;
	//bool isFirst;
};

struct Lon {
	double reallon;
	double calculatelon;
};

struct STCoordinates {
	Lon lon;//经度
	double lat;//纬度
	double phi;//映射角
};

struct Neighbor
{
	STCoordinates ST_leftneighbor;
	STCoordinates ST_rightneighbor;
};

struct ST {
	int orbitnum;//轨道数
	int index;//编号
	STCoordinates STC;
	Neighbor neighbor;
};


struct LSA
{
	int SourceSatellite_ID;
	int SourceSatellite_interface;
	int DestinationSatellite_ID;
	int DestinationSatellite_interface;
	int Metric;
	LSA* NextLSA;
};


struct OpspfVertex
{
	NodeAddress             vertexId;
	unsigned int            distance;
	OpspfVertex*				NextVertex; // 新添加

};

struct OpspfShortestVertex
{
	NodeAddress     DestinationVertex;//vertexId;//当前节点ID	
	NodeAddress		AdvertisingVertext;//ForwadVertexId;//前驱节点ID
	unsigned int	distance;//当前节点距离源节点距离
	OpspfShortestVertex*  NextShortestVertex;
};

struct LSDB
{
	//	int I = 0;
	LSA* LSAList;
};

//卫星的轨道面编号到数字标号的映射
struct SatelitteNumMap
{
	string SatelliteIndex;
	int Num;
};

struct registerList {
	registerRow* head;
	int size;
};

struct OpspfData {
	//随机种子
	RandomSeed seed;

	//更新消息发送间隔
	clocktype UpdateInterval;
	clocktype UpdateSAInterval;

	//无中继过时
	clocktype LastNoRelay;

	//ST结构
	ST st[48];
	ST oldst[48];

	//LSDB
	LSDB* lsdb;

	//最短路径树
	OpspfVertex GraphLinkList[TotallNode];
	OpspfShortestVertex* opspfShortestVertex;

	//印射表
	NodeAddress idtoaddress[48][6];
	NodeAddress linktable[48][6];
	NodeAddress linknode[128];
	NodeAddress linkid[128];

	//注册用表
	double s_a[48];
	registerList* rList;

	//判断第一次
	bool isfirst;
};

//================================================================================================================================================================================
//初始化函数
void OpspfInit(
	Node* node,
	int interfaceIndex);

//事件处理函数
void OpspfHandleProtocolEvent(
	Node* node,
	Message* msg);

//更新路由表总函数
void UpdateOpspfRoutingTable(
	Node* node,
	Message* msg,
	int i);

//更新S_A  映射表函数
void UpdateSATable(
	Node* node,
	int j);

//得到自身纬度
ST GetST(
	Node* node);

//得到所有纬度
void GetSTLat(
	ST* st,
	ST currentst);

//
void GetSTLatByFile(
	Node* node,
	int j);

//修正经度函数
double CalculateLon(
	double lat,
	double Gamma);

//经纬度映射到phi
double CoordinatesToPhi(
	STCoordinates coordinates);

//phi映射回经纬度
STCoordinates PhiToCoordinates(
	double Phi,
	double oldCalculatelon,
	double oldReallon);


void freeLSAList(
	LSA* LSAListhead);

//从LSDB中根据SourceSatelliteIDea读取LSA
LSA* OpspfLookupLSAList(
	LSDB* lsdb,
	string SatelliteIndex);

//根据SLA信息初始化图的邻接表表示
void ReadLSAToGraph(
	LSDB* lsdb,
	OpspfVertex GraphLinkList[TotallNode]);

//清理链表
void FreeList(
	OpspfShortestVertex** List);

//找LSA
OpspfShortestVertex* SearchVertex(
	OpspfShortestVertex* Path,
	NodeAddress VertexId);

//为每个节点调用Dijkstra算法，生成最短路径树。
//输出path为最短路径前驱节点编号。
void Dijstra(
	OpspfVertex GraphLinkList[TotallNode],
	NodeAddress Start,
	OpspfShortestVertex** Path);

//更新LSDB
void UpdateLSDB(
	Node* node);

//得到最短路径树
void	FindShortestPath(
	Node* node);

void VertexHopForRouting(
	NodeAddress AdvertisingVertex,
	NodeAddress DestinationVertex,
	OpspfShortestVertex* Path,
	OpspfShortestVertex** Router);

//填写路由表
void FillOpspfRoutingTable(
	Node* node);//UpdateIpForwardingTable()

				//
void OpspfAddRoutingTableRowById(
	Node* node,
	NodeAddress nodeId,
	NodeAddress dstAddr);

//
int GetAddressID(
	double lon,
	double lat);

//
double Dec(
	double lat);

//
void FixLon(
	int t,
	Coord sat[]);

//
double radian(
	double d);

//
void Fin(
	int t,
	Coord mat[48]);

//
void ChangeOPSPFAdderss(
	Node* node);

//
void ChangeUserAdderss(
	Node* node);

//
void SendRigesterPacket(
	Node* node,
	Message* msg);

//
void SendBroadcastPacket(
	Node* node);

//
void InitRegisterList(
	Node* node);

//
void AddRegisterListRow(
	Node* node,
	NodeAddress usrip,
	bool isRelay,
	int RelaySTId);

//
registerRow* FindRegisterRowByUsrIp(
	Node* node,
	NodeAddress usrip);

//
void FreeRegisterList(
	Node* node);

//
void OpspfAddReigsterRow(
	Node* node,
	Message* msg);

//结束函数
void OpspfFinalize(
	Node* node);

void PrintOpspfDataInFile(
	Node* node);

void NetworkIpReceivePacketFromMacLayer(
	Node *node,
	Message *msg,
	NodeAddress previousHopAddress,
	int incomingInterface);
	
void EmptyRouteTable();

void NetworkUpdateForwardingTable(
	Node *node, 
	NodeAddress destAddress, 
	NodeAddress destAddressMask, 
	NodeAddress nextHopAddress, 
	int interfaceIndex, 
	int cost);

//int getNodetime();
