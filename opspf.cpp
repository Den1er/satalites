#include "opspf.h"
#include <iostream>
#include <cmath>
#include <fstream>
#include <string>
#include <sstream>
#include <stdlib.h>
#include <malloc.h>
#include <ctime>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "time.h"
#include "api.h"
using namespace std;

//================================================================================================================================================================================
//固定值
const double Gamma = 4.0;
const bool debug = 0;
const bool OpspfDebug = 0;
OpspfData* opspf;
std::vector<char *> LocalRouteTable; //维护一个全局vector，用于存储本地路由表表项

//**********************************************************************************************************************************************************************************
int main(){
	//init
	Node* node;
	node = (Node*)malloc(sizeof(Node));
	node->networkData = (NetworkData*)malloc(sizeof(NetworkData));
	node->networkData->networkVar = (NetworkDataIp*)malloc(sizeof(NetworkDataIp));
	for(int m=0;m<7;m++){
		node->networkData->networkVar->interfaceInfo[m] = (IpInterfaceInfoType*)malloc(sizeof(IpInterfaceInfoType));
	}

	node->nodeId = 17;
	node->networkData->networkVar->interfaceInfo[0]->ipAddress=inet_addr("190.0.25.2");
	node->networkData->networkVar->interfaceInfo[1]->ipAddress=inet_addr("190.0.28.2");
	node->networkData->networkVar->interfaceInfo[2]->ipAddress=inet_addr("190.0.47.1");
	node->networkData->networkVar->interfaceInfo[3]->ipAddress=inet_addr("190.0.48.1");
	node->networkData->networkVar->interfaceInfo[4]->ipAddress=inet_addr("190.0.49.1");
	node->networkData->networkVar->interfaceInfo[5]->ipAddress=inet_addr("190.0.50.1");
	node->networkData->networkVar->interfaceInfo[6]->ipAddress=inet_addr("190.0.133.17");
	
	OpspfInit(node,0);

	for (int i = 0; i <=10; i++) {
		
		EmptyRouteTable();
		
		UpdateSATable(node,i);
		
		UpdateOpspfRoutingTable(node,NULL,i);
		
		SendBroadcastPacket(node);
		
		sleep(1);
	}

	//free
	for(int m=0;m<7;m++){
		if(node->networkData->networkVar->interfaceInfo[m]!=NULL) free(node->networkData->networkVar->interfaceInfo[m]);
	}
	if(node->networkData->networkVar!=NULL) free(node->networkData->networkVar);
	if(node->networkData!=NULL) free(node->networkData);
	if(node!=NULL) free(node);

	return 0;
}
//**********************************************************************************************************************************************************************************
void OpspfInit(Node* node, int interfaceIndex) {

	opspf = (OpspfData*)malloc(sizeof(OpspfData));

	//ST结构
	memset(opspf->st, 0, sizeof(ST) * 48);
	memset(opspf->oldst, 0, sizeof(ST) * 48);
	
	//LSDB
	opspf->lsdb = NULL;
	
	//第一次判断
	opspf->isfirst = 1;
	
	//最短路径树
	int i = 0;
	for (i = 0; i<TotallNode; i++) {
		opspf->GraphLinkList[i].distance = 0;
		opspf->GraphLinkList[i].NextVertex = NULL;
		opspf->GraphLinkList[i].vertexId = 0;
	}
	opspf->opspfShortestVertex = NULL;

	//卫星端口ip地址表
	opspf->idtoaddress[0][0] = -1107295997;
	opspf->idtoaddress[0][1] = -1107295742;
	opspf->idtoaddress[0][2] = -1107295487;
	opspf->idtoaddress[0][3] = -1107295231;
	opspf->idtoaddress[0][4] = 0;
	opspf->idtoaddress[0][5] = 0;
	opspf->idtoaddress[1][0] = -1107295998;
	opspf->idtoaddress[1][1] = -1107294975;
	opspf->idtoaddress[1][2] = -1107294719;
	opspf->idtoaddress[1][3] = -1107294463;
	opspf->idtoaddress[1][4] = 0;
	opspf->idtoaddress[1][5] = 0;
	opspf->idtoaddress[2][0] = -1107294974;
	opspf->idtoaddress[2][1] = -1107294207;
	opspf->idtoaddress[2][2] = -1107293951;
	opspf->idtoaddress[2][3] = -1107293695;
	opspf->idtoaddress[2][4] = 0;
	opspf->idtoaddress[2][5] = 0;
	opspf->idtoaddress[3][0] = -1107294206;
	opspf->idtoaddress[3][1] = -1107293439;
	opspf->idtoaddress[3][2] = -1107293183;
	opspf->idtoaddress[3][3] = -1107292927;
	opspf->idtoaddress[3][4] = 0;
	opspf->idtoaddress[3][5] = 0;
	opspf->idtoaddress[4][0] = -1107293438;
	opspf->idtoaddress[4][1] = -1107292671;
	opspf->idtoaddress[4][2] = -1107292415;
	opspf->idtoaddress[4][3] = -1107292159;
	opspf->idtoaddress[4][4] = 0;
	opspf->idtoaddress[4][5] = 0;
	opspf->idtoaddress[5][0] = -1107292670;
	opspf->idtoaddress[5][1] = -1107291903;
	opspf->idtoaddress[5][2] = -1107291647;
	opspf->idtoaddress[5][3] = -1107291391;
	opspf->idtoaddress[5][4] = 0;
	opspf->idtoaddress[5][5] = 0;
	opspf->idtoaddress[6][0] = -1107291902;
	opspf->idtoaddress[6][1] = -1107291135;
	opspf->idtoaddress[6][2] = -1107290623;
	opspf->idtoaddress[6][3] = -1107262462;
	opspf->idtoaddress[6][4] = 0;
	opspf->idtoaddress[6][5] = 0;
	opspf->idtoaddress[7][0] = -1107295740;
	opspf->idtoaddress[7][1] = -1107291134;
	opspf->idtoaddress[7][2] = -1107290879;
	opspf->idtoaddress[7][3] = -1107262719;
	opspf->idtoaddress[7][4] = 0;
	opspf->idtoaddress[7][5] = 0;
	opspf->idtoaddress[8][0] = -1107295486;
	opspf->idtoaddress[8][1] = -1107294718;
	opspf->idtoaddress[8][2] = -1107290367;
	opspf->idtoaddress[8][3] = -1107290111;
	opspf->idtoaddress[8][4] = -1107289855;
	opspf->idtoaddress[8][5] = -1107289599;
	opspf->idtoaddress[9][0] = -1107294462;
	opspf->idtoaddress[9][1] = -1107293950;
	opspf->idtoaddress[9][2] = -1107290366;
	opspf->idtoaddress[9][3] = -1107289343;
	opspf->idtoaddress[9][4] = -1107289087;
	opspf->idtoaddress[9][5] = -1107288831;
	opspf->idtoaddress[10][0] = -1107293694;
	opspf->idtoaddress[10][1] = -1107293182;
	opspf->idtoaddress[10][2] = -1107289342;
	opspf->idtoaddress[10][3] = -1107288575;
	opspf->idtoaddress[10][4] = -1107288319;
	opspf->idtoaddress[10][5] = -1107288063;
	opspf->idtoaddress[11][0] = -1107292926;
	opspf->idtoaddress[11][1] = -1107292414;
	opspf->idtoaddress[11][2] = -1107288574;
	opspf->idtoaddress[11][3] = -1107287807;
	opspf->idtoaddress[11][4] = -1107287551;
	opspf->idtoaddress[11][5] = -1107287295;
	opspf->idtoaddress[12][0] = -1107292158;
	opspf->idtoaddress[12][1] = -1107291646;
	opspf->idtoaddress[12][2] = -1107287806;
	opspf->idtoaddress[12][3] = -1107287039;
	opspf->idtoaddress[12][4] = -1107286783;
	opspf->idtoaddress[12][5] = -1107286527;
	opspf->idtoaddress[13][0] = -1107291390;
	opspf->idtoaddress[13][1] = -1107287038;
	opspf->idtoaddress[13][2] = -1107286271;
	opspf->idtoaddress[13][3] = -1107286015;
	opspf->idtoaddress[13][4] = -1107285759;
	opspf->idtoaddress[13][5] = -1107262463;
	opspf->idtoaddress[14][0] = -1107290622;
	opspf->idtoaddress[14][1] = -1107286270;
	opspf->idtoaddress[14][2] = -1107285503;
	opspf->idtoaddress[14][3] = -1107285247;
	opspf->idtoaddress[14][4] = -1107284991;
	opspf->idtoaddress[14][5] = -1107262718;
	opspf->idtoaddress[15][0] = -1107295230;
	opspf->idtoaddress[15][1] = -1107290110;
	opspf->idtoaddress[15][2] = -1107285502;
	opspf->idtoaddress[15][3] = -1107284735;
	opspf->idtoaddress[15][4] = -1107284479;
	opspf->idtoaddress[15][5] = -1107290878;
	opspf->idtoaddress[16][0] = -1107289854;
	opspf->idtoaddress[16][1] = -1107289086;
	opspf->idtoaddress[16][2] = -1107284223;
	opspf->idtoaddress[16][3] = -1107283967;
	opspf->idtoaddress[16][4] = -1107283711;
	opspf->idtoaddress[16][5] = -1107283455;
	opspf->idtoaddress[17][0] = -1107288830;
	opspf->idtoaddress[17][1] = -1107288062;
	opspf->idtoaddress[17][2] = -1107284222;
	opspf->idtoaddress[17][3] = -1107283199;
	opspf->idtoaddress[17][4] = -1107282943;
	opspf->idtoaddress[17][5] = -1107282687;
	opspf->idtoaddress[18][0] = -1107288318;
	opspf->idtoaddress[18][1] = -1107287550;
	opspf->idtoaddress[18][2] = -1107283198;
	opspf->idtoaddress[18][3] = -1107282431;
	opspf->idtoaddress[18][4] = -1107282175;
	opspf->idtoaddress[18][5] = -1107281919;
	opspf->idtoaddress[19][0] = -1107287294;
	opspf->idtoaddress[19][1] = -1107286782;
	opspf->idtoaddress[19][2] = -1107282430;
	opspf->idtoaddress[19][3] = -1107281663;
	opspf->idtoaddress[19][4] = -1107281407;
	opspf->idtoaddress[19][5] = -1107281151;
	opspf->idtoaddress[20][0] = -1107286526;
	opspf->idtoaddress[20][1] = -1107286014;
	opspf->idtoaddress[20][2] = -1107281662;
	opspf->idtoaddress[20][3] = -1107280639;
	opspf->idtoaddress[20][4] = -1107280383;
	opspf->idtoaddress[20][5] = -1107280127;
	opspf->idtoaddress[21][0] = -1107285758;
	opspf->idtoaddress[21][1] = -1107285246;
	opspf->idtoaddress[21][2] = -1107280638;
	opspf->idtoaddress[21][3] = -1107279871;
	opspf->idtoaddress[21][4] = -1107279615;
	opspf->idtoaddress[21][5] = -1107279359;
	opspf->idtoaddress[22][0] = -1107284990;
	opspf->idtoaddress[22][1] = -1107284734;
	opspf->idtoaddress[22][2] = -1107279870;
	opspf->idtoaddress[22][3] = -1107279103;
	opspf->idtoaddress[22][4] = -1107278847;
	opspf->idtoaddress[22][5] = -1107278591;
	opspf->idtoaddress[23][0] = -1107289598;
	opspf->idtoaddress[23][1] = -1107284478;
	opspf->idtoaddress[23][2] = -1107283966;
	opspf->idtoaddress[23][3] = -1107279102;
	opspf->idtoaddress[23][4] = -1107278335;
	opspf->idtoaddress[23][5] = -1107278079;
	opspf->idtoaddress[24][0] = -1107283454;
	opspf->idtoaddress[24][1] = -1107282942;
	opspf->idtoaddress[24][2] = -1107277823;
	opspf->idtoaddress[24][3] = -1107277567;
	opspf->idtoaddress[24][4] = -1107277311;
	opspf->idtoaddress[24][5] = -1107277055;
	opspf->idtoaddress[25][0] = -1107282686;
	opspf->idtoaddress[25][1] = -1107281918;
	opspf->idtoaddress[25][2] = -1107277822;
	opspf->idtoaddress[25][3] = -1107276799;
	opspf->idtoaddress[25][4] = -1107276287;
	opspf->idtoaddress[25][5] = -1107276543;
	opspf->idtoaddress[26][0] = -1107282174;
	opspf->idtoaddress[26][1] = -1107281406;
	opspf->idtoaddress[26][2] = -1107276798;
	opspf->idtoaddress[26][3] = -1107276031;
	opspf->idtoaddress[26][4] = -1107275775;
	opspf->idtoaddress[26][5] = -1107275519;
	opspf->idtoaddress[27][0] = -1107281150;
	opspf->idtoaddress[27][1] = -1107280382;
	opspf->idtoaddress[27][2] = -1107276030;
	opspf->idtoaddress[27][3] = -1107275263;
	opspf->idtoaddress[27][4] = -1107275007;
	opspf->idtoaddress[27][5] = -1107274751;
	opspf->idtoaddress[28][0] = -1107280126;
	opspf->idtoaddress[28][1] = -1107279614;
	opspf->idtoaddress[28][2] = -1107275262;
	opspf->idtoaddress[28][3] = -1107274495;
	opspf->idtoaddress[28][4] = -1107274239;
	opspf->idtoaddress[28][5] = -1107273983;
	opspf->idtoaddress[29][0] = -1107279358;
	opspf->idtoaddress[29][1] = -1107278846;
	opspf->idtoaddress[29][2] = -1107274494;
	opspf->idtoaddress[29][3] = -1107273727;
	opspf->idtoaddress[29][4] = -1107273471;
	opspf->idtoaddress[29][5] = -1107273215;
	opspf->idtoaddress[30][0] = -1107278590;
	opspf->idtoaddress[30][1] = -1107278078;
	opspf->idtoaddress[30][2] = -1107273726;
	opspf->idtoaddress[30][3] = -1107272959;
	opspf->idtoaddress[30][4] = -1107272703;
	opspf->idtoaddress[30][5] = -1107272447;
	opspf->idtoaddress[31][0] = -1107283710;
	opspf->idtoaddress[31][1] = -1107278334;
	opspf->idtoaddress[31][2] = -1107277566;
	opspf->idtoaddress[31][3] = -1107272958;
	opspf->idtoaddress[31][4] = -1107272191;
	opspf->idtoaddress[31][5] = -1107271935;
	opspf->idtoaddress[32][0] = -1107277054;
	opspf->idtoaddress[32][1] = -1107276286;
	opspf->idtoaddress[32][2] = -1107271679;
	opspf->idtoaddress[32][3] = -1107271423;
	opspf->idtoaddress[32][4] = -1107271167;
	opspf->idtoaddress[32][5] = -1107270911;
	opspf->idtoaddress[33][0] = -1107276542;
	opspf->idtoaddress[33][1] = -1107275774;
	opspf->idtoaddress[33][2] = -1107271678;
	opspf->idtoaddress[33][3] = -1107270655;
	opspf->idtoaddress[33][4] = -1107270399;
	opspf->idtoaddress[33][5] = -1107270143;
	opspf->idtoaddress[34][0] = -1107275518;
	opspf->idtoaddress[34][1] = -1107275006;
	opspf->idtoaddress[34][2] = -1107270654;
	opspf->idtoaddress[34][3] = -1107269887;
	opspf->idtoaddress[34][4] = -1107269631;
	opspf->idtoaddress[34][5] = -1107269375;
	opspf->idtoaddress[35][0] = -1107274750;
	opspf->idtoaddress[35][1] = -1107274238;
	opspf->idtoaddress[35][2] = -1107269886;
	opspf->idtoaddress[35][3] = -1107269119;
	opspf->idtoaddress[35][4] = -1107268095;
	opspf->idtoaddress[35][5] = -1107267839;
	opspf->idtoaddress[36][0] = -1107273982;
	opspf->idtoaddress[36][1] = -1107273470;
	opspf->idtoaddress[36][2] = -1107269118;
	opspf->idtoaddress[36][3] = -1107267583;
	opspf->idtoaddress[36][4] = -1107267327;
	opspf->idtoaddress[36][5] = -1107267071;
	opspf->idtoaddress[37][0] = -1107273214;
	opspf->idtoaddress[37][1] = -1107272702;
	opspf->idtoaddress[37][2] = -1107267582;
	opspf->idtoaddress[37][3] = -1107266815;
	opspf->idtoaddress[37][4] = -1107266559;
	opspf->idtoaddress[37][5] = -1107266303;
	opspf->idtoaddress[38][0] = -1107272446;
	opspf->idtoaddress[38][1] = -1107271934;
	opspf->idtoaddress[38][2] = -1107266814;
	opspf->idtoaddress[38][3] = -1107266047;
	opspf->idtoaddress[38][4] = -1107265791;
	opspf->idtoaddress[38][5] = -1107265535;
	opspf->idtoaddress[39][0] = -1107277310;
	opspf->idtoaddress[39][1] = -1107272190;
	opspf->idtoaddress[39][2] = -1107271422;
	opspf->idtoaddress[39][3] = -1107266046;
	opspf->idtoaddress[39][4] = -1107265279;
	opspf->idtoaddress[39][5] = -1107265023;
	opspf->idtoaddress[40][0] = -1107271166;
	opspf->idtoaddress[40][1] = -1107270142;
	opspf->idtoaddress[40][2] = -1107264767;
	opspf->idtoaddress[40][3] = -1107264511;
	opspf->idtoaddress[40][4] = 0;
	opspf->idtoaddress[40][5] = 0;
	opspf->idtoaddress[41][0] = -1107270398;
	opspf->idtoaddress[41][1] = -1107269630;
	opspf->idtoaddress[41][2] = -1107264766;
	opspf->idtoaddress[41][3] = -1107264255;
	opspf->idtoaddress[41][4] = 0;
	opspf->idtoaddress[41][5] = 0;
	opspf->idtoaddress[42][0] = -1107269374;
	opspf->idtoaddress[42][1] = -1107268094;
	opspf->idtoaddress[42][2] = -1107264254;
	opspf->idtoaddress[42][3] = -1107263999;
	opspf->idtoaddress[42][4] = 0;
	opspf->idtoaddress[42][5] = 0;
	opspf->idtoaddress[43][0] = -1107267838;
	opspf->idtoaddress[43][1] = -1107267070;
	opspf->idtoaddress[43][2] = -1107263998;
	opspf->idtoaddress[43][3] = -1107263743;
	opspf->idtoaddress[43][4] = 0;
	opspf->idtoaddress[43][5] = 0;
	opspf->idtoaddress[44][0] = -1107267326;
	opspf->idtoaddress[44][1] = -1107266558;
	opspf->idtoaddress[44][2] = -1107263742;
	opspf->idtoaddress[44][3] = -1107263487;
	opspf->idtoaddress[44][4] = 0;
	opspf->idtoaddress[44][5] = 0;
	opspf->idtoaddress[45][0] = -1107266302;
	opspf->idtoaddress[45][1] = -1107265790;
	opspf->idtoaddress[45][2] = -1107263486;
	opspf->idtoaddress[45][3] = -1107263231;
	opspf->idtoaddress[45][4] = 0;
	opspf->idtoaddress[45][5] = 0;
	opspf->idtoaddress[46][0] = -1107265534;
	opspf->idtoaddress[46][1] = -1107265278;
	opspf->idtoaddress[46][2] = -1107263230;
	opspf->idtoaddress[46][3] = -1107262975;
	opspf->idtoaddress[46][4] = 0;
	opspf->idtoaddress[46][5] = 0;
	opspf->idtoaddress[47][0] = -1107270910;
	opspf->idtoaddress[47][1] = -1107265022;
	opspf->idtoaddress[47][2] = -1107264510;
	opspf->idtoaddress[47][3] = -1107262974;
	opspf->idtoaddress[47][4] = 0;
	opspf->idtoaddress[47][5] = 0;

	//卫星端口连接的卫星号
	opspf->linktable[0][0] = 1;
	opspf->linktable[0][1] = 7;
	opspf->linktable[0][2] = 8;
	opspf->linktable[0][3] = 15;
	opspf->linktable[0][4] = -1;
	opspf->linktable[0][5] = -1;
	opspf->linktable[1][0] = 0;
	opspf->linktable[1][1] = 2;
	opspf->linktable[1][2] = 8;
	opspf->linktable[1][3] = 9;
	opspf->linktable[1][4] = -1;
	opspf->linktable[1][5] = -1;
	opspf->linktable[2][0] = 1;
	opspf->linktable[2][1] = 3;
	opspf->linktable[2][2] = 9;
	opspf->linktable[2][3] = 10;
	opspf->linktable[2][4] = -1;
	opspf->linktable[2][5] = -1;
	opspf->linktable[3][0] = 2;
	opspf->linktable[3][1] = 4;
	opspf->linktable[3][2] = 10;
	opspf->linktable[3][3] = 11;
	opspf->linktable[3][4] = -1;
	opspf->linktable[3][5] = -1;
	opspf->linktable[4][0] = 3;
	opspf->linktable[4][1] = 5;
	opspf->linktable[4][2] = 11;
	opspf->linktable[4][3] = 12;
	opspf->linktable[4][4] = -1;
	opspf->linktable[4][5] = -1;
	opspf->linktable[5][0] = 4;
	opspf->linktable[5][1] = 6;
	opspf->linktable[5][2] = 12;
	opspf->linktable[5][3] = 13;
	opspf->linktable[5][4] = -1;
	opspf->linktable[5][5] = -1;
	opspf->linktable[6][0] = 5;
	opspf->linktable[6][1] = 7;
	opspf->linktable[6][2] = 14;
	opspf->linktable[6][3] = 13;
	opspf->linktable[6][4] = -1;
	opspf->linktable[6][5] = -1;
	opspf->linktable[7][0] = 0;
	opspf->linktable[7][1] = 6;
	opspf->linktable[7][2] = 15;
	opspf->linktable[7][3] = 14;
	opspf->linktable[7][4] = -1;
	opspf->linktable[7][5] = -1;
	opspf->linktable[8][0] = 0;
	opspf->linktable[8][1] = 1;
	opspf->linktable[8][2] = 9;
	opspf->linktable[8][3] = 15;
	opspf->linktable[8][4] = 16;
	opspf->linktable[8][5] = 23;
	opspf->linktable[9][0] = 1;
	opspf->linktable[9][1] = 2;
	opspf->linktable[9][2] = 8;
	opspf->linktable[9][3] = 10;
	opspf->linktable[9][4] = 16;
	opspf->linktable[9][5] = 17;
	opspf->linktable[10][0] = 2;
	opspf->linktable[10][1] = 3;
	opspf->linktable[10][2] = 9;
	opspf->linktable[10][3] = 11;
	opspf->linktable[10][4] = 18;
	opspf->linktable[10][5] = 17;
	opspf->linktable[11][0] = 3;
	opspf->linktable[11][1] = 4;
	opspf->linktable[11][2] = 10;
	opspf->linktable[11][3] = 12;
	opspf->linktable[11][4] = 18;
	opspf->linktable[11][5] = 19;
	opspf->linktable[12][0] = 4;
	opspf->linktable[12][1] = 5;
	opspf->linktable[12][2] = 11;
	opspf->linktable[12][3] = 13;
	opspf->linktable[12][4] = 19;
	opspf->linktable[12][5] = 20;
	opspf->linktable[13][0] = 5;
	opspf->linktable[13][1] = 12;
	opspf->linktable[13][2] = 14;
	opspf->linktable[13][3] = 20;
	opspf->linktable[13][4] = 21;
	opspf->linktable[13][5] = 6;
	opspf->linktable[14][0] = 6;
	opspf->linktable[14][1] = 13;
	opspf->linktable[14][2] = 15;
	opspf->linktable[14][3] = 21;
	opspf->linktable[14][4] = 22;
	opspf->linktable[14][5] = 7;
	opspf->linktable[15][0] = 0;
	opspf->linktable[15][1] = 8;
	opspf->linktable[15][2] = 14;
	opspf->linktable[15][3] = 22;
	opspf->linktable[15][4] = 23;
	opspf->linktable[15][5] = 7;
	opspf->linktable[16][0] = 8;
	opspf->linktable[16][1] = 9;
	opspf->linktable[16][2] = 17;
	opspf->linktable[16][3] = 23;
	opspf->linktable[16][4] = 31;
	opspf->linktable[16][5] = 24;
	opspf->linktable[17][0] = 9;
	opspf->linktable[17][1] = 10;
	opspf->linktable[17][2] = 16;
	opspf->linktable[17][3] = 18;
	opspf->linktable[17][4] = 24;
	opspf->linktable[17][5] = 25;
	opspf->linktable[18][0] = 10;
	opspf->linktable[18][1] = 11;
	opspf->linktable[18][2] = 17;
	opspf->linktable[18][3] = 19;
	opspf->linktable[18][4] = 26;
	opspf->linktable[18][5] = 25;
	opspf->linktable[19][0] = 11;
	opspf->linktable[19][1] = 12;
	opspf->linktable[19][2] = 18;
	opspf->linktable[19][3] = 20;
	opspf->linktable[19][4] = 26;
	opspf->linktable[19][5] = 27;
	opspf->linktable[20][0] = 12;
	opspf->linktable[20][1] = 13;
	opspf->linktable[20][2] = 19;
	opspf->linktable[20][3] = 21;
	opspf->linktable[20][4] = 27;
	opspf->linktable[20][5] = 28;
	opspf->linktable[21][0] = 13;
	opspf->linktable[21][1] = 14;
	opspf->linktable[21][2] = 20;
	opspf->linktable[21][3] = 22;
	opspf->linktable[21][4] = 28;
	opspf->linktable[21][5] = 29;
	opspf->linktable[22][0] = 14;
	opspf->linktable[22][1] = 15;
	opspf->linktable[22][2] = 21;
	opspf->linktable[22][3] = 23;
	opspf->linktable[22][4] = 29;
	opspf->linktable[22][5] = 30;
	opspf->linktable[23][0] = 8;
	opspf->linktable[23][1] = 15;
	opspf->linktable[23][2] = 16;
	opspf->linktable[23][3] = 22;
	opspf->linktable[23][4] = 31;
	opspf->linktable[23][5] = 30;
	opspf->linktable[24][0] = 16;
	opspf->linktable[24][1] = 17;
	opspf->linktable[24][2] = 25;
	opspf->linktable[24][3] = 31;
	opspf->linktable[24][4] = 39;
	opspf->linktable[24][5] = 32;
	opspf->linktable[25][0] = 17;
	opspf->linktable[25][1] = 18;
	opspf->linktable[25][2] = 24;
	opspf->linktable[25][3] = 26;
	opspf->linktable[25][4] = 32;
	opspf->linktable[25][5] = 33;
	opspf->linktable[26][0] = 18;
	opspf->linktable[26][1] = 19;
	opspf->linktable[26][2] = 25;
	opspf->linktable[26][3] = 27;
	opspf->linktable[26][4] = 33;
	opspf->linktable[26][5] = 34;
	opspf->linktable[27][0] = 19;
	opspf->linktable[27][1] = 20;
	opspf->linktable[27][2] = 26;
	opspf->linktable[27][3] = 28;
	opspf->linktable[27][4] = 34;
	opspf->linktable[27][5] = 35;
	opspf->linktable[28][0] = 20;
	opspf->linktable[28][1] = 21;
	opspf->linktable[28][2] = 27;
	opspf->linktable[28][3] = 29;
	opspf->linktable[28][4] = 35;
	opspf->linktable[28][5] = 36;
	opspf->linktable[29][0] = 21;
	opspf->linktable[29][1] = 22;
	opspf->linktable[29][2] = 28;
	opspf->linktable[29][3] = 30;
	opspf->linktable[29][4] = 36;
	opspf->linktable[29][5] = 37;
	opspf->linktable[30][0] = 22;
	opspf->linktable[30][1] = 23;
	opspf->linktable[30][2] = 29;
	opspf->linktable[30][3] = 31;
	opspf->linktable[30][4] = 37;
	opspf->linktable[30][5] = 38;
	opspf->linktable[31][0] = 16;
	opspf->linktable[31][1] = 23;
	opspf->linktable[31][2] = 24;
	opspf->linktable[31][3] = 30;
	opspf->linktable[31][4] = 39;
	opspf->linktable[31][5] = 38;
	opspf->linktable[32][0] = 24;
	opspf->linktable[32][1] = 25;
	opspf->linktable[32][2] = 33;
	opspf->linktable[32][3] = 39;
	opspf->linktable[32][4] = 40;
	opspf->linktable[32][5] = 47;
	opspf->linktable[33][0] = 25;
	opspf->linktable[33][1] = 26;
	opspf->linktable[33][2] = 32;
	opspf->linktable[33][3] = 34;
	opspf->linktable[33][4] = 41;
	opspf->linktable[33][5] = 40;
	opspf->linktable[34][0] = 26;
	opspf->linktable[34][1] = 27;
	opspf->linktable[34][2] = 33;
	opspf->linktable[34][3] = 35;
	opspf->linktable[34][4] = 41;
	opspf->linktable[34][5] = 42;
	opspf->linktable[35][0] = 27;
	opspf->linktable[35][1] = 28;
	opspf->linktable[35][2] = 34;
	opspf->linktable[35][3] = 36;
	opspf->linktable[35][4] = 42;
	opspf->linktable[35][5] = 43;
	opspf->linktable[36][0] = 28;
	opspf->linktable[36][1] = 29;
	opspf->linktable[36][2] = 35;
	opspf->linktable[36][3] = 37;
	opspf->linktable[36][4] = 44;
	opspf->linktable[36][5] = 43;
	opspf->linktable[37][0] = 29;
	opspf->linktable[37][1] = 30;
	opspf->linktable[37][2] = 36;
	opspf->linktable[37][3] = 38;
	opspf->linktable[37][4] = 44;
	opspf->linktable[37][5] = 45;
	opspf->linktable[38][0] = 30;
	opspf->linktable[38][1] = 31;
	opspf->linktable[38][2] = 37;
	opspf->linktable[38][3] = 39;
	opspf->linktable[38][4] = 45;
	opspf->linktable[38][5] = 46;
	opspf->linktable[39][0] = 24;
	opspf->linktable[39][1] = 31;
	opspf->linktable[39][2] = 32;
	opspf->linktable[39][3] = 38;
	opspf->linktable[39][4] = 46;
	opspf->linktable[39][5] = 47;
	opspf->linktable[40][0] = 32;
	opspf->linktable[40][1] = 33;
	opspf->linktable[40][2] = 41;
	opspf->linktable[40][3] = 47;
	opspf->linktable[40][4] = -1;
	opspf->linktable[40][5] = -1;
	opspf->linktable[41][0] = 33;
	opspf->linktable[41][1] = 34;
	opspf->linktable[41][2] = 40;
	opspf->linktable[41][3] = 42;
	opspf->linktable[41][4] = -1;
	opspf->linktable[41][5] = -1;
	opspf->linktable[42][0] = 34;
	opspf->linktable[42][1] = 35;
	opspf->linktable[42][2] = 41;
	opspf->linktable[42][3] = 43;
	opspf->linktable[42][4] = -1;
	opspf->linktable[42][5] = -1;
	opspf->linktable[43][0] = 35;
	opspf->linktable[43][1] = 36;
	opspf->linktable[43][2] = 42;
	opspf->linktable[43][3] = 44;
	opspf->linktable[43][4] = -1;
	opspf->linktable[43][5] = -1;
	opspf->linktable[44][0] = 36;
	opspf->linktable[44][1] = 37;
	opspf->linktable[44][2] = 43;
	opspf->linktable[44][3] = 45;
	opspf->linktable[44][4] = -1;
	opspf->linktable[44][5] = -1;
	opspf->linktable[45][0] = 37;
	opspf->linktable[45][1] = 38;
	opspf->linktable[45][2] = 44;
	opspf->linktable[45][3] = 46;
	opspf->linktable[45][4] = -1;
	opspf->linktable[45][5] = -1;
	opspf->linktable[46][0] = 38;
	opspf->linktable[46][1] = 39;
	opspf->linktable[46][2] = 45;
	opspf->linktable[46][3] = 47;
	opspf->linktable[46][4] = -1;
	opspf->linktable[46][5] = -1;
	opspf->linktable[47][0] = 32;
	opspf->linktable[47][1] = 39;
	opspf->linktable[47][2] = 40;
	opspf->linktable[47][3] = 46;
	opspf->linktable[47][4] = -1;
	opspf->linktable[47][5] = -1;

	//链接对应的卫星
	opspf->linknode[0] = 1;
	opspf->linknode[1] = 0;
	opspf->linknode[2] = 0;
	opspf->linknode[3] = 0;
	opspf->linknode[4] = 1;
	opspf->linknode[5] = 1;
	opspf->linknode[6] = 1;
	opspf->linknode[7] = 2;
	opspf->linknode[8] = 2;
	opspf->linknode[9] = 2;
	opspf->linknode[10] = 3;
	opspf->linknode[11] = 3;
	opspf->linknode[12] = 3;
	opspf->linknode[13] = 4;
	opspf->linknode[14] = 4;
	opspf->linknode[15] = 4;
	opspf->linknode[16] = 5;
	opspf->linknode[17] = 5;
	opspf->linknode[18] = 5;
	opspf->linknode[19] = 6;
	opspf->linknode[20] = 6;
	opspf->linknode[21] = 8;
	opspf->linknode[22] = 8;
	opspf->linknode[23] = 8;
	opspf->linknode[24] = 8;
	opspf->linknode[25] = 9;
	opspf->linknode[26] = 9;
	opspf->linknode[27] = 9;
	opspf->linknode[28] = 10;
	opspf->linknode[29] = 10;
	opspf->linknode[30] = 10;
	opspf->linknode[31] = 11;
	opspf->linknode[32] = 11;
	opspf->linknode[33] = 11;
	opspf->linknode[34] = 12;
	opspf->linknode[35] = 12;
	opspf->linknode[36] = 12;
	opspf->linknode[37] = 13;
	opspf->linknode[38] = 13;
	opspf->linknode[39] = 13;
	opspf->linknode[40] = 14;
	opspf->linknode[41] = 14;
	opspf->linknode[42] = 14;
	opspf->linknode[43] = 15;
	opspf->linknode[44] = 15;
	opspf->linknode[45] = 16;
	opspf->linknode[46] = 16;
	opspf->linknode[47] = 16;
	opspf->linknode[48] = 16;
	opspf->linknode[49] = 17;
	opspf->linknode[50] = 17;
	opspf->linknode[51] = 17;
	opspf->linknode[52] = 18;
	opspf->linknode[53] = 18;
	opspf->linknode[54] = 18;
	opspf->linknode[55] = 19;
	opspf->linknode[56] = 19;
	opspf->linknode[57] = 19;
	opspf->linknode[58] = 20;
	opspf->linknode[59] = 20;
	opspf->linknode[60] = 20;
	opspf->linknode[61] = 21;
	opspf->linknode[62] = 21;
	opspf->linknode[63] = 21;
	opspf->linknode[64] = 22;
	opspf->linknode[65] = 22;
	opspf->linknode[66] = 22;
	opspf->linknode[67] = 23;
	opspf->linknode[68] = 23;
	opspf->linknode[69] = 24;
	opspf->linknode[70] = 24;
	opspf->linknode[71] = 24;
	opspf->linknode[72] = 24;
	opspf->linknode[73] = 25;
	opspf->linknode[74] = 25;
	opspf->linknode[75] = 26;
	opspf->linknode[76] = 25;
	opspf->linknode[77] = 26;
	opspf->linknode[78] = 26;
	opspf->linknode[79] = 27;
	opspf->linknode[80] = 27;
	opspf->linknode[81] = 27;
	opspf->linknode[82] = 28;
	opspf->linknode[83] = 28;
	opspf->linknode[84] = 28;
	opspf->linknode[85] = 29;
	opspf->linknode[86] = 29;
	opspf->linknode[87] = 29;
	opspf->linknode[88] = 30;
	opspf->linknode[89] = 30;
	opspf->linknode[90] = 30;
	opspf->linknode[91] = 31;
	opspf->linknode[92] = 31;
	opspf->linknode[93] = 32;
	opspf->linknode[94] = 32;
	opspf->linknode[95] = 32;
	opspf->linknode[96] = 32;
	opspf->linknode[97] = 33;
	opspf->linknode[98] = 33;
	opspf->linknode[99] = 33;
	opspf->linknode[100] = 34;
	opspf->linknode[101] = 34;
	opspf->linknode[102] = 34;
	opspf->linknode[103] = 35;
	opspf->linknode[104] = 35;
	opspf->linknode[105] = 35;
	opspf->linknode[106] = 36;
	opspf->linknode[107] = 36;
	opspf->linknode[108] = 36;
	opspf->linknode[109] = 37;
	opspf->linknode[110] = 37;
	opspf->linknode[111] = 37;
	opspf->linknode[112] = 38;
	opspf->linknode[113] = 38;
	opspf->linknode[114] = 38;
	opspf->linknode[115] = 39;
	opspf->linknode[116] = 39;
	opspf->linknode[117] = 40;
	opspf->linknode[118] = 40;
	opspf->linknode[119] = 41;
	opspf->linknode[120] = 42;
	opspf->linknode[121] = 43;
	opspf->linknode[122] = 44;
	opspf->linknode[123] = 45;
	opspf->linknode[124] = 46;
	opspf->linknode[125] = 7;
	opspf->linknode[126] = 7;
	opspf->linknode[127] = 13;

	//链接号对应的地址最后一位
	opspf->linkid[0] = 1;
	opspf->linkid[1] = 2;
	opspf->linkid[2] = 3;
	opspf->linkid[3] = 4;
	opspf->linkid[4] = 5;
	opspf->linkid[5] = 6;
	opspf->linkid[6] = 7;
	opspf->linkid[7] = 8;
	opspf->linkid[8] = 9;
	opspf->linkid[9] = 10;
	opspf->linkid[10] = 11;
	opspf->linkid[11] = 12;
	opspf->linkid[12] = 13;
	opspf->linkid[13] = 14;
	opspf->linkid[14] = 15;
	opspf->linkid[15] = 16;
	opspf->linkid[16] = 17;
	opspf->linkid[17] = 18;
	opspf->linkid[18] = 19;
	opspf->linkid[19] = 20;
	opspf->linkid[20] = 22;
	opspf->linkid[21] = 23;
	opspf->linkid[22] = 24;
	opspf->linkid[23] = 25;
	opspf->linkid[24] = 26;
	opspf->linkid[25] = 27;
	opspf->linkid[26] = 28;
	opspf->linkid[27] = 29;
	opspf->linkid[28] = 30;
	opspf->linkid[29] = 31;
	opspf->linkid[30] = 32;
	opspf->linkid[31] = 33;
	opspf->linkid[32] = 34;
	opspf->linkid[33] = 35;
	opspf->linkid[34] = 36;
	opspf->linkid[35] = 37;
	opspf->linkid[36] = 38;
	opspf->linkid[37] = 39;
	opspf->linkid[38] = 40;
	opspf->linkid[39] = 41;
	opspf->linkid[40] = 42;
	opspf->linkid[41] = 43;
	opspf->linkid[42] = 44;
	opspf->linkid[43] = 45;
	opspf->linkid[44] = 46;
	opspf->linkid[45] = 47;
	opspf->linkid[46] = 48;
	opspf->linkid[47] = 49;
	opspf->linkid[48] = 50;
	opspf->linkid[49] = 51;
	opspf->linkid[50] = 52;
	opspf->linkid[51] = 53;
	opspf->linkid[52] = 54;
	opspf->linkid[53] = 55;
	opspf->linkid[54] = 56;
	opspf->linkid[55] = 57;
	opspf->linkid[56] = 58;
	opspf->linkid[57] = 59;
	opspf->linkid[58] = 61;
	opspf->linkid[59] = 62;
	opspf->linkid[60] = 63;
	opspf->linkid[61] = 64;
	opspf->linkid[62] = 65;
	opspf->linkid[63] = 66;
	opspf->linkid[64] = 67;
	opspf->linkid[65] = 68;
	opspf->linkid[66] = 69;
	opspf->linkid[67] = 70;
	opspf->linkid[68] = 71;
	opspf->linkid[69] = 72;
	opspf->linkid[70] = 73;
	opspf->linkid[71] = 74;
	opspf->linkid[72] = 75;
	opspf->linkid[73] = 76;
	opspf->linkid[74] = 78;
	opspf->linkid[75] = 79;
	opspf->linkid[76] = 77;
	opspf->linkid[77] = 80;
	opspf->linkid[78] = 81;
	opspf->linkid[79] = 82;
	opspf->linkid[80] = 83;
	opspf->linkid[81] = 84;
	opspf->linkid[82] = 85;
	opspf->linkid[83] = 86;
	opspf->linkid[84] = 87;
	opspf->linkid[85] = 88;
	opspf->linkid[86] = 89;
	opspf->linkid[87] = 90;
	opspf->linkid[88] = 91;
	opspf->linkid[89] = 92;
	opspf->linkid[90] = 93;
	opspf->linkid[91] = 94;
	opspf->linkid[92] = 95;
	opspf->linkid[93] = 96;
	opspf->linkid[94] = 97;
	opspf->linkid[95] = 98;
	opspf->linkid[96] = 99;
	opspf->linkid[97] = 100;
	opspf->linkid[98] = 101;
	opspf->linkid[99] = 102;
	opspf->linkid[100] = 103;
	opspf->linkid[101] = 104;
	opspf->linkid[102] = 105;
	opspf->linkid[103] = 106;
	opspf->linkid[104] = 110;
	opspf->linkid[105] = 111;
	opspf->linkid[106] = 112;
	opspf->linkid[107] = 113;
	opspf->linkid[108] = 114;
	opspf->linkid[109] = 115;
	opspf->linkid[110] = 116;
	opspf->linkid[111] = 117;
	opspf->linkid[112] = 118;
	opspf->linkid[113] = 119;
	opspf->linkid[114] = 120;
	opspf->linkid[115] = 121;
	opspf->linkid[116] = 122;
	opspf->linkid[117] = 123;
	opspf->linkid[118] = 124;
	opspf->linkid[119] = 125;
	opspf->linkid[120] = 126;
	opspf->linkid[121] = 127;
	opspf->linkid[122] = 128;
	opspf->linkid[123] = 129;
	opspf->linkid[124] = 130;
	opspf->linkid[125] = 21;
	opspf->linkid[126] = 131;
	opspf->linkid[127] = 132;

	//初始化S_A  映射表
	for (i = 0; i<48; i++) {
		opspf->s_a[i] = -1;
	}

	//初始化注册表
	InitRegisterList(node);

	//if (node->nodeId>48) {
	//	ChangeUserAdderss(node);
	//}
}

//**********************************************************************************************************************************************************************************
//                                                                      静态部分
//																		静态部分
//**********************************************************************************************************************************************************************************
//void OpspfHandleProtocolEvent(Node* node, Message* msg)
//{
//
//	switch (msg->eventType) {
//		case MSG_NETWORK_OPSPF_UPDATEROUTINGTABLE:
//		{
//			if (node->nodeId <= 48) {
//				UpdateOpspfRoutingTable(node, msg);
//			}
//			break;
//		}
//		case MSG_NETWORK_OPSPF_UPDATESATABLE:
//		{
//			if (node->nodeId <= 48) {
//				UpdateSATable(node, msg);
//			}
//			break;
//		}
//		case MSG_NETWORK_OPSPF_BROADCAST:
//		{
//			if (node->nodeId <= 48) {
//				SendBroadcastPacket(node, msg);
//			}
//			break;
//		}
//		case MSG_NETWORK_OPSPF_RECEIVEREGISTER:
//		{
//			if (node->nodeId <= 48) {
//				OpspfAddReigsterRow(node, msg);
//			}
//			break;
//		}
//	}
//
//	//MESSAGE_Free(node, msg);
//}
int getNodetime(){
	time_t now_time;
	now_time = time(NULL);
	int t = now_time % 86400 + 28800;
	return t;
}
//**********************************************************************************************************************************************************************************
void UpdateOpspfRoutingTable(Node* node, Message* msg, int i) {

	opspf->st[0].orbitnum = 0;

	//计算所有卫星的纬度
	GetSTLatByFile(node,i);

	//更新LSDB	
	UpdateLSDB(node);

	//得到最短路径树
	FindShortestPath(node);
	
	//填表
	FillOpspfRoutingTable(node);

}

void GetSTLatByFile(Node* node, int j) {

	//轨道状态参量
	const int orbital = 6;
	const int maxST = 8;

	//所有卫星初始化	
	for (int i = 0; i<orbital*maxST; i++) {
		opspf->st[i].orbitnum = i / maxST + 1;
		opspf->st[i].index = (i + 1) % maxST;
		if (opspf->st[i].index == 0) opspf->st[i].index = 8;
		opspf->st[i].STC.phi = 0;
	}

	int start_time = 0;
	ifstream infile;
	if (!infile)
	{
		cerr << "open error!" << endl;
		//exit(1);
	}
	infile.open("a_24h.bin", ios::in | ios::binary);

	int currentId = node->nodeId - 1;
	//int currentTime = getNodetime();
	int currentTime = j;

	Coord* TempST = NULL;
	TempST = (Coord*)malloc(sizeof(Coord));
	for (int i = 0; i<48; i++) {
		start_time = i * 1441 + currentTime % 1441;
		infile.seekg(sizeof(Coord) * start_time, ios_base::beg);
		infile.read((char*)(TempST), sizeof(Coord));
		opspf->st[i].STC.lat = TempST->x;
	}
	free(TempST);
	infile.close();
}

/*更新LSDB的函数*/
void UpdateLSDB(Node* node){
	LSA* head;
	LSA* back;
	//清空LSDB中的LSAList
	if (opspf->lsdb != NULL) {
		if (opspf->lsdb->LSAList != NULL) {
			freeLSAList(opspf->lsdb->LSAList);
		}
	}

	//初始化opspf->lsdb->LSAList
	opspf->lsdb = (LSDB*)malloc(sizeof(LSDB));
	head = (LSA*)malloc(sizeof(LSA));
	opspf->lsdb->LSAList = head;

	int j = 0;
	/* 同一轨道面的前后卫星始终相连*/
	for (int i = 0; i < 48; i++)
	{
		/*当前卫星与前向卫星相连*/
		back = head;
		back->DestinationSatellite_ID = (opspf->st[i].orbitnum - 1) * 8 + (opspf->st[i].index) % 8;
		back->SourceSatellite_ID = (opspf->st[i].orbitnum - 1) * 8 + opspf->st[i].index - 1;
		for (j = 0; j<6; j++) {
			if (opspf->linktable[back->DestinationSatellite_ID][j] == back->SourceSatellite_ID) {
				break;
			}
		}
		back->DestinationSatellite_interface = j;
		for (j = 0; j<6; j++) {
			if (opspf->linktable[back->SourceSatellite_ID][j] == back->DestinationSatellite_ID) {
				break;
			}
		}
		back->SourceSatellite_interface = j;
		back->Metric = 1;
		back->NextLSA = NULL;

		/*当前卫星与后向卫星相连*/
		head = (LSA*)malloc(sizeof(LSA));
		back->NextLSA = head;
		back = head;
		back->DestinationSatellite_ID = (opspf->st[i].orbitnum - 1) * 8 + (opspf->st[i].index + 6) % 8;
		back->SourceSatellite_ID = (opspf->st[i].orbitnum - 1) * 8 + opspf->st[i].index - 1;
		for (j = 0; j<6; j++) {
			if (opspf->linktable[back->DestinationSatellite_ID][j] == back->SourceSatellite_ID) {
				break;
			}
		}
		back->DestinationSatellite_interface = j;
		for (j = 0; j<6; j++) {
			if (opspf->linktable[back->SourceSatellite_ID][j] == back->DestinationSatellite_ID) {
				break;
			}
		}
		back->SourceSatellite_interface = j;
		back->Metric = 1;
		head = (LSA*)malloc(sizeof(LSA));
		back->NextLSA = head;
	}
    free(head);

	/*相邻轨道面之间卫星的链接关系，根据卫星的维度信息判断*/
	for (int i = 0; i < 48; i++)
	{
		//当前卫星维度的绝对值若是大于beia并且小于90，则该卫星与左右轨道卫星均断开链接
		if ((abs(opspf->st[i].STC.lat) > OpspfBeita) && (abs(opspf->st[i].STC.lat) <= 90))
		{
			head = (LSA*)malloc(sizeof(LSA));
			back->NextLSA = head;
			back = head;
			back->DestinationSatellite_ID = 0;
			back->DestinationSatellite_interface = 3;
			back->SourceSatellite_ID = ((opspf->st[i].orbitnum - 1) * 8 + opspf->st[i].index - 1);
			back->SourceSatellite_interface = 1;
			back->Metric = MAX;
			back->NextLSA = NULL;

			head = (LSA*)malloc(sizeof(LSA));
			back->NextLSA = head;
			back = head;
			back->DestinationSatellite_ID = 0;
			back->DestinationSatellite_interface = 1;
			back->SourceSatellite_ID = ((opspf->st[i].orbitnum - 1) * 8 + opspf->st[i].index - 1);
			back->SourceSatellite_interface = 3;
			back->Metric = MAX;
			back->NextLSA = NULL;
		}

		//当前卫星维度的绝对值小于或等于beita
		else
		{	//当卫星位于第1轨道面时
			if (opspf->st[i].orbitnum == 1)
			{
				/*在轨道1和轨道6之间，存在反向缝，轨道1需要单独考虑*/
				/*轨道1中的卫星和其左侧卫星断开*/
				if ((((opspf->st[i].STC.lat) - (opspf->oldst[i].STC.lat)) >= 0) || (opspf->isfirst == 1))
				{
					opspf->isfirst = 0;
					head = (LSA*)malloc(sizeof(LSA));
					back->NextLSA = head;
					back = head;
					back->DestinationSatellite_ID = 0;
					back->DestinationSatellite_interface = 1;
					back->SourceSatellite_ID = (opspf->st[i].orbitnum - 1) * 8 + opspf->st[i].index - 1;
					back->SourceSatellite_interface = 3;
					back->Metric = MAX;
					back->NextLSA = NULL;

					//轨道1中的卫星与其右侧轨道卫星的链接关系通过判卫星的维度获得
					if ((abs(opspf->st[(opspf->st[i].orbitnum) * 8 + (opspf->st[i].index + 6) % 8].STC.lat) > OpspfBeita) && (abs(opspf->st[(opspf->st[i].orbitnum) * 8 + (opspf->st[i].index + 6) % 8].STC.lat) <= 90))
					{
						head = (LSA*)malloc(sizeof(LSA));
						back->NextLSA = head;
						back = head;
						back->DestinationSatellite_ID = 0;
						back->DestinationSatellite_interface = 3;
						back->SourceSatellite_ID = (opspf->st[i].orbitnum - 1) * 8 + opspf->st[i].index - 1;
						back->SourceSatellite_interface = 1;
						back->Metric = MAX;
						back->NextLSA = NULL;
					}
					else
					{
						head = (LSA*)malloc(sizeof(LSA));
						back->NextLSA = head;
						back = head;
						back->DestinationSatellite_ID = (opspf->st[i].orbitnum) * 8 + (opspf->st[i].index + 6) % 8;
						back->SourceSatellite_ID = (opspf->st[i].orbitnum - 1) * 8 + opspf->st[i].index - 1;
						for (j = 0; j<6; j++) {
							if (opspf->linktable[back->DestinationSatellite_ID][j] == back->SourceSatellite_ID) {
								break;
							}
						}
						back->DestinationSatellite_interface = j;
						for (j = 0; j<6; j++) {
							if (opspf->linktable[back->SourceSatellite_ID][j] == back->DestinationSatellite_ID) {
								break;
							}
						}
						back->SourceSatellite_interface = j;
						back->Metric = 1;
						back->NextLSA = NULL;
					}
				}
				else
				{
					head = (LSA*)malloc(sizeof(LSA));
					back->NextLSA = head;
					back = head;
					back->DestinationSatellite_ID = 0;
					back->DestinationSatellite_interface = 1;
					back->SourceSatellite_ID = (opspf->st[i].orbitnum - 1) * 8 + opspf->st[i].index - 1;
					back->SourceSatellite_interface = 3;
					back->Metric = MAX;
					back->NextLSA = NULL;
					if ((abs(opspf->st[i + 8].STC.lat) > OpspfBeita) && (abs(opspf->st[i + 8].STC.lat) <= 90))
					{
						head = (LSA*)malloc(sizeof(LSA));
						back->NextLSA = head;
						back = head;
						back->DestinationSatellite_ID = 0;
						back->DestinationSatellite_interface = 3;
						back->SourceSatellite_ID = (opspf->st[i].orbitnum - 1) * 8 + opspf->st[i].index - 1;
						back->SourceSatellite_interface = 1;
						back->Metric = MAX;
						back->NextLSA = NULL;
					}
					else
					{
						head = (LSA*)malloc(sizeof(LSA));
						back->NextLSA = head;
						back = head;
						back->DestinationSatellite_ID = opspf->st[i].orbitnum * 8 + opspf->st[i].index - 1;
						back->SourceSatellite_ID = (opspf->st[i].orbitnum - 1) * 8 + opspf->st[i].index - 1;
						for (j = 0; j<6; j++) {
							if (opspf->linktable[back->DestinationSatellite_ID][j] == back->SourceSatellite_ID) {
								break;
							}
						}
						back->DestinationSatellite_interface = j;
						for (j = 0; j<6; j++) {
							if (opspf->linktable[back->SourceSatellite_ID][j] == back->DestinationSatellite_ID) {
								break;
							}
						}
						back->SourceSatellite_interface = j;
						back->Metric = 1;
						back->NextLSA = NULL;
					}
				}
			}

			//当卫星位于第2-5轨道面时
			else if ((opspf->st[i].orbitnum > 1) && (opspf->st[i].orbitnum < 6))
			{
				//当本卫星处于正向运动时
				if ((((opspf->st[i].STC.lat) - (opspf->oldst[i].STC.lat)) >= 0) || (opspf->isfirst == 1))
				{
					opspf->isfirst = 0;
					//判断本卫星与右边卫星连接状态
					if ((abs(opspf->st[(opspf->st[i].orbitnum) * 8 + (opspf->st[i].index + 6) % 8].STC.lat) > OpspfBeita) && (abs(opspf->st[(opspf->st[i].orbitnum) * 8 + (opspf->st[i].index + 6) % 8].STC.lat) <= 90))
					{
						head = (LSA*)malloc(sizeof(LSA));
						back->NextLSA = head;
						back = head;
						back->DestinationSatellite_ID = 0;
						back->DestinationSatellite_interface = 3;
						back->SourceSatellite_ID = (opspf->st[i].orbitnum - 1) * 8 + opspf->st[i].index - 1;
						back->SourceSatellite_interface = 1;
						back->Metric = MAX;
						back->NextLSA = NULL;
					}
					else
					{
						head = (LSA*)malloc(sizeof(LSA));
						back->NextLSA = head;
						back = head;
						back->DestinationSatellite_ID = (opspf->st[i].orbitnum) * 8 + (opspf->st[i].index + 6) % 8;
						back->SourceSatellite_ID = (opspf->st[i].orbitnum - 1) * 8 + opspf->st[i].index - 1;
						for (j = 0; j<6; j++) {
							if (opspf->linktable[back->DestinationSatellite_ID][j] == back->SourceSatellite_ID) {
								break;
							}
						}
						back->DestinationSatellite_interface = j;
						for (j = 0; j<6; j++) {
							if (opspf->linktable[back->SourceSatellite_ID][j] == back->DestinationSatellite_ID) {
								break;
							}
						}
						back->SourceSatellite_interface = j;
						back->Metric = 1;
						back->NextLSA = NULL;
					}
					//判断本卫星与左边卫星连接状态
					if ((abs(opspf->st[(opspf->st[i].orbitnum - 2) * 8 + (opspf->st[i].index) % 8].STC.lat) > OpspfBeita) && (abs(opspf->st[(opspf->st[i].orbitnum - 2) * 8 + (opspf->st[i].index) % 8].STC.lat) <= 90))
					{
						head = (LSA*)malloc(sizeof(LSA));
						back->NextLSA = head;
						back = head;
						back->DestinationSatellite_ID = 0;
						back->DestinationSatellite_interface = 3;
						back->SourceSatellite_ID = (opspf->st[i].orbitnum - 1) * 8 + opspf->st[i].index - 1;
						back->SourceSatellite_interface = 1;
						back->Metric = MAX;
						back->NextLSA = NULL;
					}
					else
					{
						head = (LSA*)malloc(sizeof(LSA));
						back->NextLSA = head;
						back = head;
						back->DestinationSatellite_ID = (opspf->st[i].orbitnum - 2) * 8 + (opspf->st[i].index) % 8;
						back->SourceSatellite_ID = (opspf->st[i].orbitnum - 1) * 8 + opspf->st[i].index - 1;
						for (j = 0; j<6; j++) {
							if (opspf->linktable[back->DestinationSatellite_ID][j] == back->SourceSatellite_ID) {
								break;
							}
						}
						back->DestinationSatellite_interface = j;
						for (j = 0; j<6; j++) {
							if (opspf->linktable[back->SourceSatellite_ID][j] == back->DestinationSatellite_ID) {
								break;
							}
						}
						back->SourceSatellite_interface = j;
						back->Metric = 1;
						back->NextLSA = NULL;
					}
				}

				//当本卫星处于反向运动时
				else
				{
					//判断本卫星与右边卫星连接状态
					if ((abs(opspf->st[i + 8].STC.lat) > OpspfBeita) && (abs(opspf->st[i + 8].STC.lat) <= 90))
					{
						head = (LSA*)malloc(sizeof(LSA));
						back->NextLSA = head;
						back = head;
						back->DestinationSatellite_ID = 0;
						back->DestinationSatellite_interface = 3;
						back->SourceSatellite_ID = (opspf->st[i].orbitnum - 1) * 8 + opspf->st[i].index - 1;
						back->SourceSatellite_interface = 1;
						back->Metric = MAX;
						back->NextLSA = NULL;
					}
					else
					{
						head = (LSA*)malloc(sizeof(LSA));
						back->NextLSA = head;
						back = head;
						back->DestinationSatellite_ID = (opspf->st[i].orbitnum) * 8 + opspf->st[i].index - 1;
						back->SourceSatellite_ID = (opspf->st[i].orbitnum - 1) * 8 + opspf->st[i].index - 1;
						for (j = 0; j<6; j++) {
							if (opspf->linktable[back->DestinationSatellite_ID][j] == back->SourceSatellite_ID) {
								break;
							}
						}
						back->DestinationSatellite_interface = j;
						for (j = 0; j<6; j++) {
							if (opspf->linktable[back->SourceSatellite_ID][j] == back->DestinationSatellite_ID) {
								break;
							}
						}
						back->SourceSatellite_interface = j;
						back->Metric = 1;
						back->NextLSA = NULL;
					}
					//判断本卫星与左边卫星连接状态
					if ((abs(opspf->st[i - 8].STC.lat) > OpspfBeita) && (abs(opspf->st[i - 8].STC.lat) <= 90))
					{
						head = (LSA*)malloc(sizeof(LSA));
						back->NextLSA = head;
						back = head;
						back->DestinationSatellite_ID = 0;
						back->DestinationSatellite_interface = 1;
						back->SourceSatellite_ID = (opspf->st[i].orbitnum - 1) * 8 + opspf->st[i].index - 1;
						back->SourceSatellite_interface = 3;
						back->Metric = MAX;
						back->NextLSA = NULL;
					}
					else
					{
						head = (LSA*)malloc(sizeof(LSA));
						back->NextLSA = head;
						back = head;
						back->DestinationSatellite_ID = (opspf->st[i].orbitnum - 2) * 8 + opspf->st[i].index - 1;
						back->SourceSatellite_ID = (opspf->st[i].orbitnum - 1) * 8 + opspf->st[i].index - 1;
						for (j = 0; j<6; j++) {
							if (opspf->linktable[back->DestinationSatellite_ID][j] == back->SourceSatellite_ID) {
								break;
							}
						}
						back->DestinationSatellite_interface = j;
						for (j = 0; j<6; j++) {
							if (opspf->linktable[back->SourceSatellite_ID][j] == back->DestinationSatellite_ID) {
								break;
							}
						}
						back->SourceSatellite_interface = j;
						back->Metric = 1;
						back->NextLSA = NULL;
					}
				}
			}
			//当卫星位于第6轨道面时
			else
			{
				/*在轨道6和轨道1之间，存在反向缝，轨道6需要单独考虑*/
				/*轨道6中的卫星和其右侧卫星断开*/
				head = (LSA*)malloc(sizeof(LSA));
				back->NextLSA = head;
				back = head;
				back->DestinationSatellite_ID = 0;
				back->DestinationSatellite_interface = 3;
				back->SourceSatellite_ID = (opspf->st[i].orbitnum - 1) * 8 + opspf->st[i].index - 1;
				back->SourceSatellite_interface = 1;
				back->Metric = MAX;
				back->NextLSA = NULL;

				//轨道6中的卫星与其左侧轨道卫星的链接关系通过判卫星的维度获得
				//当卫星处于正向运动时
				if ((((opspf->st[i].STC.lat) - (opspf->oldst[i].STC.lat)) >= 0) || (opspf->isfirst == 1))
				{
					opspf->isfirst = 0;
					//判断本卫星与左边卫星连接状态
					if ((abs(opspf->st[(opspf->st[i].orbitnum - 2) * 8 + (opspf->st[i].index) % 8].STC.lat) > OpspfBeita) && (abs(opspf->st[(opspf->st[i].orbitnum - 2) * 8 + (opspf->st[i].index) % 8].STC.lat) <= 90))
					{
						head = (LSA*)malloc(sizeof(LSA));
						
						back->NextLSA = head;
						back = head;
						back->DestinationSatellite_ID = 0;
						back->DestinationSatellite_interface = 1;
						back->SourceSatellite_ID = (opspf->st[i].orbitnum - 1) * 8 + opspf->st[i].index - 1;
						back->SourceSatellite_interface = 3;
						back->Metric = MAX;
						back->NextLSA = NULL;
					}
					else
					{
						head = (LSA*)malloc(sizeof(LSA));
						back->NextLSA = head;
						back = head;
						back->DestinationSatellite_ID = (opspf->st[i].orbitnum - 2) * 8 + (opspf->st[i].index) % 8;
						back->SourceSatellite_ID = (opspf->st[i].orbitnum - 1) * 8 + opspf->st[i].index - 1;
						for (j = 0; j<6; j++) {
							if (opspf->linktable[back->DestinationSatellite_ID][j] == back->SourceSatellite_ID) {
								break;
							}
						}
						back->DestinationSatellite_interface = j;
						for (j = 0; j<6; j++) {
							if (opspf->linktable[back->SourceSatellite_ID][j] == back->DestinationSatellite_ID) {
								break;
							}
						}
						back->SourceSatellite_interface = j;
						back->Metric = 1;
						back->NextLSA = NULL;
					}
				}
				//当本卫星处于反向运动时
				else
				{
					//判断本卫星与左边卫星连接状态						
					if ((abs(opspf->st[i - 8].STC.lat) > OpspfBeita) && (abs(opspf->st[i - 8].STC.lat) <= 90))
					{
						head = (LSA*)malloc(sizeof(LSA));
						back->NextLSA = head;
						back = head;
						back->DestinationSatellite_ID = 0;
						back->DestinationSatellite_interface = 1;
						back->SourceSatellite_ID = (opspf->st[i].orbitnum - 1) * 8 + opspf->st[i].index - 1;
						back->SourceSatellite_interface = 3;
						back->Metric = MAX;
						back->NextLSA = NULL;
					}
					else
					{
						head = (LSA*)malloc(sizeof(LSA));
						back->NextLSA = head;
						back = head;
						back->DestinationSatellite_ID = (opspf->st[i].orbitnum - 2) * 8 + (opspf->st[i].index) % 8;
						back->SourceSatellite_ID = (opspf->st[i].orbitnum - 1) * 8 + opspf->st[i].index - 1;
						for (j = 0; j<6; j++) {
							if (opspf->linktable[back->DestinationSatellite_ID][j] == back->SourceSatellite_ID) {
								break;
							}
						}
						back->DestinationSatellite_interface = j;
						for (j = 0; j<6; j++) {
							if (opspf->linktable[back->SourceSatellite_ID][j] == back->DestinationSatellite_ID) {
								break;
							}
						}
						back->SourceSatellite_interface = j;
						back->Metric = 1;
						back->NextLSA = NULL;
					}
				}
			}
		}
	}

	/*LSDB更新完成后，把当前时刻星座中的卫星维度信息保存下来，以便下一时刻判断卫星的运行方向*/
	for (int i = 0; i < 48; i++)
	{
		opspf->oldst[i].STC.lat = opspf->st[i].STC.lat;
	}
}

//得到最短路径树
void FindShortestPath(Node* node) {
	ReadLSAToGraph(opspf->lsdb, opspf->GraphLinkList);
	Dijstra(opspf->GraphLinkList, node->nodeId - 1, &(opspf->opspfShortestVertex));
}

void FillOpspfRoutingTable(Node* node) {

	OpspfShortestVertex* a = NULL;
	OpspfShortestVertex* tempv = NULL;

	LSA* NextHopLsa;

	int DestinationIndex;
	for (int i = 0; i<128; i++) {
		//得到从原节点出发的路径
		VertexHopForRouting(node->nodeId - 1, opspf->linknode[i], opspf->opspfShortestVertex, &a);

		DestinationIndex = opspf->linknode[i];
	
		if (a->NextShortestVertex != a) {
			//得到下一跳节点的LSA
			tempv = a->NextShortestVertex;
			NextHopLsa = opspf->lsdb->LSAList;
			while (NextHopLsa) {
				if ((NextHopLsa->SourceSatellite_ID == tempv->AdvertisingVertext) && (NextHopLsa->DestinationSatellite_ID == tempv->DestinationVertex)) {
					break;
				}
				NextHopLsa = NextHopLsa->NextLSA;
			}
			while (tempv->NextShortestVertex != NULL) {
				tempv = tempv->NextShortestVertex;
			}
			//LSA存在时
			if (NextHopLsa != NULL) {
				NodeAddress DstAddress = 190 * 256 * 256 * 256 + (opspf->linkid[i]) * 256 - 4294967296;
				NodeAddress NextHopAddress = opspf->idtoaddress[a->NextShortestVertex->DestinationVertex][NextHopLsa->DestinationSatellite_interface];				
				//NetworkUpdateForwardingTable(node, DstAddress, -256, NextHopAddress, NextHopLsa->SourceSatellite_interface, tempv->distance, ROUTING_PROTOCOL_OPSPF);
				NetworkUpdateForwardingTable(node, DstAddress, -256, NextHopAddress, NextHopLsa->SourceSatellite_interface, tempv->distance);//2016823
			}
		}
		else {
			int j = 0;
			for (j = 0; j<6; j++) {
				if (((opspf->idtoaddress[node->nodeId - 1][j]) / 256 - 190 * 256 * 256) == (opspf->linkid[i])) break;
			}
			int SourceInterface = j;
			NodeAddress DstAddress = opspf->linktable[node->nodeId - 1][SourceInterface];
			for (j = 0; j<6; j++) {
				if (((opspf->idtoaddress[DstAddress][j]) / 256 - 190 * 256 * 256) == (opspf->linkid[i])) break;
			}
			int DstInterface = j;
			DstAddress = opspf->idtoaddress[DstAddress][DstInterface];
			//NetworkUpdateForwardingTable(node, (NodeAddress)(190 * 256 * 256 * 256 + (opspf->linkid[i]) * 256 - 4294967296), -256, DstAddress, SourceInterface, 0, ROUTING_PROTOCOL_OPSPF);
			NetworkUpdateForwardingTable(node, (NodeAddress)(190 * 256 * 256 * 256 + (opspf->linkid[i]) * 256 - 4294967296), -256, DstAddress, SourceInterface, 0);//2016823
		}
	}
	for (int i = 0; i<48; i++) {
		int areaId = opspf->s_a[i];
		VertexHopForRouting(node->nodeId - 1, i, opspf->opspfShortestVertex, &a);
		//目的节点不是自己网段
		if (a->NextShortestVertex != a) {
			//得到下一跳节点的LSA
			tempv = a->NextShortestVertex;
			NextHopLsa = opspf->lsdb->LSAList;
			while (NextHopLsa) {
				if ((NextHopLsa->SourceSatellite_ID == tempv->AdvertisingVertext) && (NextHopLsa->DestinationSatellite_ID == tempv->DestinationVertex)) {
					break;
				}
				NextHopLsa = NextHopLsa->NextLSA;
			}
			while (tempv->NextShortestVertex != NULL) {
				tempv = tempv->NextShortestVertex;
			}
			//LSA存在时
			if (NextHopLsa != NULL) {
				NodeAddress DstAddress = areaId * 256 * 256 * 256;
				NodeAddress NextHopAddress = opspf->idtoaddress[a->NextShortestVertex->DestinationVertex][NextHopLsa->DestinationSatellite_interface];
				//NetworkUpdateForwardingTable(node, DstAddress, 255 * 256 * 256 * 256, NextHopAddress, NextHopLsa->SourceSatellite_interface, tempv->distance, ROUTING_PROTOCOL_OPSPF);
				NetworkUpdateForwardingTable(node, DstAddress, 255 * 256 * 256 * 256, NextHopAddress, NextHopLsa->SourceSatellite_interface, tempv->distance);//2016823
			}
		}
		else {//目的节点是自己网段
			NodeAddress DstAddress = areaId * 256 * 256 * 256;
			NodeAddress NextHopAddress = areaId * 256 * 256 * 256 + 255 * 256 * 256 + 255 * 256 + 255;
			int inf = 6;
			if (node->nodeId <= 8 || (node->nodeId >= 41 && node->nodeId <= 48)) {
				inf = 4;
			}
			else {
				inf = 6;
			}
			//NetworkUpdateForwardingTable(node, DstAddress, 255 * 256 * 256 * 256, NextHopAddress, inf, 0, ROUTING_PROTOCOL_OPSPF);
			NetworkUpdateForwardingTable(node, DstAddress, 255 * 256 * 256 * 256, NextHopAddress, inf, 0);//2016823
		}
	}
}

//**********************************************************************************************************************************************************************************
/*清空链表的函数*/
void freeLSAList(LSA* LSAListhead){
	LSA* LSAListp;
	LSA* LSAListq;
	if (LSAListhead == NULL)
	{
		return;
	}
	LSAListp = LSAListhead;
	while (LSAListp != NULL)
	{
		LSAListq = LSAListp;
		LSAListp = LSAListp->NextLSA;
		free(LSAListq);

	}
	LSAListhead = NULL;
}

//从LSDB中根据SourceSatelliteIDea读取LSA
LSA* OpspfLookupLSAList(LSDB* lsdb, int SatelliteIndex){
	LSA* tempLsa;
	tempLsa = lsdb->LSAList;
	while (tempLsa)
	{
		if (tempLsa->SourceSatellite_ID == SatelliteIndex) //找SatelliteIndex卫星的LSA
		{
			return tempLsa;
		}
		tempLsa = tempLsa->NextLSA;
	}
	return NULL;

}

//根据SLA信息初始化图的邻接表表示
void ReadLSAToGraph(LSDB* lsdb, OpspfVertex GraphLinkList[TotallNode]){
	LSA* SatelliteLSA;
	OpspfVertex* LinkVertex;
	OpspfVertex* tempLink;
	int i;
	int index;
	//stringstream ss;
	for (i = 0; i < TotallNode; i++)
	{
		index = i;
		SatelliteLSA = OpspfLookupLSAList(lsdb, index);
		//邻接表头结点指向当前自己节点
		GraphLinkList[i].distance = 0;
		GraphLinkList[i].vertexId = i;
		GraphLinkList[i].NextVertex = NULL;
		tempLink = GraphLinkList + i;//指向当前头结点
		if (SatelliteLSA)
		{
			while (SatelliteLSA)//遍历当前SatelliteIndex卫星的所有LSA
			{
				if ((SatelliteLSA->SourceSatellite_ID == index) && (SatelliteLSA->Metric != MAX)) {
					LinkVertex = (OpspfVertex*)malloc(sizeof(OpspfVertex));
					LinkVertex->distance = SatelliteLSA->Metric;
					LinkVertex->vertexId = SatelliteLSA->DestinationSatellite_ID;//目的节点轨道编号
					LinkVertex->NextVertex = NULL;
					tempLink->NextVertex = LinkVertex;
					tempLink = LinkVertex;
				}
				SatelliteLSA = SatelliteLSA->NextLSA;//下一条LSA

			}
		}

	}
}

//将列表设为空表
void FreeList(OpspfShortestVertex** List){
	OpspfShortestVertex* TempVertexHead;
	OpspfShortestVertex* TempVertex;
	if (*List == NULL)
	{
		return;//初始为空表
	}
	else//非空，释放空间
	{
		TempVertex = *List;
		TempVertexHead = (*List)->NextShortestVertex;
		if (TempVertex != TempVertexHead) {
			while (TempVertexHead)
			{
				free(TempVertex);
				TempVertex = TempVertexHead;
				TempVertexHead = TempVertexHead->NextShortestVertex;
			}
		}
		free(TempVertex);
		*List = NULL;
	}
}

//根据VertextId在最短路径中寻找节点
OpspfShortestVertex* SearchVertex(OpspfShortestVertex* Path, NodeAddress VertexId){
	OpspfShortestVertex* TempShortestVertex = Path;
	while (TempShortestVertex)
	{
		if (TempShortestVertex->DestinationVertex == VertexId)
		{
			return TempShortestVertex;
		}
		TempShortestVertex = TempShortestVertex->NextShortestVertex;
	}
	return NULL;
}

//为每个节点调用Dijkstra算法，生成最短路径树。
//输出path中存放当前节点ID，前驱节点ID，以当前节点ID到源节点的距离。
void Dijstra(OpspfVertex GraphLinkList[TotallNode], NodeAddress Start, OpspfShortestVertex** Path){
	OpspfVertex W;
	OpspfVertex* TempVertex;
	OpspfShortestVertex* TempShortestVertex;
	OpspfShortestVertex* TempShortestVertexHead;
	//	OspfVertex *ShortestVertex;
	unsigned int min;
	unsigned int Arcs[TotallNode];
	int i, j;
	int VertexNum;//节点编号；
	bool Known[TotallNode] = { false };

	for (i = 0; i < TotallNode; i++)
	{
		Arcs[i] = MAX;
	}
	Arcs[Start] = 0; //起始节点

					 //初始化最短路为空表
	FreeList(Path);

	//初始化最短路径首节点，指向自己，距离为0
	TempShortestVertex = (OpspfShortestVertex*)malloc(sizeof(OpspfShortestVertex));
	TempShortestVertex->distance = 0;
	TempShortestVertex->DestinationVertex = Start;
	TempShortestVertex->AdvertisingVertext = Start;//前驱节点指向自己
	TempShortestVertex->NextShortestVertex = NULL;

	*Path = TempShortestVertex; //链表首节点为当前节点自己
	TempShortestVertexHead = *Path;//指向链表中最后一个节点
	for (i = 0; i < TotallNode; i++)
	{
		min = MAX;
		for (j = 0; j < TotallNode; j++)//找到距离最小节点
		{
			if (!Known[j])
			{
				if (Arcs[j]<min)
				{
					W = GraphLinkList[j];
					min = Arcs[j];
				}
			}
		}
		VertexNum = W.vertexId;
		Known[VertexNum] = true;//标记最短路径

		TempVertex = GraphLinkList[VertexNum].NextVertex;//W的邻接点

		while (TempVertex)
		{
			VertexNum = TempVertex->vertexId;//邻接点编号
			if (!Known[VertexNum] && (min + TempVertex->distance)<Arcs[VertexNum])
			{
				//更新最短距离
				Arcs[VertexNum] = min + TempVertex->distance;
				//在最短路径列表中查找当前节点是否在最短路径列表中
				TempShortestVertex = SearchVertex(*Path, VertexNum);
				if (TempShortestVertex != NULL && TempShortestVertex->distance>Arcs[VertexNum])
				{
					//如果已经在最短路径列表中，则更新当前节点的距离值以及前驱节点编号
					TempShortestVertex->distance = Arcs[VertexNum];
					TempShortestVertex->AdvertisingVertext = W.vertexId;
				}
				else //没有在最短路径列表中,则将当前节点加入到列表中
				{
					TempShortestVertex = (OpspfShortestVertex*)malloc(sizeof(OpspfShortestVertex));
					TempShortestVertex->distance = Arcs[VertexNum];
					TempShortestVertex->DestinationVertex = VertexNum;
					TempShortestVertex->AdvertisingVertext = W.vertexId; //前驱节点为W
					TempShortestVertex->NextShortestVertex = NULL;
					TempShortestVertexHead->NextShortestVertex = TempShortestVertex;
					TempShortestVertexHead = TempShortestVertex;
				}
			}
			TempVertex = TempVertex->NextVertex;
		}
	}
}

//计算从源节点到目的节点的链表
void VertexHopForRouting(NodeAddress AdvertisingVertex,
	NodeAddress DestinationVertex,
	OpspfShortestVertex* Path,
	OpspfShortestVertex** Router)
{
	OpspfShortestVertex* PathVertex;
	OpspfShortestVertex* HeadVertex;
	OpspfShortestVertex* TempVertex;
	NodeAddress SatelliteIndex;

	SatelliteIndex = DestinationVertex;
	PathVertex = Path;

	FreeList(Router);//清空之前的链表节点

	PathVertex = (OpspfShortestVertex*)malloc(sizeof(OpspfShortestVertex));
	TempVertex = SearchVertex(Path, AdvertisingVertex);//查找源节点,且一定在在最短路径树中。


	PathVertex->AdvertisingVertext = TempVertex->AdvertisingVertext;
	PathVertex->DestinationVertex = TempVertex->DestinationVertex;
	PathVertex->distance = TempVertex->distance;
	PathVertex->NextShortestVertex = NULL;

	*Router = PathVertex;
	HeadVertex = PathVertex;
	//找到Routing节点
	while (SatelliteIndex != AdvertisingVertex)
	{
		TempVertex = SearchVertex(Path, SatelliteIndex);
		if (TempVertex == NULL)
		{
			cout << "Destination cannot be reached." << endl;
			return;
		}

		SatelliteIndex = TempVertex->AdvertisingVertext;  //当前节点的AdvertisingID是上一跳的DestinationID

		PathVertex = (OpspfShortestVertex*)malloc(sizeof(OpspfShortestVertex));
		PathVertex->AdvertisingVertext = TempVertex->AdvertisingVertext;
		PathVertex->DestinationVertex = TempVertex->DestinationVertex;
		PathVertex->distance = TempVertex->distance;
		//PathVertex->NextShortestVertex = NULL;
		//按照路跳的顺序存储路由节点
		PathVertex->NextShortestVertex = HeadVertex->NextShortestVertex;
		HeadVertex->NextShortestVertex = PathVertex;
	}
	if (HeadVertex->NextShortestVertex == NULL) {
		HeadVertex->NextShortestVertex = HeadVertex;
	}
}

//**********************************************************************************************************************************************************************************
//                                                                      切换部分
//																		切换部分
//**********************************************************************************************************************************************************************************
//S_A  计算
void UpdateSATable(Node* node, int j) {

	int sheet_s_a[48] = { 99,99,99,99,99,99,99,99,
		99,99,99,99,99,99,99,99,
		99,99,99,99,99,99,99,99,
		99,99,99,99,99,99,99,99,
		99,99,99,99,99,99,99,99,
		99,99,99,99,99,99,99,99 };
	int sheet_a_s[48] = { 99,99,99,99,99,99,99,99,
		99,99,99,99,99,99,99,99,
		99,99,99,99,99,99,99,99,
		99,99,99,99,99,99,99,99,
		99,99,99,99,99,99,99,99,
		99,99,99,99,99,99,99,99 };
	Coord sats[48];
	//int currentTime = getNodetime();
	int currentTime = j;
	Fin(currentTime, sats);
	FixLon(currentTime, sats);
	for (int i = 0; i<48; i++) {
		sheet_s_a[i] = GetAddressID(sats[i].y, sats[i].x);
	}
	for (int i = 0; i<48; i++) {
		int k = sheet_s_a[i];
		if (k % 2 == 0) {
			sheet_a_s[k] = i;
		}
	}
	for (int i = 0; i<12; i++) {
		int a = sheet_a_s[4 * i];
		int b = sheet_a_s[4 * i + 2];
		if (a % 8 == 0 && b % 8 == 7) {
			sheet_a_s[4 * i + 1] = a + 1;
			sheet_a_s[4 * i + 3] = b - 1;
		}
		else if (a % 8 == 7 && b % 8 == 0) {
			sheet_a_s[4 * i + 1] = a - 1;
			sheet_a_s[4 * i + 3] = b + 1;
		}
		else if (a % 8 == 0 && b % 8 == 1) {
			sheet_a_s[4 * i + 1] = a + 7;
			sheet_a_s[4 * i + 3] = b + 1;
		}
		else if (a % 8 == 1 && b % 8 == 0) {
			sheet_a_s[4 * i + 1] = a + 1;
			sheet_a_s[4 * i + 3] = b + 7;
		}
		else if (a % 8 == 6 && b % 8 == 7) {
			sheet_a_s[4 * i + 1] = a - 1;
			sheet_a_s[4 * i + 3] = b - 7;
		}
		else if (a % 8 == 7 && b % 8 == 6) {
			sheet_a_s[4 * i + 1] = a - 7;
			sheet_a_s[4 * i + 3] = b - 1;
		}
		else if (a<b) {
			sheet_a_s[4 * i + 1] = a - 1;
			sheet_a_s[4 * i + 3] = b + 1;
		}
		else if (a>b) {
			sheet_a_s[4 * i + 1] = a + 1;
			sheet_a_s[4 * i + 3] = b - 1;
		}
	}
	for (int i = 0; i<48; i++) {
		opspf->s_a[i] = sheet_s_a[i];
	}
	for (int i = 0; i<48; i++) {
		int n = sheet_a_s[i];
		opspf->s_a[n] = i;
	}

	//改变对地的ip  地址
	ChangeOPSPFAdderss(node);

}

double radian(double d)
{
	return d * PI / 180.0;

}

int GetAddressID(double lon, double lat) {
	int mat[12][4] = {
		0,1,2,3,
		4,5,6,7,
		8,9,10,11,
		12,13,14,15,
		16,17,18,19,
		20,21,22,23,
		24,25,26,27,
		28,29,30,31,
		32,33,34,35,
		36,37,38,39,
		40,41,42,43,
		44,45,46,47
	};
	int r, c;
	if (lon == 180) r = 5;
	else if (lon == -180) r = 11;
	else if (lon < 0) r = (-lon / 30) + 6;
	else r = lon / 30;
	if (lat == 90) c = 1;
	else if (lat == -90) c = 3;
	else if (lat < 0) c = (-lat / 45) + 2;
	else c = lat / 45;
	return mat[r][c];
}

void Fin(int t, Coord mat[48]) {
	int start_time = 0;
	ifstream infile;
	if (!infile)
	{
		cerr << "open error!" << endl;
		//exit(1);
	}
	infile.open("a_24h.bin", ios::in | ios::binary);
	for (int i = 0; i<48; i++) {
		start_time = i * 1441 + t;
		infile.seekg(sizeof(Coord) * start_time, ios_base::beg);
		infile.read((char*)(mat + i), sizeof(Coord));
	}
	infile.close();
}

double Dec(double lat) {
	double lat_fix = lat;
	if (lat>86) lat_fix = 86;
	if (lat<-86) lat_fix = -86;
	double a = radian(4);
	double b = radian(lat_fix);
	double c = tan(a)*tan(b);
	double dec = asin(c);
	return double((dec / PI) * 180);
}

void FixLon(int t, Coord sat[]) {
	Coord later[48];
	Fin(t + 1, later);
	double out;
	for (int i = 0; i<48; i++) {
		if (sat[i].x>later[i].x) {
			out = sat[i].y + Dec(sat[i].x);
			if (out>180) {
				out = -180 + (sat[i].y + Dec(sat[i].x) - 180);
			}
			else if (out<-180) {
				out = 180 + (sat[i].y + Dec(sat[i].x) + 180);
			}
			sat[i].y = out;
		}
		else {
			out = sat[i].y - Dec(sat[i].x);
			if (out<-180) {
				out = 180 + (out + 180);
			}
			else if (out>180) {
				out = -180 + (out - 180);
			}
			sat[i].y = out;
		}
	}
}

//**********************************************************************************************************************************************************************************
void ChangeOPSPFAdderss(Node* node)
{
	//Change IP
	NetworkDataIp* ip = node->networkData->networkVar;
	int inf = 6;
	if (node->nodeId <= 8 || (node->nodeId >= 41 && node->nodeId <= 48)) {
		inf = 4;
	}
	else {
		inf = 6;
	}
	IpInterfaceInfoType* interfaceInfo = ip->interfaceInfo[inf];

	interfaceInfo->ipAddress=((int)opspf->s_a[node->nodeId - 1]) * 256 * 256 * 256 + 1;
	
	ChangeAddress(inf,interfaceInfo->ipAddress);
}

//void ChangeUserAdderss(Node* node)
//{
//	NetworkDataIp* ip = node->networkData.networkVar;
//	int inf = 0;
//	IpInterfaceInfoType* interfaceInfo = ip->interfaceInfo[inf];
//
//	Address oldAddress;
//	Address sendAddress;
//
//	oldAddress.interfaceAddr.ipv4 = interfaceInfo->ipAddress;
//	oldAddress.networkType = NETWORK_IPV4;
//
//	double lon = node->mobilityData->current->position.latlonalt.longitude;
//	double lat = node->mobilityData->current->position.latlonalt.latitude;
//	int areaId = GetAddressID(lon, lat);
//	sendAddress.networkType = NETWORK_IPV4;
//	sendAddress.interfaceAddr.ipv4 = areaId * 256 * 256 * 256 + node->nodeId - 48 + 1;
//}

//**********************************************************************************************************************************************************************************
void SendBroadcastPacket(Node* node) {

	int inf = 6;
	if (node->nodeId <= 8 || (node->nodeId >= 41 && node->nodeId <= 48)) {
		inf = 4;
	}
	else {
		inf = 6;
	}

	NetworkDataIp* ip = node->networkData->networkVar;
	IpInterfaceInfoType* interfaceInfo = ip->interfaceInfo[inf];
	NodeAddress sourceAddr = interfaceInfo->ipAddress;
	NodeAddress destAddr = -1;//255.255.255.255
	char pkt[]="ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    Message* msg = (Message*)malloc(sizeof(Message));
    msg->packet = pkt;
    NetworkIpSendRawMessage(
		node, 
		msg, 
		sourceAddr, 
		destAddr, 
		inf,
        IPPROTO_IP,
		200);

}

void InitRegisterList(Node* node) {
	opspf->rList = (registerList*)malloc(sizeof(registerList));
	opspf->rList->head = NULL;
	opspf->rList->size = 0;
}

void AddRegisterListRow(Node* node, NodeAddress usrip, bool isRelay, int RelaySTId) {

	if (opspf->rList->head != NULL) {
		registerRow* tempRow = opspf->rList->head;
		while (tempRow->next != NULL) tempRow = tempRow->next;
		registerRow* newRow = (registerRow*)malloc(sizeof(registerRow));
		newRow->isRelay = isRelay;
		newRow->RelaySTId = RelaySTId;
		newRow->usrip = usrip;
		newRow->next = NULL;
		tempRow->next = newRow;
	}
	else {
		opspf->rList->head = (registerRow*)malloc(sizeof(registerRow));
		opspf->rList->head->isRelay = isRelay;
		opspf->rList->head->RelaySTId = RelaySTId;
		opspf->rList->head->usrip = usrip;
		opspf->rList->head->next = NULL;
	}
	opspf->rList->size++;
}

registerRow* FindRegisterRowByUsrIp(Node* node, NodeAddress usrip) {

	registerRow* tempRow = opspf->rList->head;
	while (tempRow != NULL) {
		if (tempRow->usrip == usrip) return tempRow;
		tempRow = tempRow->next;
	}
	return NULL;
}

void FreeRegisterList(Node* node) {

	registerRow* p = opspf->rList->head;
	if (p != NULL) {
		while (p->next != NULL) {
			opspf->rList->head = p->next;
			free(p);

			p = opspf->rList->head;
		}
		free(opspf->rList->head);
	}
	opspf->rList->head = NULL;
	opspf->rList->size = 0;
}

void OpspfAddReigsterRow(Node* node, NodeAddress usrip,bool isRelay,int RelaySTId) {


	int inf = 6;
	if (node->nodeId <= 8 || (node->nodeId >= 41 && node->nodeId <= 48)) {
		inf = 4;
	}
	else {
		inf = 6;
	}

	NetworkDataIp* ip = node->networkData->networkVar;
	IpInterfaceInfoType* interfaceInfo = ip->interfaceInfo[inf];
	NodeAddress myAddr = interfaceInfo->ipAddress;

	registerInfo* addInfo;
	addInfo->usrip=usrip;
	addInfo->isRelay=isRelay;
	addInfo->RelaySTId= RelaySTId;

	//无中继
	if (addInfo->isRelay == 0) {
		registerRow* usrRow = FindRegisterRowByUsrIp(node, addInfo->usrip);
		//有usrip  对应的表项
		if (usrRow != NULL) {
			usrRow->isRelay = addInfo->isRelay;
			usrRow->RelaySTId = addInfo->RelaySTId;
		}
		else {//没有usrip  对应的表项
			AddRegisterListRow(node, addInfo->usrip, addInfo->isRelay, addInfo->RelaySTId);
		}
		opspf->LastNoRelay = getNodetime();
	}
	else {//有中继
		registerRow* usrRow = FindRegisterRowByUsrIp(node, addInfo->usrip);
		//有usrip  对应的表项
		if (usrRow != NULL) {
			if (usrRow->isRelay != 0) {
				usrRow->isRelay = addInfo->isRelay;
				usrRow->RelaySTId = addInfo->RelaySTId;
			}
			else {
				//有中继项过期
				if (getNodetime() - opspf->LastNoRelay>1 * 1000000000) {
					usrRow->isRelay = addInfo->isRelay;
					usrRow->RelaySTId = addInfo->RelaySTId;
				}
			}
		}
		else {//没有usrip  对应的表项
			AddRegisterListRow(node, addInfo->usrip, addInfo->isRelay, addInfo->RelaySTId);
		}
	}

}

void OpspfAddRoutingTableRowById(Node* node, NodeAddress nodeId, NodeAddress dstAddr) {

	OpspfShortestVertex* a = NULL;
	OpspfShortestVertex* tempv = NULL;

	LSA* DesLsa;
	LSA* NextHopLsa;

	int DestinationIndex;

	int areaId = opspf->s_a[nodeId - 1];
	VertexHopForRouting(node->nodeId - 1, nodeId - 1, opspf->opspfShortestVertex, &a);
	//目的节点不是自己网段
	if (a->NextShortestVertex != a) {
		//得到下一跳节点的LSA
		tempv = a->NextShortestVertex;
		NextHopLsa = opspf->lsdb->LSAList;
		while (NextHopLsa) {
			if ((NextHopLsa->SourceSatellite_ID == tempv->AdvertisingVertext) && (NextHopLsa->DestinationSatellite_ID == tempv->DestinationVertex)) {
				break;
			}
			NextHopLsa = NextHopLsa->NextLSA;
		}
		while (tempv->NextShortestVertex != NULL) {
			tempv = tempv->NextShortestVertex;
		}
		//LSA存在时
		if (NextHopLsa != NULL) {
			NodeAddress DstAddress = dstAddr;
			NodeAddress NextHopAddress = opspf->idtoaddress[a->NextShortestVertex->DestinationVertex][NextHopLsa->DestinationSatellite_interface];			
			NetworkUpdateForwardingTable(node, DstAddress, 255 * 256 * 256 * 256 + 255 * 256 * 256 + 255 * 256 + 255, NextHopAddress, NextHopLsa->SourceSatellite_interface, tempv->distance);//2016826
		}
	}
	else {//目的节点是自己网段
		NodeAddress DstAddress = dstAddr;
		NodeAddress NextHopAddress = dstAddr;
		int inf = 6;
		if (node->nodeId <= 8 || (node->nodeId >= 41 && node->nodeId <= 48)) {
			inf = 4;
		}
		else {
			inf = 6;
		}
		NetworkUpdateForwardingTable(node, DstAddress, 255 * 256 * 256 * 256 + 255 * 256 * 256 + 255 * 256 + 255, NextHopAddress, inf, 0);//2016826
	}
}

//**********************************************************************************************************************************************************************************
void PrintOpspfDataInFile(Node* node) {
	OpspfData* opspf;
	ofstream outfile;
	if (!outfile) {
		cerr << "open error!" << endl; 
	}
	outfile.open("D:\\5.1\\usrdata\\output.txt", ios::out | ios::app);

	char clockStr[MAX_CLOCK_STRING_LENGTH];
	//ctoa((node->getNodeTime() / SECOND), clockStr);

	outfile << "==================================================================================" << endl;

	outfile << "Node " << node->nodeId << " at time " << clockStr << endl;

	outfile << "The RegisterList is: " << endl;

	if (opspf->rList != NULL) {
		registerRow* temp = opspf->rList->head;
		while (temp != NULL) {
			outfile << "usrip:" << hex << temp->usrip;
			outfile << " isRelay:" << temp->isRelay << " RelaySTId:" << temp->RelaySTId << endl;
			temp = temp->next;
		}
	}


	outfile.close();
}


//**********************************************************************************************************************************************************************************

//**********************************************************************************************************************************************************************************
//                                                                         接口部分
//**********************************************************************************************************************************************************************************
/**
执行vector中存储的路由删除命令，并将本地路由表清空
*/
void EmptyRouteTable(){
	cout<<"size:"<<LocalRouteTable.size()<<endl;
	if (LocalRouteTable.size()!=0)
	{
		vector<char *>::iterator it;
		for(it=LocalRouteTable.begin();it!=LocalRouteTable.end();it++){			
			cout<<"delete existed route item -"<<*it<<endl;
			system(*it);			
		}
	}
	LocalRouteTable.clear();
}

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
	char * delcon = (char *)malloc(sizeof(char) * len);  //added
	//sprintf(con, "sudo route add -net %s netmask %s gw %s metric %d dev %d",  DecDstAddress, DecDstAddressMask, DecNextHopAddress, interfaceIndex, interfaceIndex);	
	sprintf(con, "sudo route add -net %s netmask %s gw %s metric %d dev %s",  DecDstAddress, DecDstAddressMask, DecNextHopAddress, cost, "eth0");	
	//printf("%ld add route item - %s\n", strlen(con), con);
	system(con);	

	//added
	sprintf(delcon, "sudo route del -net %s netmask %s gw %s metric %d dev %s", DecDstAddress, DecDstAddressMask, DecNextHopAddress, cost, "eth0");
	LocalRouteTable.push_back(delcon);
}
