#include <stdio.h>
#include <time.h>
#include <Winsock2.h>
#include <Windows.h> 
#pragma comment (lib, "ws2_32.lib")
// 2字节 对齐 sizeof(icmp_header) == 8 
// 这是ping 在wireshark抓包中的数据结构 
typedef struct icmp_header {
	unsigned char icmp_type;
	// 消息类型
	unsigned char icmp_code;
	// 代码
	unsigned short icmp_checksum;
	// 校验和
	unsigned short icmp_id;
	// 用来惟一标识此请求的ID号，通常设置为进程ID
	unsigned short icmp_sequence;
	// 序列号
}
icmp_header;
#define ICMP_HEADER_SIZE sizeof(icmp_header)
#define ICMP_ECHO_REQUEST 0x08
#define ICMP_ECHO_REPLY 0x00
// 计算校验和 
unsigned short chsum(struct icmp_header *picmp, int len) {
	long sum = 0;
	unsigned short *pusicmp = (unsigned short *)picmp;
	while ( len > 1 ) {
		sum += *(pusicmp++);
		if ( sum & 0x80000000 ) {
			sum = (sum & 0xffff) + (sum >> 16);
		}
		len -= 2;
	}
	if ( len ) {
		sum += (unsigned short)*(unsigned char *)pusicmp;
	}
	while ( sum >> 16 ) {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	return (unsigned short)~sum;
}
static int respNum = 0;
static int minTime = 0,maxTime = 0,sumTime = 0;
int allTime[4];
static int Time_j=0;
int ping(char *szDestIp) {
	int bRet = 1;
	WSADATA wsaData;
	int nTimeOut = 1000;
	//1000ms  
	char szBuff[ICMP_HEADER_SIZE + 32] = {
		0
	}
	;
	icmp_header *pIcmp = (icmp_header *)szBuff;
	char icmp_data[32] = {
		0
	}
	;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	// 创建原始套接字
	SOCKET s = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
	// 设置接收超时
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char const*)&nTimeOut, sizeof(nTimeOut));
	// 设置目的地址
	sockaddr_in dest_addr;
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_addr.S_un.S_addr = inet_addr(szDestIp);
	dest_addr.sin_port = htons(0);
	// 构造ICMP封包
	pIcmp->icmp_type = ICMP_ECHO_REQUEST;
	pIcmp->icmp_code = 0;
	pIcmp->icmp_id = (USHORT)::GetCurrentProcessId();
	pIcmp->icmp_sequence = 0;
	pIcmp->icmp_checksum = 0;
	// 填充数据，可以任意 
	memcpy((szBuff + ICMP_HEADER_SIZE), "abcdefghijklmnopqrstuvwabcdefghi", 32);
	// 计算校验和
	pIcmp->icmp_checksum = chsum((struct icmp_header *)szBuff, sizeof(szBuff));
	sockaddr_in from_addr;
	char szRecvBuff[1024];
	int nLen = sizeof(from_addr);
	int ret,flag = 0;
	DWORD  start = GetTickCount();
	ret = sendto(s, szBuff, sizeof(szBuff), 0, (SOCKADDR *)&dest_addr, sizeof(SOCKADDR));
	int i = 0;
	//这里一定要用while循环，因为recvfrom 会接受到很多报文，包括发送出去的报文也会被收到 
	while(1) {
		if(i++ > 5) {
			// icmp报文 如果到不了目标主机，是不会返回报文，多尝试几次接受数据，如果都没收到 即请求失败 
			flag = 1;
			break;
		}
		memset(szRecvBuff,0,1024);
		int ret = recvfrom(s, szRecvBuff, MAXBYTE, 0, (SOCKADDR *)&from_addr, &nLen);
		//printf("errorCode2:%d\n",WSAGetLastError() ); 
		//printf("ret=%d,%s\n",ret,inet_ntoa(from_addr.sin_addr)) ; 
		//接受到 目标ip的 报文 
		respNum++;
		break;
	}
	int  end = GetTickCount();
	int time = end -start;
	if(flag) {
		printf("Request time out.\n");
		return bRet;
	}
	//计算时间之和
	sumTime += time;
	//响应时间存入数组
	allTime[Time_j] = time;
	Time_j++;
	//计算最大时间
	if( maxTime < time) {
		maxTime = time;
	}
	// Windows的原始套接字 开发，系统没有去掉IP协议头，需要程序自己处理。
	// ip头部的第一个字节（只有1个字节不涉及大小端问题），前4位 表示 ip协议版本号，后4位 表示IP 头部长度(单位为4字节)
	char ipInfo = szRecvBuff[0];
	// ipv4头部的第9个字节为TTL的值
	char ttl = szRecvBuff[8];
	//printf("ipInfo = %x\n",ipInfo);
	//回显应答报文 
	if(time >= nTimeOut) {
		respNum--;
		printf("Request time out.\n");
	} else {
		printf("来自 %s 的回复：字节=32 时间=%2dms TTL=%d\n", szDestIp, time, ttl);
	}
	return bRet;
}
char* dns() {
	//  调用WSAStarup初始化WINsock库
	WSADATA wsaData;
	::WSAStartup(
	MAKEWORD(2,2),
	&wsaData);
	//  输入域名、服务器名或IP地址，例如idealist-haoyu.top或localhost或43.129.172.52
	char szHost[200];
	printf("ping ");
	scanf("%s",szHost);
	//  解析域名
	hostent *pHost = gethostbyname(szHost);
	in_addr addr;
	int i;
	char *Ip;
	for ( i = 0;; i++) {
		char *p = pHost->h_addr_list[i];
		if (p == NULL) {
			break;
		}
		memcpy(&addr.S_un.S_addr,p,pHost->h_length);
		char *strIp = ::inet_ntoa(addr);
		Ip = strIp;
	}
	::WSACleanup();
	printf("\n正在 Ping %s [%s] 具有 32 字节的数据:\n", szHost,Ip);
	return Ip;
}
int main() {
	while(1) {
		printf("\n----输入目标主机域名或IP地址----\n\n");
		int i = 0;
		//解析域名
		char *Ip = dns();
		respNum = 0,minTime = 0,maxTime = 0,sumTime = 0,Time_j = 0;
		//发送 4 个 ICMP 回送请求报文
		while ( i < 4 ) {
			int result = ping(Ip);
			Sleep(500);
			i ++;
		}
		minTime = allTime[0];
		for (i=0;i<4;i++) {
			if(allTime[i]<minTime) {
				minTime=allTime[i];
			}
		}
		//打印统计信息
		printf("\n%s 的 Ping 统计信息:\n", Ip);
		if( i-respNum >= 4) {
			printf("    数据包: 已发送 = %d，已接收 = %d，丢失 = %d (%d%% 丢失)，\n", i, respNum, i-respNum, (i-respNum)*100/i);
			continue;
		}
		printf("    数据包: 已发送 = %d，已接收 = %d，丢失 = %d (%d%% 丢失)，\n", i, respNum, i-respNum, (i-respNum)*100/i);
		printf("往返行程的估计时间(以毫秒为单位):\n");
		printf("    最短 = %dms，最长 = %dms，平均 = %dms\n", minTime, maxTime, sumTime/respNum);
	}
	return 0;
}