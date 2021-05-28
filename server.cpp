/*
author:朱一鸣
date:2021/05/21
description:微型安全协议的客户端程序
*/

#include <iostream>
#include <WinSock2.h>
#include <Windows.h>
#include <string>
#include <cstring>
#include <fstream>
#pragma comment(lib,"ws2_32.lib")
using namespace std;

#include <openssl/des.h>
#include <openssl/sha.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <memory.h>

#pragma comment(lib, "C:\\Users\\Dreaming\\Desktop\\大三下\\Ex1\\openssl-0[1].9.8k_WIN32\\lib\\libeay32.lib") 
#pragma comment(lib, "C:\\Users\\Dreaming\\Desktop\\大三下\\Ex1\\openssl-0[1].9.8k_WIN32\\lib\\ssleay32.lib")


#define READ_SIZE 32768
// 七种数据包
#define JOIN_REQ	(short int)1
#define PASS_REQ	(short int)2
#define PASS_ACCEPT	(short int)3
#define REJECT		(short int)4

#define PASS_RESP	(short int)5
#define TERMINATE	(short int)6

#define DATA		(short int)7

#define ENC 1
#define DEC 0
DES_key_schedule key;
char recvBuff[1010];
char sendBuff[1010];

// 四种包结构体：登录、密码、结束和数据
struct PKT_LOG{
	short int Header;
	int Payload;
};
struct PKT_PWD{
	short int Header;
	int Payload;
	char PWD[50];
};
struct PKT_END{
	short int Header;
	int Payload;
	unsigned char Digest[20];
};
struct PKT_DATA{
	short int Header;
	int Payload;
	int pkt_id;
	char Data[1000];
};


// 字符串转int用来取payload
int str2int(char *str){
	int number = 0;
	for (int i=0; *(str+i)!='\0' && i<4; i++) {
		number *= 10;
		number += *(str+i) - '0';
	}
	return number;
}

int mod8(int num){
	if(num%8 == 0)
		return num;
	else
		return num + 8 - num%8;
}

// 登录检查密码有关的包的make和demake
void mk_pkt_log(PKT_LOG *pkt,short int header){
	pkt->Header = header;
	pkt->Payload = 0;
	//char Pkt[6];
	sprintf(sendBuff ,"%d", pkt->Header);
	sprintf(sendBuff + 2 ,"%d", pkt->Payload);
	//return Pkt;
}

PKT_LOG dmk_pkt_log(char data[]){
	PKT_LOG pkt;
	pkt.Header = (short int)data[0]-48;
	pkt.Payload = 0;
	return pkt;
}

// 带有密码的包
void mk_pkt_pwd(char pwd[],PKT_PWD *pkt){
	//char Pkt[56];
	pkt->Header = PASS_RESP;
	pkt->Payload = strlen(pwd);
	strcpy(pkt->PWD,pwd);
	sprintf(sendBuff ,"%d", pkt->Header);
	sprintf(sendBuff + 2,"%d",pkt->Payload);
	strcpy(sendBuff + 6,pkt->PWD);
	//return Pkt;
}

PKT_PWD dmk_pkt_pwd(char data[]){
	PKT_PWD pkt;
	pkt.Header = (short int)data[0]-48;
	pkt.Payload = str2int(data+2);
	strcpy(pkt.PWD,data+6);
	return pkt;
}

// 带有结束信息的包
void mk_pkt_end(unsigned char *digest,PKT_END *pkt){
	//char Pkt[26];
	pkt->Header = TERMINATE;
	pkt->Payload = 20;
	memcpy(pkt->Digest,digest,20);

	sprintf(sendBuff ,"%d", pkt->Header);
	sprintf(sendBuff + 2,"%d",pkt->Payload);
	memcpy(sendBuff + 6,digest,20);
	//return Pkt;
}
PKT_END dmk_pkt_end(char data[]){
	PKT_END pkt;
	pkt.Header = (short int)data[0]-48;
	pkt.Payload = 20;
	memcpy(pkt.Digest,(unsigned char *)(data + 6),20);
	return pkt;
}

//带有数据的包
void mk_pkt_data(char data[],PKT_DATA *pkt,int id,int length){
	//char Pkt[1010];
	pkt->Header = DATA;
	pkt->Payload = length;
	pkt->pkt_id = id;
	memcpy(pkt->Data,data,mod8(length));

	sprintf(sendBuff ,"%d", pkt->Header);
	sprintf(sendBuff + 2,"%d",pkt->Payload);
	sprintf(sendBuff + 6,"%d",pkt->pkt_id);
	memcpy(sendBuff + 10,pkt->Data,mod8(length));
	//return Pkt;
}

PKT_DATA dmk_pkt_data(char data[]){
	PKT_DATA pkt;
	pkt.Header = (short int)data[0]-48;
	pkt.Payload = str2int(data+2);
	pkt.pkt_id = str2int(data+6);
	memcpy(pkt.Data,data+10,mod8(pkt.Payload));
	return pkt;
}
int mk_digest(char* path,unsigned char *digest){

	unsigned char wbuff[20] = {};
	SHA_CTX	c;
	const int bufsize = READ_SIZE;
	int bytes_read = 0;

	FILE *inpfile = fopen(path, "rb");
	if (!inpfile) {
		printf("can not open %s\n", path);
		return -1;
	}

	char *buffer = (char*)malloc(bufsize);
	memset(wbuff,0,sizeof(wbuff));
	if (!buffer) {
		printf("malloc failed\n");
		fclose(inpfile);
		return -1;
	}

	SHA1_Init(&c);
	while((bytes_read = fread(buffer, 1, bufsize, inpfile)))
		SHA1_Update(&c, buffer, bytes_read);
	SHA1_Final(wbuff,&c);

	//printf("Clear text: %s\n",rbuff);
	printf("SHA-1 digest:");
	for (int i = 0;i<sizeof(wbuff);i++)
		printf("%x",wbuff[i]);
	printf("\n");

	memcpy(digest,wbuff,20);
	fclose(inpfile);
	free(buffer);
	return 0;
}

// 把一个无符号字符串复制到另一个字符串
void copyValue(const_DES_cblock val1, unsigned char *val2, int size) {
    for(int i=0; i<size; i++) {
        val2[i] = val1[i];
    }
}

// 用两个无符号长字符（4字节），对上次加密结果和这次的明文data进行异或
void LongXor(DES_LONG *xor, DES_LONG* data, const_DES_cblock iv) {
    DES_LONG temp[2];
    memcpy(temp, iv, 8*sizeof(unsigned char));	// 转换成相同的类型
    for(int i=0; i<2; i++) {
        xor[i] = temp[i] ^ data[i];
    }
}



void dataenc(char *mdata, char *encdata, const_DES_cblock IV, int length){
	const_DES_cblock iv ;
	copyValue(IV,iv,sizeof(const_DES_cblock));
	DES_LONG data[2] = {0,0},temp[2] = {0,0};
	for( int i = 0 ; i < length ;i = i+8){
		memcpy(data, mdata + i, 8);
		LongXor(temp, data, iv);
		DES_encrypt1(temp,&key,ENC);
		memcpy(encdata + i,temp,8);
		memcpy(iv, temp, 2*sizeof(DES_LONG));
		data[0]=0;data[1]=0;
	}
}

void datadec(char *cdata, char *decdata, const_DES_cblock IV, int length){
	const_DES_cblock iv ;
	copyValue(IV,iv,sizeof(const_DES_cblock));
	DES_LONG data[2] = {0,0},temp1[2],temp2[2];
	for( int i = 0 ; i < length ;i = i+8){
		memcpy(data,cdata + i,8);
		memcpy(temp1, data, 2*sizeof(DES_LONG));
		DES_encrypt1(data,&key,DEC);
		LongXor(temp2, data, iv);
		memcpy(decdata + i ,temp2,8);
		memcpy(iv, temp1, 2*sizeof(DES_LONG)); 
		data[0]=0;data[1]=0; 
	}
}


int main(int argc, char* argv[])
{ 
	// 设置socket有关信息
	WORD wVersionRequested; 
	WSADATA wsaData; 
	int err; 
	wVersionRequested = MAKEWORD( 2, 2 ); 
	err = WSAStartup( wVersionRequested, &wsaData ); 
	if ( err != 0 ) { 
		return -1; 
	} 
	if ( LOBYTE( wsaData.wVersion ) != 2 || 
		 HIBYTE( wsaData.wVersion ) != 2 ) { 
		WSACleanup(); 
		return -1; 
	} 
	SOCKET sockSrv = socket(AF_INET,SOCK_DGRAM,0); 
	SOCKADDR_IN addrSrv; 
	addrSrv.sin_family = AF_INET; 
	addrSrv.sin_port = htons(9877); //端口号
	addrSrv.sin_addr.S_un.S_addr = htonl(INADDR_ANY); //服务器假设为本机

	if (bind(sockSrv, (sockaddr *)&addrSrv, sizeof(SOCKADDR)) == SOCKET_ERROR)
	{
		printf("\nUDP socket binding failed ERROR CODE : %d\n", WSAGetLastError());
		closesocket(sockSrv);
		WSACleanup();
		return -1;
    }
	SOCKADDR_IN addrCli;  //用户保存客户端地址

	//char *recvBuf = (char*)malloc(1010); 
	//char *sendBuf = (char*)malloc(1010); 
	FILE *recvFile ;//= fopen("decfile.txt","wb");
	FILE *sendFile = fopen("text.txt","rb");
	FILE *decFile = fopen("dectext.txt","wb");

	char *password = "thisispasswordandyouarewrite";
	int len = sizeof(SOCKADDR); 
	int ret;
	int passcount = 1;

	int keycheck;
	const_DES_cblock cbc_key = {0x40,0xfe,0xdf,0x38,0x6d,0xa1,0x3d,0x57};
	const_DES_cblock IV		 = {0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
	if ((keycheck = DES_set_key_checked(&cbc_key,&key)) != 0)
			{printf("\n生成密钥不符合要求！\n");return 0;}

	cout << "等待连接......" << endl;

	//PKT_LOG *join_req = (struct PKT_LOG *)malloc(sizeof(struct PKT_LOG));
	//sendBuf = mk_pkt_log(join_req,JOIN_REQ); 
	//发送JOIN_REQ
	//sendto(sockCli, sendBuf, 6, 0, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
	//recvfrom(sockSrv,recvBuf,200,0,(SOCKADDR*)&addrCli,&len); 
	//接受PASS_REQ

	recvfrom(sockSrv, recvBuff, 1010, 0, (SOCKADDR*)&addrCli, &len);

	while( recvBuff[0] != 0){
		//发送PASS_RESP
		switch(recvBuff[0] - 48 ){
		case JOIN_REQ:{
			PKT_LOG * pass_req = (struct PKT_LOG *)malloc(sizeof(struct PKT_LOG));
			//sendBuf = 
			mk_pkt_log(pass_req,PASS_REQ);
			sendto(sockSrv, sendBuff, 6, 0, (SOCKADDR*)&addrCli, sizeof(SOCKADDR));
			memset(sendBuff, 0, sizeof(sendBuff));
					  }
			break;
		case PASS_REQ:{
			PKT_PWD *pass_resp = (struct PKT_PWD *)malloc(sizeof(struct PKT_PWD)); 
			char *pwd = "thisispasswordandyouarewrite" ;//(char*)malloc(50);
			//sendBuf = 
			mk_pkt_pwd(pwd,pass_resp);
			sendto(sockSrv, sendBuff, 6 + strlen(sendBuff+6), 0, (SOCKADDR*)&addrCli, sizeof(SOCKADDR));
			memset(sendBuff, 0, sizeof(sendBuff));
					  }//接收PASS_ACCEPT
			break;
		case PASS_ACCEPT:{
			printf("密码验证通过，开始接受文件……\n");
						 }
			break;
		case REJECT:{
			passcount++;
			if(passcount > 3){
				printf("三次密码均失败，断开连接……\n");
			}
			else{
				PKT_PWD *pass_resp = (struct PKT_PWD *)malloc(sizeof(struct PKT_PWD)); 
				char *pwd = "thisispasswordandyouarewrite";//(char*)malloc(50);
				//sendBuf = 
				mk_pkt_pwd(pwd,pass_resp);
				sendto(sockSrv, sendBuff, 6 + strlen(sendBuff+6), 0, (SOCKADDR*)&addrCli, sizeof(SOCKADDR));
				memset(sendBuff, 0, sizeof(sendBuff));
			}
					}//接收PASS_ACCEPT
			break;
		case PASS_RESP:{
			PKT_PWD pkt_pwd = dmk_pkt_pwd(recvBuff) ;
			if(strcmp(password,pkt_pwd.PWD)){
				printf("密码错误，请重新输入\n");
				passcount ++;
				PKT_LOG *reject  = (struct PKT_LOG *)malloc(sizeof(struct PKT_LOG));
				//sendBuf = 
				mk_pkt_log(reject,REJECT);
				sendto(sockSrv, sendBuff, 6, 0, (SOCKADDR*)&addrCli, sizeof(SOCKADDR));
				memset(sendBuff, 0, sizeof(sendBuff));
			}
			else{
				printf("密码正确，开始发送数据\n");
				PKT_LOG *pass_accept  = (struct PKT_LOG *)malloc(sizeof(struct PKT_LOG));
				//sendBuf = 
				mk_pkt_log(pass_accept,PASS_ACCEPT);
				sendto(sockSrv, sendBuff, 6, 0, (SOCKADDR*)&addrCli, sizeof(SOCKADDR));
				memset(sendBuff, 0, sizeof(sendBuff));
				int count;
				char mdata[1000]   = {};
				char encdata[1000] = {};
				char decdata[1000] = {};
				int id = 1;
				while (count = fread(mdata, 1, 1000, sendFile)){
					PKT_DATA *pkt_data  = (struct PKT_DATA *)malloc((sizeof(struct PKT_DATA)));
					//cout<<"data数据包大小："<<sizeof(struct PKT_DATA)<<endl;
					dataenc(mdata,encdata,IV,count);
					//datadec(encdata,decdata,IV,count);
					//fwrite(decdata,1,count,decFile);这里没有问题
					//sendBuf = 
					mk_pkt_data(encdata,pkt_data,id,count); //这里有问题了
					PKT_DATA mpkt_data = dmk_pkt_data(sendBuff);
					datadec(mpkt_data.Data,decdata,IV,mpkt_data.Payload);
					fwrite(decdata,1,mpkt_data.Payload,decFile);

					sendto(sockSrv, sendBuff, 1010, 0, (SOCKADDR*)&addrCli, sizeof(SOCKADDR));
					memset(sendBuff, 0, sizeof(sendBuff));
					id ++;
				}
				fclose(sendFile);
				//结束时发送摘要
				char* path = "text.txt"; unsigned char digest[20] = {} ;
				mk_digest(path,digest);
				PKT_END *pkt_end  = (struct PKT_END *)malloc(sizeof(struct PKT_END));
				//sendBuf = 
				mk_pkt_end(digest,pkt_end);
				sendto(sockSrv,sendBuff,26,0,(SOCKADDR*)&addrCli,len); 
				memset(sendBuff, 0, sizeof(sendBuff));
			}
			if(passcount > 3){
				printf("连续三次输错密码，服务器关闭\n");
				closesocket(sockSrv);
				WSACleanup(); 
				return 0;
			}
					   }
			break;
		case TERMINATE:{
			fclose(recvFile);
			char* decfilepath = "decfile.txt";unsigned char decfiledigest[20] = {};
			mk_digest(decfilepath,decfiledigest);
			PKT_END terminate = dmk_pkt_end(recvBuff);
			if(memcmp(decfiledigest,terminate.Digest,20)){
				printf("解密文件的摘要和传输过来的不同\n");
			}
			else{
				printf("接受到正确的文件\n");
			}
					   }
			break;
		case DATA:{
			PKT_DATA pkt_data = dmk_pkt_data(recvBuff);
			char decdata[1000] = {};
			datadec(pkt_data.Data,decdata,IV,pkt_data.Payload);
			fwrite(decdata,1,pkt_data.Payload,recvFile);
				  }
			break;
		default:
			break;
		}
		//memset(recvBuff, 0, sizeof(sendBuff));
		recvfrom(sockSrv, recvBuff, 1010, 0, (SOCKADDR*)&addrCli, &len);
	}
	closesocket(sockSrv);
	WSACleanup(); 
	return 0;
} 
