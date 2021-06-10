/*
author:朱一鸣
date:2021/05/21
description:微型安全协议的客户端程序
*/

//有关网络和文件的一些库
#include <iostream>
#include <WinSock2.h>
#include <Windows.h>
#include <string>
#include <cstring>
#include <fstream>
#pragma comment(lib,"ws2_32.lib")
using namespace std;

//有关openssl加密、摘要函数的一些库
#include <openssl/des.h>
#include <openssl/sha.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <memory.h>

#pragma comment(lib, "C:\\Users\\Administrator\\Desktop\\课件\\大三下\\算法协议\\Ex1\\Ex1\\openssl-0[1].9.8k_WIN32\\lib\\libeay32.lib") //通过绝对路径链接到libeay32.lib
#pragma comment(lib, "C:\\Users\\Administrator\\Desktop\\课件\\大三下\\算法协议\\Ex1\\Ex1\\openssl-0[1].9.8k_WIN32\\lib\\ssleay32.lib") //通过绝对路径链接到ssleay32.lib

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
char recvBuff[1010]; //接受缓冲区
char sendBuff[1010]; //发送缓冲区

// 四种包结构体：登录、密码、结束和数据
struct PKT_LOG{
	short int Header;
	int Payload;
};
struct PKT_PWD{
	short int Header;
	int Payload;
	char PWD[50];			  //密码长度最长为50个字节
};
struct PKT_END{
	short int Header;
	int Payload;
	unsigned char Digest[20]; //sha1摘要的长度为20个字节
};
struct PKT_DATA{
	short int Header;
	int Payload;
	int pkt_id;
	char Data[1000];		  //数据包的数据长度为1000个字节
};


// 4个字节的字符串转int用来取payload，或者数据包id
int str2int(char *str){
	int number  = 0;
	for (int i=0; *(str+i)!='\0' && i<4; i++) {
		number *= 10;
		number += *(str+i) - '0';
	}
	return number;
}

//向8对齐，用于加解密时复制超过length的数据
int mod8(int num){
	if(num%8 == 0)
		return num;
	else
		return num + 8 - num%8;
}

// 登录检查密码有关的包的打包和解包
void mk_pkt_log(PKT_LOG *pkt,short int header){
	pkt->Header  = header;
	pkt->Payload = 0;
	sprintf(sendBuff ,"%d", pkt->Header);
	sprintf(sendBuff + 2 ,"%d", pkt->Payload);
}

PKT_LOG dmk_pkt_log(char data[]){
	PKT_LOG pkt;
	pkt.Header  = (short int)data[0]-48;
	pkt.Payload = 0;
	return pkt;
}

// 带有密码的包的打包和解包
void mk_pkt_pwd(char pwd[],PKT_PWD *pkt){
	pkt->Header  = PASS_RESP;
	pkt->Payload = strlen(pwd);
	strcpy(pkt->PWD,pwd);
	sprintf(sendBuff ,"%d", pkt->Header);
	sprintf(sendBuff + 2,"%d",pkt->Payload);
	strcpy( sendBuff + 6,pkt->PWD);
}

PKT_PWD dmk_pkt_pwd(char data[]){
	PKT_PWD pkt;
	pkt.Header  = (short int)data[0]-48;
	pkt.Payload = str2int(data+2);
	strcpy(pkt.PWD,data+6);
	return pkt;
}

// 带有结束信息的包的打包和解包
void mk_pkt_end(unsigned char *digest,PKT_END *pkt){
	pkt->Header  = TERMINATE;
	pkt->Payload = 20;
	memcpy(pkt->Digest,digest,20);

	sprintf(sendBuff ,"%d", pkt->Header);
	sprintf(sendBuff + 2,"%d",pkt->Payload);
	memcpy( sendBuff + 6,digest,20);
}

PKT_END dmk_pkt_end(char data[]){
	PKT_END pkt;
	pkt.Header  = (short int)data[0]-48;
	pkt.Payload = 20;
	memcpy(pkt.Digest,(unsigned char *)(data + 6),20);
	return pkt;
}

//带有数据的包的打包和解包
void mk_pkt_data(char data[],PKT_DATA *pkt,int id,int length){
	pkt->Header  = DATA;
	pkt->Payload = length;
	pkt->pkt_id  = id;
	memcpy(pkt->Data,data,mod8(length));	//加密后的数据的包长度向8对齐

	sprintf(sendBuff ,"%d", pkt->Header);
	sprintf(sendBuff + 2,"%d",pkt->Payload);
	sprintf(sendBuff + 6,"%d",pkt->pkt_id);
	memcpy( sendBuff + 10,pkt->Data,mod8(length));
}

PKT_DATA dmk_pkt_data(char data[]){
	PKT_DATA pkt;
	pkt.Header  = (short int)data[0]-48;	//字符串转成short int
	pkt.Payload = str2int(data+2);
	pkt.pkt_id  = str2int(data+6);
	memcpy(pkt.Data,data+10,mod8(pkt.Payload));
	return pkt;
}


// 用sha1来获取20个字节的digest
int mk_digest(char* path,unsigned char *digest){

	unsigned char wbuff[20] = {};
	SHA_CTX	c;
	const int bufsize = READ_SIZE;
	int bytes_read = 0;

	//读取文件
	FILE *inpfile = fopen(path, "rb");
	if (!inpfile) {
		printf("can not open %s\n", path);
		return -1;
	}

	//逐块计算sha1的缓冲区
	char *buffer = (char*)malloc(bufsize);
	memset(wbuff,0,sizeof(wbuff));
	if (!buffer) {
		printf("malloc failed\n");
		fclose(inpfile);
		return -1;
	}

	//计算sha1给wbuff
	SHA1_Init(&c);
	while((bytes_read = fread(buffer, 1, bufsize, inpfile)))
		SHA1_Update(&c, buffer, bytes_read);
	SHA1_Final(wbuff,&c);

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

// 对字符串数据进行cbcdes解密
void dataenc(char *mdata, char *encdata, const_DES_cblock IV, int length){
	const_DES_cblock iv ;
	copyValue(IV,iv,sizeof(const_DES_cblock));	//局部变量iv，防止改变解密时的iv
	DES_LONG data[2] = {0,0},temp[2] = {0,0};	//加密数据和中间量
	for( int i = 0 ; i < length ;i = i+8){
		memcpy(data, mdata + i, 8);		//把第i块（8个字节）的明文给data，进行加密
		LongXor(temp, data, iv);		//与iv异或得到temp
		DES_encrypt1(temp,&key,ENC);		//对temp进行加密
		memcpy(encdata + i,temp,8);		//把加密结果写到第i块密文
		memcpy(iv, temp, 2*sizeof(DES_LONG));	//把密文复制到iv用于下一轮加密
		data[0]=0;data[1]=0;			//清零
	}
}

// 对字符串数据进行cbcdes解密
void datadec(char *cdata, char *decdata, const_DES_cblock IV, int length){
	const_DES_cblock iv ;
	copyValue(IV,iv,sizeof(const_DES_cblock));	
	DES_LONG data[2] = {0,0},temp1[2],temp2[2];
	for( int i = 0 ; i < length ;i = i+8){
		memcpy(data,cdata + i,8);		//把密文复制给data进行解密
		memcpy(temp1, data, 2*sizeof(DES_LONG));//保存到temp1，作为下一次的iv
		DES_encrypt1(data,&key,DEC);		//解密到data
		LongXor(temp2, data, iv);		//data和iv异或得到明文temp2
		memcpy(decdata + i ,temp2,8);		//明文保存下来
		memcpy(iv, temp1, 2*sizeof(DES_LONG));	//保留的密文作为iv给下一轮解密
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
		WSACleanup( ); 
		return -1; 
	} 

	SOCKET sockCli = socket(AF_INET,SOCK_DGRAM,0); 
	SOCKADDR_IN addrSrv; 
	addrSrv.sin_family = AF_INET; 
	addrSrv.sin_port = htons(9877); //端口号，应该为argv[]
	addrSrv.sin_addr.S_un.S_addr = inet_addr("127.0.0.1"); //服务器假设为本机
	
	FILE *recvFile = fopen("decfile.txt","wb");		//客户端创建接收的文件
	FILE *sendFile ;//= fopen("text.txt","rb");
	if (!recvFile) {
		printf("can not open, %s\n", "text.txt");
		return -1;
	}

	char *password = "thisispasswordandyouarewrite";	//密码（调试时的预先设置的）
	int len = sizeof(SOCKADDR); 
	int passcount = 1;	//计算错误密码次数
	int idcount = 1;	//计算接到的包的id

	int keycheck;
	const_DES_cblock cbc_key = {0x40,0xfe,0xdf,0x38,0x6d,0xa1,0x3d,0x57};
	const_DES_cblock IV	 = {0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
	if ((keycheck = DES_set_key_checked(&cbc_key,&key)) != 0)
			{printf("\n生成密钥不符合要求！\n");return 0;}

	cout << "发送连接请求......" << endl;
	
	PKT_LOG *join_req = (struct PKT_LOG *)malloc(sizeof(struct PKT_LOG));
	mk_pkt_log(join_req,JOIN_REQ); 
	//发送JOIN_REQ
	sendto(sockCli, sendBuff, 1010, 0, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
	free(join_req);
	memset(sendBuff, 0, sizeof(sendBuff));
	//接受PASS_REQ
	recvfrom(sockCli, recvBuff, 1010, 0, (SOCKADDR*)&addrSrv, &len);
	
	while( recvBuff[0] != 0){
		switch(recvBuff[0] - 48 ){
		case JOIN_REQ:{
			PKT_LOG * pass_req = (struct PKT_LOG *)malloc(sizeof(struct PKT_LOG));
			mk_pkt_log(pass_req,PASS_REQ);
			//发送PASS_REQ
			sendto(sockCli, sendBuff, 6, 0, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
			free(pass_req);
			memset(sendBuff, 0, sizeof(sendBuff));
					  }
			break;
		case PASS_REQ:{
			PKT_PWD *pass_resp = (struct PKT_PWD *)malloc(sizeof(struct PKT_PWD)); 
			char *pwd = "thisispasswordandyouarewrite1" ;
			//发送PASS_RESP
			mk_pkt_pwd(pwd,pass_resp);
			sendto(sockCli, sendBuff, 6 + strlen(sendBuff+6), 0, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
			free(pass_resp);
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
				char *pwd = "thisispasswordandyouarewrite"; // 应该修改成参数的argv[]
				printf("发送第二个密码:%s\n",pwd);
				//sendBuf = 
				//发送第二个和第三个密码
				mk_pkt_pwd(pwd,pass_resp);
				sendto(sockCli, sendBuff, 6 + strlen(sendBuff+6), 0, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
				free(pass_resp);
				memset(sendBuff, 0, sizeof(sendBuff));
			}
					}
			break;
		case PASS_RESP:{
			PKT_PWD pkt_pwd = dmk_pkt_pwd(recvBuff) ;
			if(strcmp(password,pkt_pwd.PWD)){
				printf("密码错误，请重新输入\n");
				passcount ++;
				PKT_LOG *reject  = (struct PKT_LOG *)malloc(sizeof(struct PKT_LOG));
				mk_pkt_log(reject,REJECT);
				//错误发送REJECT
				sendto(sockCli, sendBuff, 6, 0, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
				free(reject);
				memset(sendBuff, 0, sizeof(sendBuff));
			}
			else{
				printf("密码正确，开始发送数据\n");
				PKT_LOG *pass_accept  = (struct PKT_LOG *)malloc(sizeof(struct PKT_LOG));
				mk_pkt_log(pass_accept,PASS_ACCEPT);
				//发送PASS_ACCEPT，之后开始发送数据
				sendto(sockCli, sendBuff, 6, 0, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
				free(pass_accept);
				memset(sendBuff, 0, sizeof(sendBuff));
				int count;
				char mdata[1000]   = {}; //明文
				char encdata[1000] = {}; //密文
				int id = 1;
				PKT_DATA *pkt_data  = (struct PKT_DATA *)malloc(sizeof(struct PKT_DATA));	
				//发送进行加密过后的数据
				while ((count = fread(mdata, 1, 1000, sendFile)) > 0){
					dataenc(mdata,encdata,IV,count); //进行加密
					mk_pkt_data(encdata,pkt_data,id,count); //将加密数据打包发送
					sendto(sockCli, sendBuff, 1010, 0, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
					memset(sendBuff, 0, sizeof(sendBuff));
					id ++;
				}
				free(pkt_data);
				fclose(sendFile);
				//结束时发送摘要
				char* path = "text.txt"; unsigned char digest[20] = {} ; //应该为argv[]
				mk_digest(path,digest);
				PKT_END *pkt_end  = (struct PKT_END *)malloc(sizeof(struct PKT_END));
				mk_pkt_end(digest,pkt_end);
				sendto(sockCli,sendBuff,26,0,(SOCKADDR*)&addrSrv,len); 
				free(pkt_end);
				memset(sendBuff, 0, sizeof(sendBuff));
			}
			if(passcount > 3){
				printf("连续三次输错密码，服务器关闭\n");
				closesocket(sockCli);
				WSACleanup(); 
				return 0;
			}
					   }
			break;
		case TERMINATE:{
			//接受到TERMINATE包，对比和解密后得到的文件，摘要是否相同
			fclose(recvFile);
			char* decfilepath = "decfile.txt";unsigned char decfiledigest[20] = {};
			mk_digest(decfilepath,decfiledigest);
			PKT_END terminate = dmk_pkt_end(recvBuff);
			if(memcmp(decfiledigest,terminate.Digest,20)){
				printf("解密文件的摘要和传输过来的不同！ABORT！\n");
			}
			else{
				printf("接受到正确的文件\n");
				recvBuff[0] = 0;
				sendto(sockCli,sendBuff,1,0,(SOCKADDR*)&addrSrv,len); 
			}
					   }
			break;
		case DATA:{
			//接受到DATA包，解密后写到文件中
			PKT_DATA pkt_data = dmk_pkt_data(recvBuff);
			if(pkt_data.pkt_id != idcount)
				cout<<"接受到错误的数据包！ABORT！"<<endl;
			idcount++;
			char decdata[1000] = {};
			datadec(pkt_data.Data,decdata,IV,pkt_data.Payload);
			fwrite(decdata,1,pkt_data.Payload,recvFile);
				  }
			break;
		default:
			break;
		}
		memset(recvBuff, 0, sizeof(sendBuff));
		recvfrom(sockCli, recvBuff, 1010, 0, (SOCKADDR*)&addrSrv, &len);
	}
	closesocket(sockCli);
	WSACleanup(); 
	return 0;
} 
