/*
author:��һ��
date:2021/05/21
description:΢�Ͱ�ȫЭ��Ŀͻ��˳���
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

#pragma comment(lib, "C:\\Users\\Administrator\\Desktop\\�μ�\\������\\�㷨Э��\\Ex1\\Ex1\\openssl-0[1].9.8k_WIN32\\lib\\libeay32.lib") 
#pragma comment(lib, "C:\\Users\\Administrator\\Desktop\\�μ�\\������\\�㷨Э��\\Ex1\\Ex1\\openssl-0[1].9.8k_WIN32\\lib\\ssleay32.lib")



#define READ_SIZE 32768
// �������ݰ�
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



// ���ְ��ṹ�壺��¼�����롢����������
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
	char Digest[20];
};
struct PKT_DATA{
	short int Header;
	int Payload;
	int pkt_id;
	char Data[1000];
};


// �ַ���תint����ȡpayload
int str2int(char *str){
	int number = 0;
	for (int i=0; *(str+i)!='\0' && i<4; i++) {
		number *= 10;
		number += *(str+i) - '0';
	}
	return number;
}

// ��¼��������йصİ���make��demake
char* mk_pkt_log(PKT_LOG pkt,short int header){
	pkt.Header = header;
	pkt.Payload = 0;
	char Pkt[6];
	sprintf(Pkt ,"%d", pkt.Header);
	sprintf(Pkt + 2 ,"%d", pkt.Payload);
	return Pkt;
}

PKT_LOG dmk_pkt_log(char data[]){
	PKT_LOG pkt;
	pkt.Header = (short int)data[0]-48;
	pkt.Payload = 0;
	return pkt;
}

// ��������İ�
char* mk_pkt_pwd(char pwd[],PKT_PWD pkt){
	char Pkt[56];
	pkt.Header = PASS_RESP;
	pkt.Payload = sizeof(pwd);
	sprintf(Pkt ,"%d", pkt.Header);
	sprintf(Pkt+2,"%d",pkt.Payload);
	memcpy(Pkt+6,pwd,strlen(pwd)+1);
	return Pkt;
}
PKT_PWD dmk_pkt_pwd(char data[]){
	PKT_PWD pkt;
	pkt.Header = (short int)data[0]-48;
	pkt.Payload = str2int(data+2);
	memcpy(pkt.PWD,data+6,pkt.Payload);
	return pkt;
}

// ���н�����Ϣ�İ�
char* mk_pkt_end(char *digest,PKT_END pkt){
	char Pkt[26];
	pkt.Header = TERMINATE;
	pkt.Payload = 20;
	memcpy(pkt.Digest,digest,20);
	sprintf(Pkt ,"%d", pkt.Header);
	sprintf(Pkt+2,"%d",pkt.Payload);
	memcpy(Pkt+6,digest,20);
	return Pkt;
}
PKT_END dmk_pkt_end(char data[]){
	PKT_END pkt;
	pkt.Header = (short int)data[0]-48;
	pkt.Payload = str2int(data+2);
	memcpy(pkt.Digest,data+6,pkt.Payload);
	return pkt;
}

//�������ݵİ�

char* mk_pkt_data(char data[],PKT_DATA pkt,int id){
	char Pkt[1006];
	pkt.Header = DATA;
	pkt.Payload = sizeof(data);
	pkt.pkt_id = id;
	memcpy(pkt.Data,data,sizeof(data));
	sprintf(Pkt ,"%d", pkt.Header);
	sprintf(Pkt+2,"%d",pkt.Payload);
	sprintf(Pkt+6,"%d",pkt.pkt_id);
	memcpy(Pkt+10,data,pkt.Payload);
	return Pkt;
}

PKT_DATA dmk_pkt_data(char data[]){
	PKT_DATA pkt;
	pkt.Header = (short int)data[0]-48;
	pkt.Payload = str2int(data+2);
	pkt.pkt_id = str2int(data+6);
	memcpy(pkt.Data,data+10,pkt.Payload);
	return pkt;
}

int mk_digest(char* path, unsigned char *digest){

	//int i;
	//unsigned char rbuff[]="SHA-1 Clear Text";
	//unsigned char wbuff[20];
	SHA_CTX	c;

	char *buffer = NULL;
	const int bufsize = READ_SIZE;
	int bytes_read = 0;

	FILE *inpfile = fopen(path, "rb");
	if (!inpfile) {
		printf("%s: can not open %s\n", __func__, path);
		return -1;
	}

	buffer = (char*)malloc(bufsize);
	//memset(wbuff,0,sizeof(wbuff));
	if (!buffer) {
		printf("%s: malloc failed\n", __func__);
		fclose(inpfile);
		return -1;
	}

	SHA1_Init(&c);
	while((bytes_read = fread(buffer, 1, bufsize, inpfile)))
		SHA1_Update(&c, buffer, bytes_read);
	SHA1_Final(digest,&c);

	//printf("Clear text: %s\n",rbuff);
	printf("SHA-1 digest:");
	for (int i=0;i<sizeof(digest);i++)
		printf("%x",digest[i]);
	printf("\n");

	fclose(inpfile);
	free(buffer);

	return 0;
}

// ��һ���޷����ַ������Ƶ���һ���ַ���
void copyValue(const_DES_cblock val1, unsigned char *val2, int size) {
    for(int i=0; i<size; i++) {
        val2[i] = val1[i];
    }
}

// �������޷��ų��ַ���4�ֽڣ������ϴμ��ܽ������ε�����data�������
void LongXor(DES_LONG *xor, DES_LONG* data, const_DES_cblock iv) {
    DES_LONG temp[2];
    memcpy(temp, iv, 8*sizeof(unsigned char));	// ת������ͬ������
    for(int i=0; i<2; i++) {
        xor[i] = temp[i] ^ data[i];
    }
}

void dataenc(FILE *inpFile,FILE *outFile,const_DES_cblock IV){
	const_DES_cblock iv ;
	copyValue(IV,iv,sizeof(const_DES_cblock));
	DES_LONG data[2] = {0,0},temp[2] = {0,0}; // data��������ÿ�ζ�ȡ��8�ֽ�64���ص����ݣ�temp����������ܺ������
	int mRead = fread(data, 1, 8, inpFile); // �������ж�ȡ8�ֽڵ�����
	while(mRead > 0){ // ���ܹ��������ж������ݵ�ʱ��
		LongXor(temp, data, iv); // �Ƚ����ݺ�iv���
		DES_encrypt1(temp,&key,ENC); // ���Ľ�����м���
		fwrite(temp, 8, 1, outFile); // �����ܵĽ��д��������
		memcpy(iv, temp, 2*sizeof(DES_LONG)); // �����ܵĽ����Ϊ��һ�ε�iv�������
		data[0]=0;data[1]=0; // ��0���data
		mRead = fread(data, 1, 8, inpFile);
	}
	printf("�������\n");	//�������
}


int main(int argc, char* argv[])
{ 
	// ����socket�й���Ϣ
	WORD wVersionRequested; 
	WSADATA wsaData; 
	int err; 
	wVersionRequested = MAKEWORD( 2, 2 ); 
	err = WSAStartup( wVersionRequested, &wsaData ); 
	if ( err != 0 ) { 
		return; 
	} 
	if ( LOBYTE( wsaData.wVersion ) != 2 || 
		 HIBYTE( wsaData.wVersion ) != 2 ) { 
		WSACleanup( ); 
		return; 
	} 
	SOCKET sockCli = socket(AF_INET,SOCK_DGRAM,0); 
	SOCKADDR_IN addrSrv; 
	addrSrv.sin_family = AF_INET; 
	addrSrv.sin_port = htons(5050); //�˿ں�
	addrSrv.sin_addr.S_un.S_addr = inet_addr("127.0.0.1"); //����������Ϊ����
	char *recvBuf; 
	char *sendBuf; 
	char *password = "thisispasswordandyouarewrite";
	int len = sizeof(SOCKADDR); 
	int ret;
	int passcount = 1;

	int keycheck;
	const_DES_cblock cbc_key = {0x40,0xfe,0xdf,0x38,0x6d,0xa1,0x3d,0x57};
	const_DES_cblock IV = {0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
	if ((keycheck = DES_set_key_checked(&cbc_key,&key)) != 0)
			{printf("\n������Կ������Ҫ��\n");return 0;}

	cout << "������������......" << endl;

	PKT_LOG join_req;
	sendBuf = mk_pkt_log(join_req,JOIN_REQ); 
	//����JOIN_REQ
	sendto(sockCli, sendBuf, 6, 0, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
	//����PASS_REQ
	while( ret = recvfrom(sockCli, recvBuf, 6, 0, (SOCKADDR*)&addrSrv, &len)){
		//����PASS_RESP
		switch(recvBuf[0] - 48 ){
		case JOIN_REQ:
			PKT_LOG pass_req;
			sendBuf = mk_pkt_log(pass_req,PASS_REQ);
			sendto(sockCli, sendBuf, 6, 0, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
			break;
		case PASS_REQ:
			PKT_PWD pass_resp; char *pwd;
			sendBuf = mk_pkt_pwd(pwd,pass_resp);
			sendto(sockCli, sendBuf, 6 + strlen(sendBuf+6), 0, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
			//����PASS_ACCEPT
			break;
		case PASS_ACCEPT:
			printf("������֤ͨ������ʼ�����ļ�����\n");
			break;
		case REJECT:
			passcount++;
			if(passcount > 3){
				printf("���������ʧ�ܣ��Ͽ����ӡ���\n");
			}
			else{
				PKT_PWD pass_resp; char *pwd;
				sendBuf = mk_pkt_pwd(pwd,pass_resp);
				sendto(sockCli, sendBuf, 6 + strlen(sendBuf+6), 0, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
			}
			//����PASS_ACCEPT
			break;
		case PASS_RESP:
			PKT_PWD pkt_pwd;
			pkt_pwd = dmk_pkt_pwd(recvBuf);
			if(strcmp(password,pkt_pwd.PWD)){
				printf("�����������������\n");
				passcount ++;
				PKT_LOG reject;
				sendBuf = mk_pkt_log(reject,REJECT);
				sendto(sockCli, sendBuf, 6, 0, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
			}
			else{
				printf("������ȷ����ʼ��������\n");
				PKT_LOG pass_accept;
				sendBuf = mk_pkt_log(pass_accept,PASS_ACCEPT);
				sendto(sockCli, sendBuf, 6, 0, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));




			}
			if(passcount > 3){
				printf("��������������룬�������ر�\n");
				closesocket(sockCli);
				WSACleanup(); 
				return 0;
			}
			break;
		case TERMINATE:
			char* decfilepath; unsigned char *decfiledigest;
			mk_digest(decfilepath,decfiledigest);
			PKT_END terminate = dmk_pkt_end(recvBuf);
			if(strcmp((char *)decfiledigest,terminate.Digest)){
				printf("�����ļ���ժҪ�ʹ�������Ĳ�ͬ\n");
			}
			else{
				printf("���ܵ���ȷ���ļ�\n");
			}
			break;

			recvfrom(sockCli, recvBuf, 6, 0, (SOCKADDR*)&addrSrv, &len);

			FILE * recfile = fopen("1.jpg","wb");
			//����DATA
			while(recvfrom(sockCli, recvBuf, 1006, 0, (SOCKADDR*)&addrSrv, &len) != SOCKET_ERROR){
	
			}
		case DATA:




			//����ʱ����ժҪ
			char* path; unsigned char *digest;
			mk_digest(path,digest);
			PKT_END pkt_end;
			sendBuf = mk_pkt_end((char *)digest,pkt_end);
			sendto(sockCli,sendBuf,strlen(sendBuf)+1,0,(SOCKADDR*)&addrSrv,len); 
			//���͸�������
			recvfrom(sockCli,recvBuf,strlen(recvBuf)+1,0,(SOCKADDR*)&addrSrv,&len); 
			//���շ�������Ӧ��
			if(recvBuf[0] != 0) {
				printf("response from sever:%s, IP is %s",recvBuf,inet_ntoa(addrSrv.sin_addr)); 
			} 

		}
	}
	closesocket(sockCli);
	WSACleanup( ); 
	return 0;
} 