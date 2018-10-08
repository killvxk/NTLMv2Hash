#pragma once
#include "stdafx.h"

typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;

	bool operator==(const ip_address &adr) const
	{
		return this->byte1 == adr.byte1 && this->byte2 == adr.byte2 && this->byte3 == adr.byte3 && this->byte4 == adr.byte4;
	}
}ip_address;

typedef struct mac_address {
	u_char bytes[6];
}mac_address;

/* IPv4 header */
typedef struct ip_header {
	u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
	u_char  tos;            // Type of service 
	u_short tlen;           // Total length 
	u_short identification; // Identification
	u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
	u_char  ttl;            // Time to live
	u_char  proto;          // Protocol
	u_short crc;            // Header checksum
	ip_address spa;       // Source address u_char tpa[4]; u_char spa[4];
	ip_address tpa;             // Destination address
	u_int   op_pad;         // Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header {
	u_short sport;          // Source port
	u_short dport;          // Destination port
	u_short len;            // Datagram length
	u_short crc;            // Checksum
}udp_header;
typedef struct tcp_header {
	u_short sport;          // Source port
	u_short dport;          // Destination port
	u_int seq_numb; // Sequence Number
	u_int ack_numb; // Acknowledge Number
	u_char ns : 1;//Nonce Sum (необязательное поле) 
	u_char reservedPart1 : 3;
	u_char header_length : 4;
	//Флаги
	u_char fin : 1;								//указывает на завершение соединения
	u_char syn : 1;								//синхронизация номеров последовательности
	u_char rst : 1;								//оборвать соединения, сбросить буфер
	u_char psh : 1;								//инструктирует получателя протолкнуть данные, накопившиеся в приемном буфере, в приложение пользователя
	u_char ack : 1;								//номер подтверждения
	u_char UrgentFlag : 1;						//указатель важности

	u_short window;//число, определяющее в байтах размер данных, которые отправитель готов принять
	u_short checksum;//контрольная сумма
	u_short urgentPointer;

}tcp_header;

//arp header
typedef struct arp_header {

	u_short htype; // hardware type канальный протокол
	u_short ptype; // protocol type код сетевого протокола
	u_char hlen; // hardware length длина физ адреса Здесь была ошибка
	u_char plen; // protocol length длина лог адреса и Здесб
	u_short oper; // Operation код операции отправителя 1 - запрос 2 - отправитель
	mac_address sha; // физ адрес отправ 6
	ip_address spa; // лог адрес отправ 4 
	mac_address tha; // физ адрес получ 6 - длина ethernet адреса
	ip_address tpa; // лог адрес получ
}arp_header;

typedef struct Ethernet_header {

	mac_address destinationAdr; // MAC адрес получателя
	mac_address sourceAdr; // МАС адрес отправителя
	u_short ptype; // protocol type след уровня 0x0800 для ip
}Ethernet_header;

typedef struct netBios_header {
	u_char messageType;
	u_char length[3];
}netBios;

typedef struct smb_header {
	u_int serverComponent;
	u_char command;
	u_int statusCode; //RCLS
	u_char rebFlagsLock; // flags
	u_short flags2;
	u_short processIDHighBytes; //идентификатор клиентского процесса фактического соединения
	u_char signature[6];

	u_short treeID; //Идентификатор соед с сетевым ресурсом
	u_short processID; 	 //идентификатор клиентского процесса фактического соединения

	u_short userID; //идентификатор пользователя; используется сервером для проверки прав доступа пользователя
	u_short multiplexID; //идентификатор группы пользователя; используется сервером для проверки прав доступа группы пользователя
	u_char wct; //Кол-во параметров, след за заголовком


}smb_header;


typedef struct parStruct {
	ip_address domainController;
	u_short domainPort;
};

typedef struct smbv2 {
	
	u_int servComponent;
	u_short headLen;
	u_short creditCharge;

	// Последующие два элемента зачастую являются одним элементом, отображающим статус
	u_short channelSequence;
	u_short reserved;
	// Важный элемент - команда
	u_short command;
	//
	u_short creditReqOrGrant;
	// Флаги
    /*u_char responseOrRequest : 1;
	u_char sync : 1;
	u_char chained : 1;
	u_char signing : 1;
	u_char priority : 3;
    */	
	u_int flags;
	u_int chainOffset;
	u_int messageID[2];
	u_int ProcessID;
	u_int TreeID;
	u_int sessionID[2];
	u_int signature[4];


};

typedef struct setupRequest
{
	/*u_short fixedPartLen : 15;
	u_short dynamicPart : 1;*/
	
	u_short length;
	u_char flags;
	u_char securityMode; //Предпоследний Signing enable, последний Signing require
	u_int capabilities;
	u_int channel;
	//u_int prevSession[2];
};

typedef struct securityBlob
{
	u_short offset;
	u_short length;
};


typedef struct negTokenTargComponent
{
	u_char negTokenTargcomponent[8];
	
	bool operator==(const negTokenTargComponent &ntt) const
	{
		for (int i = 0; i < 8; ++i)
			if (this->negTokenTargcomponent[i] != ntt.negTokenTargcomponent[i])
				return false;
		return true;
	}
	
};
typedef struct negTokenTarg
{
	negTokenTargComponent ntt;
	u_char negResult;
	u_char unknownComponent1[4];
	u_char supportedMech[10];
	u_char unknownComponent2[6];
};
typedef struct ntlmChallenge
{
	/*ostream& operator<<(std::ostream &out)
	{
		for (int i = 0; i < 8; ++i)
			out << this->byte[i] << " ";

		return out;
	}*/
	u_char byte[8];
};
typedef struct NTLMSSPfromServer 
{
	u_int ntlmsspComponent[2];
	u_int messageType;
	u_int unknownComponent[2];
	u_int negotiateFlags;
	ntlmChallenge challenge;
	double reserved;
};


typedef struct lanManager 
{
	u_short len;
	u_short maxLen;
	u_int offset;
};
typedef struct ntlm
{
	u_short len;
	u_short maxLen;
	u_int offset;
};
typedef struct domainName
{
	u_short len;
	u_short maxLen;
	u_int offset;
};
typedef struct userName
{
	u_short len;
	u_short maxLen;
	u_int offset;
};
typedef struct hostName
{
	u_short len;
	u_short maxLen;
	u_int offset;
};
typedef struct sessionKey
{
	u_short len;
	u_short maxLen;
	u_int offset;
};
typedef struct version
{
	u_char majorVersion;
	u_char minorVersion;
	u_short buildNumber;
	u_char reserved[3];
	u_char ntlmCurrentRevision;
};

typedef struct NTLMv2
{
	u_char reserved[6];
	u_char ntProofStr[16];
	u_char responseVersion;
	u_char hiResponseVersion;
	u_char unknownComponent1[6];
	u_char time[8];
	ntlmChallenge challenge;
	u_char unknownComponent2[4];
};

typedef struct NTLMSSPfromClient
{
	u_int ntlmsspComponent[2];
	u_int messageType;
	lanManager lm;
	ntlm ntlm;
	domainName dN;
	userName uN;
	hostName hN;
	sessionKey sK;
	u_int negotiateFlags;
	version version;
	u_char mic[16];
/*
	u_char *domainName = new u_char[dN.len];
	u_char *userName = new u_char[uN.len];
	u_char *hostName = new u_char[hN.len];
*/
	/*u_char domainName[20];
	u_char userName[10];
	u_char hostName[20];
	u_char lmv2Challenge[8];
	u_char lmv2Response[10];
	NTLMv2 ntlmv2;*/
};

/*typedef struct AtribStruct
{
	u_char *domainName;
	u_char *userName;
	u_char *hostName;
	u_char lmv2Challenge[8];
	u_char *lmv2Response;
	u_char *ntlmv2;

	AtribStruct(int dNLen, int uNLen, int hNLen,int lmLen, int ntlmv2Len)
	{
		domainName = new u_char[dNLen];
		userName = new u_char[uNLen];
		hostName = new u_char[hNLen];
		lmv2Response = new u_char[lmLen -8];
		ntlmv2 = new u_char[ntlmv2Len];
	}

	~AtribStruct()
	{
		delete[] domainName;
		delete[] userName;
		delete[] hostName;
		delete[] lmv2Response;
		delete[] ntlmv2;
	}
};*/