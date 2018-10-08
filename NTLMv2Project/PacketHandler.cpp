#include "stdafx.h"

using namespace std;
/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm ltime;
	char timestr[16];
	time_t local_tv_sec;

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	/* print timestamp and length of the packet */
	//printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

	Ethernet_header *ethernet_header = (Ethernet_header*)pkt_data;

	try 
	{
		if (ethernet_header->ptype == 8) // case  0x0800
		{
			PacketWork(param,header,pkt_data);
		}
	}
	catch(exception ex)
	{
		cout << ex.what() << endl;
	}
}

/*
switch (ntohs(ethernet_header->ptype))
		{
		case 0x0800: // тип Ip
			{
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
							throw("No smb continuation");
						}

						int usual_smb_h_len = 64;
						smb = (smbv2*)((u_char*)nbt + nbt_len);

						if (smb->headLen != usual_smb_h_len)
						{
							throw("Wrong smb header size");
						}
						// 1112364030 - smbv2 component
						

						if (smb->servComponent == smbv2Component)
						{
							
							if (smb->command == 1 && ih->spa == parametr.domainController)
							{
								fout.open(fileName);
								if (!fout)
									throw("Couldn`t open file");

								sr = (setupRequest*)((u_char*)smb + smb->headLen);

								int lllll = sr->fixedPartLen;
								int a;
							}

							//if(smb->command == 1 &&)
							//	smb = (smb_header*)((u_char*)nbt + 4); // 4 - длина полей netbios SS
							//PrintSMB(smb);
						}
						else throw("This is not smbv2 header");
					}
					break;

				}
			}
		}
*/