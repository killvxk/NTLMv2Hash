#pragma once

#include "targetver.h"

#include <iostream>
#include <stdio.h>
#include <tchar.h>
#include "pcap.h"
#include "Struct.hpp"
#include "Winsock2.h"
#include <cmath>
#include <string>
#include <fstream>
#include <exception>


void PrintARP(arp_header *arp);
void PrintEthernet(Ethernet_header *eheader);
void PrintIP(ip_header *ip);
void PrintUDP(udp_header *udp);
void PrintTCP(tcp_header *tcp);
void PrintnetBios(netBios *nbt);
void PrintSMB(smb_header *smb);

bool PacketContinuation(int ipLength, int tcpLength, int headerLength);
void FillStruct(parStruct &structure, u_char* par);
void FillPar(u_char* par);
int CountSmbLen(netBios_header nbt);
void PacketWork(u_char* param,const struct pcap_pkthdr *header, const u_char *pkt_data);