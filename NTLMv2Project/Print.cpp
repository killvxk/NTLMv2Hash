#include "stdafx.h"

void PrintARP(arp_header *arp)
{
	printf("Заголовок ARP\n");
	printf("Физический адрес получателя: %.2x-%.2x-%.2x-%.2x-%.2x-%.2x \n", arp->tha.bytes[0], arp->tha.bytes[1], arp->tha.bytes[2], arp->tha.bytes[3], arp->tha.bytes[4], arp->tha.bytes[5]);
	printf("Логический адрес получателя: %d.%d.%d.%d \n", arp->tpa.byte1, arp->tpa.byte2, arp->tpa.byte3, arp->tpa.byte4);
	printf("Физический адрес отправителя: %.2x-%.2x-%.2x-%.2x-%.2x-%.2x \n", arp->sha.bytes[0], arp->sha.bytes[1], arp->sha.bytes[2], arp->sha.bytes[3], arp->sha.bytes[4], arp->sha.bytes[5]);
	printf("Логический адресс отправителя: %d.%d.%d.%d \n", arp->spa.byte1, arp->spa.byte2, arp->spa.byte3, arp->spa.byte4);
	printf("Длина физического адреса: %x\n", arp->hlen);
	printf("Длина логического адреса: %x \n", arp->plen);
}

void PrintEthernet(Ethernet_header *eheader)
{
	printf("Заголовок Ethernet.\n");
	printf("MAC адрес получателя: %.2x-%.2x-%.2x-%.2x-%.2x-%.2x \n", eheader->destinationAdr.bytes[0], eheader->destinationAdr.bytes[1], eheader->destinationAdr.bytes[2], eheader->destinationAdr.bytes[3], eheader->destinationAdr.bytes[4], eheader->destinationAdr.bytes[5]);
	printf("MAC адрес отправителя: %.2x-%.2x-%.2x-%.2x-%.2x-%.2x \n", eheader->sourceAdr.bytes[0], eheader->sourceAdr.bytes[1], eheader->sourceAdr.bytes[2], eheader->sourceAdr.bytes[3], eheader->sourceAdr.bytes[4], eheader->sourceAdr.bytes[5]);

}

void PrintIP(ip_header *ih)
{
	printf("	Заголовок IP. \n");
	printf("	Длина: %d\n", ntohs((u_short)ih->tlen));
	printf("	Размер заголовка: %d\n", (ih->ver_ihl & 0xf) * 4);
	printf("	Адрес отправителя: %d.%d.%d.%d \n", ih->spa.byte1, ih->spa.byte2, ih->spa.byte3, ih->spa.byte4);
	printf("	Адрес назначения: %d.%d.%d.%d \n", ih->tpa.byte1, ih->tpa.byte2, ih->tpa.byte3, ih->tpa.byte4);

}
void PrintUDP(udp_header *udp)
{
	printf("		Заголовок UDP. \n");
	printf("		Длина данных: %d\n", ntohs((u_short)udp->len));
	printf("		Порт отправителя: %d\n", ntohs((u_short)udp->sport));
	printf("		Порт получателя: %d\n", ntohs((u_short)udp->dport));
}
void PrintTCP(tcp_header *tcp)
{
	printf("		Заголовок TCP. \n");
	printf("		Порт отправителя: %d\n", ntohs((u_short)tcp->sport));
	printf("		Порт получателя: %d\n", ntohs((u_short)tcp->dport));
	printf("		Длина пакета:  %d \n", (tcp->header_length * 4));
}

void PrintnetBios(netBios_header *nbt)
{
	printf("			Заголовок netBios. \n");
	printf("			Тип сообщения: %.2x \n", nbt->messageType);
	printf("			Длина данных: %d \n", nbt->length[2] + nbt->length[1] * 256 + nbt->length[0] * 131072);
}
void PrintSMB(smb_header *smb)
{
	printf("				Заголовок SMB. \n");
	printf("				Компонента сервера: %d \n", smb->serverComponent);
	printf("				Команда: %.2x \n", smb->command);
	printf("				Tree ID: %d\n", smb->treeID);
	printf("				ID процесса: %d\n", smb->processID);
	printf("				ID пользователя: %d\n", smb->userID);
	printf("				ID группы: %d\n", smb->multiplexID);
	printf("				WCT: %d\n", smb->wct);
}