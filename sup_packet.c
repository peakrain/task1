#include"sup_packet.h"
#include<linux/tcp.h>
#include<linux/ip.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<string.h>
#include<malloc.h>
#include<pcap.h>

int count=0;
void  socket_copy(Socket *socket1,Socket *socket2)
{
	strcpy(socket1->src_ip,socket2->src_ip);
	strcpy(socket1->dst_ip,socket2->dst_ip);
	socket1->src_port=socket2->src_port;
	socket1->dst_port=socket2->dst_port;
	socket1->prot=socket2->prot;
}
int is_same(Socket *socket1,Socket *socket2)
{
	int sip=strcmp(socket1->src_ip,socket2->src_ip);
	int dip=strcmp(socket1->dst_ip,socket2->dst_ip);
	int sport=socket1->src_port==socket2->src_port;
	int dport=socket1->dst_port==socket2->dst_port;
	int rsip=strcmp(socket1->src_ip,socket2->dst_ip);
	int rdip=strcmp(socket1->dst_ip,socket2->src_ip);
	int rsport=socket1->src_port==socket2->dst_port;
	int rdport=socket1->dst_port==socket2->src_port;
	int prot=socket1->prot==socket2->prot;
	int samedire=(sip==0&&dip==0&&sport==1&&dport==1);
	int redire=(rsip==0&&rdip==0&&rsport==1&&rdport==1);
	if((samedire==1||redire==1)&&prot==1)
		return 1;
	else
		return 0;
}
int analysis(LNode **list,struct pcap_pkthdr *pkt,const u_char *packet)
{
	LNode *p=*list;
	int offset=14;
	int len=pkt->len;
	if(len>offset)
	{
		struct in_addr addr;
		struct iphdr* ip_h;
		ip_h=(struct iphdr*)(packet+offset);
		offset+=ip_h->ihl<<2;
		if(ip_h->protocol==6)
		{
			struct tcphdr *tcp_h;
			tcp_h=(struct tcphdr*)(packet+offset);
			offset+=tcp_h->doff<<2;
			len=ntohs(ip_h->tot_len)+14-offset;
			Socket *socket=(Socket *)malloc(sizeof(Socket));
			addr.s_addr=ip_h->saddr;
			strcpy(socket->src_ip,inet_ntoa(addr));
			addr.s_addr=ip_h->daddr;
			strcpy(socket->dst_ip,inet_ntoa(addr));
			socket->prot=ip_h->protocol;
			socket->src_port=ntohs(tcp_h->source);
			socket->dst_port=ntohs(tcp_h->dest);
			
			if(len<=0)
				return 1;
			if(ListLength(p)!=0)
			{
				while(p->next!=NULL)
				{
					p=p->next;
					if(is_same(p->data.socket,socket))
					{
						int dev=(ntohl(tcp_h->seq)-p->data.syn_seq)+(ntohl(tcp_h->ack_seq)-p->data.syn_ack);
						memcpy(p->data.payload+dev,packet+offset,len);
						p->data.len+=len;
						return 0;
					}
				}
			}
			packet_info element;
			packet_info_init(&element);
			socket_copy(element.socket,socket);
			element.syn_seq=ntohl(tcp_h->seq);
			element.syn_ack=ntohl(tcp_h->ack_seq);
			memcpy(element.payload,packet+offset,len);
			element.len=len;
			if(ListInsert(&p,element)==0)
				printf("Insert length:%d\n",ListLength(p));
		}
		else
			return EOF;
		
	}
	else
	{
		printf("packet length error!\n");
		return EOF;
	}
	*list=p;
}
int get_packet(int num,char *filter,LNode **list,char *filename)
{
	char ebuf[PCAP_ERRBUF_SIZE];
	/*open a pcap file*/
	pcap_t *device=pcap_open_offline(filename,ebuf);
	if(!device)
	{
		printf("error:%s\n",ebuf);
		return;
	}
	/*init filter*/
	struct bpf_program fp;
	pcap_compile(device,&fp,filter,1,0);
	pcap_setfilter(device,&fp);
	
	/*catch pakcet*/
	struct pcap_pkthdr *pkt;
	const u_char *packet;
	int ret;
	if(num==-1)
	{
		while(1)
		{
			ret=pcap_next_ex(device,&pkt,&packet);
			if(ret==EOF||ret==0)
				return EOF;
			if(ret==-2)
				break;
			if(analysis(list,pkt,packet)==EOF)
				return EOF;
		}	
	}
	else
	{
		int count=0;
		while(count<num)
		{
			ret=pcap_next_ex(device,&pkt,&packet);
			if(ret==EOF||ret==0)
				return EOF;
			if(ret==-2)
				break;
			if(analysis(list,pkt,packet)==EOF)
				return EOF;
			count++;
		}	
	}
	pcap_close(device);	
}

packet_info_init(packet_info *info)
{
	info->socket=(Socket*)malloc(sizeof(Socket));
	info->len=0;
	info->capacity=655350;
	info->syn_seq=-1;
	info->syn_ack=-1;
	info->payload=(unsigned char*)malloc(sizeof(unsigned char)*info->capacity);
}

void packet_info_free(packet_info *info)
{
	if(!info)
		return;
	if(!info->socket)
		free(info->socket);
	if(!info->payload)
		free(info->payload);
	free(info);
}
int InitList(LNode* *L)
{
	LNode *l=(LNode *)malloc(sizeof(LNode));
	if(!l)
		return EOF;
	l->next=NULL;
	*L=l;
	return 0;
}
int ListInsert(LNode* *L,packet_info e)
{
	LNode *head,*p;
	head=*L;
	p=head;
	while(p->next!=NULL)
		p=p->next;
	LNode *s=(LNode *)malloc(sizeof(LNode));
	if(!s)
		return EOF;
	s->data=e;
	s->next=p->next;
	p->next=s;
	*L=head;
	return 0;
}
int ListLength(LNode *L)
{
	LNode *p=L;
	int length=0;
	while(p->next!=NULL)
	{
		length++;
		p=p->next;
	}
	return length;
}
