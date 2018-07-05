#include"sup_packet.h"
#include"sup_session.h"
#include"pat_gzip.h"
#include<stdio.h>
#include<malloc.h>
#include<string.h>
int main(int argc,char *argv[])
{
	if(argc!=3)
	{
		printf("syntax error!\n");
		return;
	}
	char *filename=argv[1];
	int n=atoi(argv[2]);
	packet_info *info;
	LNode *List;
	if(InitList(&List)==EOF)
		return EOF;
	get_packet(n,"tcp",&List,filename);
	printf("length:%d\n",ListLength(List));
	LNode *p=List;
	int count=0;
	while(p->next!=NULL)
	{	
		p=p->next;
		count++;
		printf("NO.%d length:%d\n",count,p->data.len);
		pat_print_socket(p->data.socket);
		printf("TCP Stream:\n");
		pat_print_gzc(p->data.payload,p->data.len);
		tcp_stream_parse(p->data.payload,p->data.len);
	}	
	/*pat_print_socket(info->socket);
	printf("TCP Stream:\n");
	pat_print_gzc(info->payload,info->len);
	tcp_stream_parse(info->payload,info->len);*/
	return 0;
}
