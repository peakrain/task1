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
	LNode List;
	if(InitList(&List,12)==EOF)
		return EOF;
	get_packet(n,"tcp",&List,filename);
	printf("length:%d\n",List.n);
	int i;
	packet_info info;
	packet_info *p=List.data;
	unsigned char head[5];
	int count=0;
	for(i=0;i<List.n;i++)
	{
		if(i<0||i>=List.n)
			break;
		info=*(p+i);
		if(info.len<=0)
			continue;
		sscanf(info.payload,"%s",head);
		if(strncmp(head,"GET",3)&&strncmp(head,"POST",4)!=0&&strncmp(head,"HTTP",4)!=0)
			continue;
		printf("No.%d\n",++count);
		pat_print_socket(List.data[i].socket);
		printf("TCP Stream:\n");
		pat_print_gzc(List.data[i].payload,List.data[i].len);
		tcp_stream_parse(List.data[i].payload,List.data[i].len);
	}
	if(count==0)
		printf("can't find http session data\n");
	/*pat_print_socket(info->socket);
	printf("TCP Stream:\n");
	pat_print_gzc(info->payload,info->len);
	tcp_stream_parse(info->payload,info->len);*/
	return 0;
}
