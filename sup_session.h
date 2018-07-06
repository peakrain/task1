#ifndef _sup_session_h
#define _sup_session_h

#define field_size 128
typedef struct fields{
	char Connection[field_size];
	char Transfer_Encoding[field_size];
	char Content_Encoding[field_size];
	char Content_Language[field_size];
	char Content_Type[field_size];
	int Content_Length;
}head_fields;

int auto_split(unsigned char  *data,int *len,unsigned char **source,int *slen,int flag);
int join_chunk(unsigned char *out,int *u_len,unsigned char *source,int slen);
int get_line(char *buf,unsigned char **data);
#endif
