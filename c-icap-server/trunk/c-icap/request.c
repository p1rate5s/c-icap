/*
 *  Copyright (C) 2004 Christos Tsantilas
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


#include "c-icap.h"
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <assert.h>
#ifdef _NOTUSED
#include <sys/ioctl.h>
#endif

#include "debug.h"
#include "request.h"
#include "service.h"
#include "access.h"
#include "util.h"
#include "cfg_param.h"

#define STARTBUF 1024


extern int TIMEOUT;

#define icap_write_nonblock ci_write_nonblock
#define icap_write(fd,buf,count) ci_write(fd,buf,count,TIMEOUT)
#define icap_read(fd,buf,count) ci_read(fd,buf,count,TIMEOUT)
#define wait_for_outgoing_data(fd) ci_wait_for_data(fd,TIMEOUT,wait_for_write)


/**/

void send_headers_block(request_t *req,ci_header_list_t *responce_head);


#define FORBITTEN_STR "ICAP/1.0 403 Forbidden\r\n\r\n"

request_t *newrequest(ci_connection_t *connection){
     request_t *req;
     int access;
     ci_connection_t *conn;

     if((access=access_check_client(connection))==CI_ACCESS_DENY){ /*Check for client access */
	  icap_write(connection->fd,FORBITTEN_STR,strlen(FORBITTEN_STR));
	  return NULL; /*Or something that means authentication error*/
     }
     
     conn=(ci_connection_t *)malloc(sizeof(ci_connection_t));
     memcpy(conn, connection,sizeof(ci_connection_t));
     req=ci_request_alloc(conn);

     req->access_type=access;
     return  req;
}


int recycle_request(request_t *req,ci_connection_t *connection){
     int access;

     if((access=access_check_client(connection))==CI_ACCESS_DENY){ /*Check for client access */
	  icap_write(connection->fd,FORBITTEN_STR,strlen(FORBITTEN_STR));
	  return 0; /*Or something that means authentication error*/
     }
     req->access_type=access;
     ci_request_reset(req);
     memcpy(req->connection,connection,sizeof(ci_connection_t));
     return 1;
}



int read_encaps_header(request_t *req,ci_header_list_t *h,int size){
     int bytes=0,remains,readed=0;
     char *buf_end=NULL;

     if(!set_size_header(h,size))
	  return EC_500;
     buf_end=h->buf;
     
     if(req->pstrblock_read_len>0){
	  readed=(size>req->pstrblock_read_len?req->pstrblock_read_len:size);
	  memcpy(h->buf,req->pstrblock_read,readed);
	  buf_end=h->buf+readed;
	  if(size<=req->pstrblock_read_len){/*We have readed all this header.......*/
	       req->pstrblock_read=(req->pstrblock_read)+readed;
	       req->pstrblock_read_len=(req->pstrblock_read_len)-readed;
	  }
	  else{
	       req->pstrblock_read=NULL;
	       req->pstrblock_read_len=0;
	  }
     }

     remains=size-readed;
     while(remains>0){
	  if((bytes=icap_read(req->connection->fd,buf_end,remains))<0)
	       return bytes;
	  remains-=bytes;
	  buf_end+=bytes;
     }

     h->bufused=buf_end - h->buf; // -1 ;
     if(strncmp(buf_end-4,"\r\n\r\n",4)==0){
	  h->bufused-=2; /*eat the last 2 bytes of "\r\n\r\n"*/
     }
     return EC_100;
}


int parse_request(request_t *req,char *buf){
     char *start,*end;
     int servnamelen,len;

     if( (start=strstr(buf,"icap://")) != NULL ){
	  start=start+7;
	  if( (end=strchr(start,'/')) != NULL || (end=strchr(start,' ')) != NULL ){ /*server*/
	       len=end-start;
	       servnamelen=(CI_MAXHOSTNAMELEN>len?len:CI_MAXHOSTNAMELEN);
	       memcpy(req->req_server,start,servnamelen);
	       req->req_server[servnamelen]='\0';

	       if(*end=='/'){ /*service*/
		    start=++end;
		    while(*end!=' ' &&  *end!= '?') end++;
		    len=end-start;
		    if(len>0){
			 req->service=malloc((len+1)*sizeof(char));
			 strncpy(req->service,start,len);
			 req->service[len]='\0';
			 if(*end=='?'){/*args*/
			      start=++end;
			      if((end=strchr(start,' '))!=NULL){
				   len=end-start;
				   req->args=malloc((len+1)*sizeof(char));
				   strncpy(req->args,start,len);
				   req->args[len]='\0';
			      }
			 }/*args*/
			 if(!(req->current_service_mod=find_service(req->service)))
			      return EC_404; /* Service not found ..... */
			 if( !ci_method_support(req->current_service_mod->mod_type,req->type) || req->type != ICAP_OPTIONS )
			      return EC_405; /* Method not allowed for service. */
		    }
		    else{
			 return EC_400;
		    }
	       } //service

	  }//server
     }  
     return EC_100;
}


int process_encapsulated(request_t *req,char *buf){
     char *start;
     char *pos;
     char *end;
     int type=0,num=0,val=0;
     int hasbody=1;/*Assume that we have a resbody or reqbody or optbody*/
     start=buf+14;
     pos=start;
     while(*pos!='\0'){
	  while(!isalpha(*pos) && *pos!='\0') pos++;
	  type=get_encaps_type(pos,&val,&end);
	  if(num>5) /*In practice there is an error here .... */
	       break;
	  if(type==ICAP_NULL_BODY)
	       hasbody=0; /*We have not a body*/
	  req->entities[num++]=ci_request_alloc_entity(req,type,val);
	  pos=end;/* points after the value of entity....*/
     }
     req->hasbody=hasbody;
     return 0;
}


int parse_header(request_t *req){
     int i,request_status=0,result;
     ci_header_list_t *h;

     h=req->head;
     if((request_status=ci_read_icap_header(req,h,TIMEOUT))<0)
	  return request_status;

     if( (result=get_method(h->buf))>=0){
	  req->type=result;
	  request_status=parse_request(req,h->buf);
     }
     else
	  return EC_400;

     if((request_status=ci_headers_unpack(h))!=EC_100)
	  return request_status;
     
     for(i=1;i<h->used;i++){
	  if(strncmp("Preview:",h->headers[i],8)==0){
	       result=strtol(h->headers[i]+9,NULL,10);
	       if(errno!= EINVAL && errno!= ERANGE){
		    req->preview=result;
		    ci_buf_reset_size(&(req->preview_data),result+100);
	       }
	  }
	  else if(strncmp("Encapsulated: ",h->headers[i],14)==0)
	       request_status=process_encapsulated(req,h->headers[i]);
	  else if(strncmp("Connection: ",h->headers[i],12)==0){
/*	       if(strncasecmp(h->headers[i]+12,"keep-alive",10)==0)*/
	       if(strncasecmp(h->headers[i]+12,"close",5)==0)
		    req->keepalive=0;
	       else
		    req->keepalive=1;
	  }
	  else if(strncmp("Allow: 204",h->headers[i],10)==0){
	       req->allow204=1;
	  }
     }

     return request_status;
}


int parse_encaps_headers(request_t *req){  
     int size,i,request_status=0;
     ci_encaps_entity_t *e=NULL;
     for(i=0;(e=req->entities[i])!=NULL;i++){
	  if(e->type>ICAP_RES_HDR) //res_body,req_body or opt_body so the end of the headers.....
	       return EC_100;

	  if(req->entities[i+1]==NULL)
	       return EC_400;

	  size=req->entities[i+1]->start-e->start;

	  if((request_status=read_encaps_header(req,(ci_header_list_t *)e->entity,size))!=EC_100)
	       return request_status;

	  if((request_status=ci_headers_unpack((ci_header_list_t *)e->entity))!=EC_100)
	       return request_status;
     }
     return EC_100;
}

int write_preview_data( void *notused,char *data,int len,int iseof,struct request *req){
    return ci_buf_write(&(req->preview_data),data,len);
}


int get_next_chunk_def(request_t *req){
     char *end/*,eofchunk[15]*/;
     int i,remains=0,len;
     int ret_status=CI_OK;

     while(1){
	  if(req->pstrblock_read_len<=0){
	       if((req->pstrblock_read_len=icap_read(req->connection->fd,req->rbuf,BUFSIZE))<0){
		    ci_debug_printf(5,"Error reading from client: count=%d, case 1\n",req->pstrblock_read_len);
		    return CI_ERROR; 
	       }
	       req->pstrblock_read=req->rbuf;
	       continue;
	  }

	  /*At this point the start must point to the start of a chunk eg to a "123\r\n"*/
	  errno=0;
	  req->current_chunk_len=strtol(req->pstrblock_read,&end,16); /*Must verified!!!!!!*/
/*	  ci_debug_printf(9,"New chunk size :%d,end:%s, nextlen:%d\n",req->current_chunk_len,end,req->pstrblock_read_len);*/
	  if(req->current_chunk_len==0 && req->pstrblock_read==end ){ /*Oh .... an error ...*/
	       ci_debug_printf(5,"Parse error:count=%d,start=%s\n",req->pstrblock_read_len,req->pstrblock_read);
	       return CI_ERROR; 
	  }
	  if(end-req->pstrblock_read+2>=req->pstrblock_read_len){ /*If we have not enough data for chunk length line eg 123\r\n*/
	       len=req->pstrblock_read_len; 
	       for(i=0;i<len;i++) *((req->rbuf)+i)=*(req->pstrblock_read+i); /*... put the current data to the begining of buf ....*/
	       if((req->pstrblock_read_len=icap_read(req->connection->fd,(req->rbuf)+len,BUFSIZE-len))<0){ /*... read some data...*/
		    ci_debug_printf(5,"Error reading data (count=%d) , case 2\n",req->pstrblock_read_len);
		    return CI_ERROR; 
	       }
	       req->pstrblock_read_len+=len;/* ... (size of data is readed plus old )...*/
	       req->pstrblock_read=req->rbuf; /* ... and try again.*/
	       continue;  
	  }
	  /*But the "\r\n at the end of line must verified and an error must returned...... TODO"*/
	  break;
     }

     if(req->current_chunk_len==0){ /*we have reach the end and we have at least 3 bytes readed .....*/
	  if(strncmp(req->pstrblock_read,"0\r\n",3)!=0 && strncmp(req->pstrblock_read,"0; ",3)!=0 ){
	       end[2]='\0';
	       ci_debug_printf(10,"Ending with end chunk(count :%d):%s %s\n",
			    req->pstrblock_read_len,req->pstrblock_read,end);  
	       return CI_ERROR;
	  } 
	  if(req->pstrblock_read_len>11)/* !!!!!!!parse error!!!!!!!!! */
	       return CI_ERROR;
	  
	  remains=(*end==';'?11-req->pstrblock_read_len:5-req->pstrblock_read_len);
	  /*The end sequence must be "0\r\n\r\n" or "0; ieof" the second  handled later ...*/
	  if(remains){ /*Can happen count <5 and must read some more bytes for keeping alive.....*/
	       if(req->pstrblock_read!=req->rbuf){   /*Copy bytes at the beggining of rbuf .......*/
		    for(i=0;i<req->pstrblock_read_len;i++) *((req->rbuf)+i)=*(req->pstrblock_read+i);
		    req->pstrblock_read=req->rbuf;
	       }
	       for(i=0;i<remains;i++)
		    icap_read(req->connection->fd,&(req->pstrblock_read[req->pstrblock_read_len+i]),1);
	       
	  }
	  req->pstrblock_read_len=req->pstrblock_read_len+remains;
	  req->chunk_bytes_read=0;
     }
     else{
	  req->pstrblock_read_len=req->pstrblock_read_len-(end+2-req->pstrblock_read);
	  req->pstrblock_read=end+2;  /*Skip the F\r\n where F is the hex number*/
	  if(req->current_chunk_len>req->pstrblock_read_len)
	       req->chunk_bytes_read=req->pstrblock_read_len;
	  else
	       req->chunk_bytes_read=req->current_chunk_len;
     }
     req->write_to_module_pending=req->chunk_bytes_read;
     return ret_status;
} 

int get_chunk_data(request_t *req){
     int len,ret_status=CI_OK,remains=0;

     if(req->current_chunk_len==0) /*Nothing to do so leave the function*/
	 return CI_OK;

     remains=req->current_chunk_len-req->chunk_bytes_read;
     if(remains){
	  req->pstrblock_read=req->rbuf;
	  if((req->pstrblock_read_len=icap_read(req->connection->fd,req->rbuf,BUFSIZE))<0){ 
	       ci_debug_printf(5,"Error reading data (count=%d),case 2\n",req->pstrblock_read_len);
	       return CI_ERROR;
	  }
	  len=(remains<req->pstrblock_read_len?remains:req->pstrblock_read_len);
	  req->chunk_bytes_read+=len;
	  ci_debug_printf(10,"Pendings bytes to be written to module :%d \n",len);
	  req->write_to_module_pending=len;
	  return CI_OK;
     }


     /*req->pstrblock_read_len>=len always (I think)...........*/
     if(req->pstrblock_read_len>=2){ /*In this case include the \r\n sequence*/
	  req->pstrblock_read=req->pstrblock_read+2;
	  req->pstrblock_read_len=req->pstrblock_read_len-2;
     }
     else{/* req->current_chunk_len<= req->pstrblock_read_len < req->current_chunk_len+2. 
	     All the \r\n sequence or a part ("\r") 
	     included in the next read*/
	  len=2-req->pstrblock_read_len; /*len is now the length of the remains bytes of \r\n sequence (1 or 2)*/
	  if((req->pstrblock_read_len=icap_read(req->connection->fd,req->rbuf,BUFSIZE))<0){ 
	       ci_debug_printf(5,"Error reading data (count=%d),case 3\n",req->pstrblock_read_len);
	       return CI_ERROR;
	  } /*if len==2 and count==1 we have a problem here .........*/
	  req->pstrblock_read=(req->rbuf)+len;
	  req->pstrblock_read_len=req->pstrblock_read_len-len;
	  /*continue;*/
     }
     return ret_status;
}


/*
  Reads from network must be moved from get_chunk_def and get_chunk_data to the two 
  following functions.
  The read from client must done at the beggining of these functions and if more 
  data needed the function must return with a status code 
  (something like NEEDS_MORE_DATA).
  It can be done for at least get_chunk_data becouse  all the reads are at the 
  begining of req->rbuf 
  for get_next_chunk_def the req->pstrblock_read_len can be used .....
*/


int read_preview_data(request_t *req){
    int ret,ret_status=CI_OK;
     do{
	 /*if we have read all chunks data get next chunk definition */
	 if(req->current_chunk_len<=req->chunk_bytes_read)
	     if((ret_status=get_next_chunk_def(req))!=CI_OK)
		 return CI_ERROR;
	 
	 if((ret_status=get_chunk_data(req))!=CI_OK)
	     return CI_ERROR;

	 if((ret=ci_buf_write(&(req->preview_data),req->pstrblock_read,req->write_to_module_pending))<0)
	     return CI_ERROR;
	 
	 req->pstrblock_read+=req->write_to_module_pending;
	 req->pstrblock_read_len-=req->write_to_module_pending;
	 req->write_to_module_pending=0;

     }while(req->current_chunk_len!=0);



     if(req->current_chunk_len==0){/*eochunk is filled ....*/
	   if(strncmp(req->pstrblock_read,"0\r\n\r\n",5)==0){ 
		    ret_status=CI_OK;
	       }
	       else if(strncmp(req->pstrblock_read,"0; ieof\r\n\r\n",11)==0){
		    req->eof_received=1;
		    ret_status=CI_EOF;
	       }
     }

     req->pstrblock_read=NULL; 
     req->pstrblock_read_len=0;
     if(req->eof_received)
	 return CI_EOF;
     return CI_OK;
}


int read_chunk_data(request_t *req){
     int wbytes,ret_status=CI_OK;
     int (*writedata)(void *, char *,int,int,struct request*);
     writedata=req->current_service_mod->mod_writedata;

     if(!req->write_to_module_pending){
	 /*if we have read all chunk data get next chunk definition*/
	 if(req->current_chunk_len<=req->chunk_bytes_read)
	     if((ret_status=get_next_chunk_def(req))!=CI_OK)
		 return CI_ERROR;
     }
     else{
	 wbytes=(*writedata)(req->service_data,req->pstrblock_read,req->write_to_module_pending,0,req);
	 req->pstrblock_read+=wbytes;
	 req->pstrblock_read_len-=wbytes;
	 req->write_to_module_pending-=wbytes;
     }

     if(req->write_to_module_pending ==0 ) /*In practice we are blocking until service read the data*/
	 if((ret_status=get_chunk_data(req))!=CI_OK)
	     return CI_ERROR;

     if(req->current_chunk_len==0){
	  ret_status=CI_EOF;
	  req->pstrblock_read=NULL;
	  req->pstrblock_read_len=0;
	  req->eof_received=1;
	  writedata=req->current_service_mod->mod_writedata;
	  (*writedata)(req->service_data,NULL,0,1,req);/*simply mark the eof*/
     }

     return ret_status;
}


int get_preview_or_chunk_data(request_t *req, int preview_operation){
     int wbytes,ret_status=CI_OK;
     int (*writedata)(void *, char *,int,int,struct request*);

     do{
	  if(req->pstrblock_read_len<0){
	       ci_debug_printf(10,"\n!!!!!!!!!!!!!!!!!!!!\n WHY negative  pstrblocklen??????????\n\n");
	  }

	  if(preview_operation)
	       writedata=write_preview_data; /*write to preview buffer ...... */
	  else
	       writedata=req->current_service_mod->mod_writedata;


	  if(!req->write_to_module_pending){
	       if((ret_status=get_next_chunk_def(req))!=CI_OK)
		    return CI_ERROR;
	  }
	  else{
	       wbytes=(*writedata)(req->service_data,req->pstrblock_read,req->write_to_module_pending,0,req);
	       req->pstrblock_read+=wbytes;
	       req->pstrblock_read_len-=wbytes;
	       req->write_to_module_pending-=wbytes;
	  }
	  
	  if(req->current_chunk_len==0)
	      break;

	  if(req->write_to_module_pending ==0 ) /*In practice we are blocking until service read the data*/
	       if((ret_status=get_chunk_data(req))!=CI_OK)
		    return CI_ERROR;
     }while(preview_operation && req->current_chunk_len!=0);

     if(preview_operation){
	  if(req->current_chunk_len==0){/*eochunk is filled ....*/
	       if(strncmp(req->pstrblock_read,"0\r\n\r\n",5)==0){ 
		    ret_status=CI_OK;
	       }
	       else if(strncmp(req->pstrblock_read,"0; ieof\r\n\r\n",11)==0){
		    req->eof_received=1;
		    ret_status=CI_EOF;
	       }
	  }

	  req->pstrblock_read=NULL; 
	  req->pstrblock_read_len=0;
	  if(req->eof_received)
	       return CI_EOF;
	  return CI_OK;
     } 

     if(req->current_chunk_len==0){
	  ret_status=CI_EOF;
	  req->pstrblock_read=NULL;
	  req->pstrblock_read_len=0;
	  req->eof_received=1;
	  writedata=req->current_service_mod->mod_writedata;
	  (*writedata)(req->service_data,NULL,0,1,req);
     }

     return ret_status;
}




void ec_responce(request_t *req,int ec){
     char buf[256];
     snprintf(buf,256,"ICAP/1.0 %d %s\r\n\r\n",
	      ci_error_code(ec),
	      ci_error_code_string(ec));
     buf[255]='\0';
     icap_write(req->connection->fd,buf,strlen(buf));
}





int mk_responce_header(request_t *req){
     ci_header_list_t *head;
     ci_encaps_entity_t **e_list;
//     time_t t;

     //  struct mem_body *responce_body=NULL;

     head=req->head;
     reset_header(req->head);
     add_header(head,"ICAP/1.0 200 OK");

//     snprintf(buf,255,"Server: C-Icap server 0.01/%s",((str=req->current_service_mod->service)?str:""));
//     buf[255]='\0';
//     add_header(responce_head,buf);
     if(req->keepalive)
	  add_header(head,"Connection: keep-alive");
     else
	  add_header(head,"Connection: close");
     add_header(head,"ISTag: \"5BDEEEA9-12E4-2\"" );

     /* DATE e****************************/
//     time(&t);
//     sprintf(buf,"Date: %s",asctime(localtime(&t)));
//     buf[strlen(buf)-1]='\0'; /*Eat the \n at the end of the asctime returned string*/
//     add_header(responce_head,buf);
//     add_header(responce_head,"Connection: close");
  
     e_list=req->entities;
     if(req->type==ICAP_RESPMOD){
	  if(e_list[0]->type==ICAP_REQ_HDR){
	       ci_request_release_entity(req,0);
	       e_list[0]=e_list[1];
	       e_list[1]=e_list[2];
	       e_list[2]=NULL;
	  }
     }
     ci_request_pack(req);

     return 1;
}


/****************************************************************/
/* New  functions to send responce */

const char *eol_str="\r\n";
const char *eof_str="0\r\n\r\n";


int send_current_block_data(request_t *req){
     int bytes;
     if(req->remain_send_block_bytes==0)
	  return 0;
     if((bytes=icap_write_nonblock(req->connection->fd,req->pstrblock_responce,req->remain_send_block_bytes))<0){
	  ci_debug_printf(5,"Error writing to server (errno:%d)",errno);
	  return CI_ERROR;
     }
     req->pstrblock_responce+=bytes;
     req->remain_send_block_bytes-=bytes;
     return req->remain_send_block_bytes;
}

/* This version of body send functions, copys the chunk to a buffer
and then tries to send the chunk
the declaration 
 char writebuf[MAX_CHUNK_SIZE+30]; 
must added struct request_t  and the method
int get_available_data_size(request_t *req,void *b)
must added to struct module;

But, declarations in struct request_t
     char chunk_defs_buf[10];
     char *pstr_chunk_defs;
     char remain_chunk_defs_bytes;  
can removed and the same for the method 
     int  get_posdata(struct body *,char**,int) 
in the body 

*/

int start_send_body_chunk(request_t *req){
     int chunksize,def_bytes;
     char *wbuf=NULL;
     char tmpbuf[EXTRA_CHUNK_SIZE];
     int (*readdata)(void *data,char *,int,struct request *);

     if(!req->responce_hasbody)
	  return CI_EOF;

     readdata=req->current_service_mod->mod_readdata;

     wbuf=req->wbuf+EXTRA_CHUNK_SIZE;/*Let size of EXTRA_CHUNK_SIZE space in the beggining of chunk*/
     if((chunksize=(*readdata)(req->service_data,wbuf,MAX_CHUNK_SIZE,req)) <=0){
/*	  ci_debug_printf(1,"No data to send or eof reached (%d,).......\n",chunksize);*/
	  req->remain_send_block_bytes=0;
	  return chunksize; /*Must be 0 or CI_EOF */
     }

     wbuf+=chunksize; /*Put the "\r\n" sequence at the end of chunk*/
     *(wbuf++)='\r';
     *wbuf='\n';

     def_bytes=snprintf(tmpbuf,EXTRA_CHUNK_SIZE,"%x\r\n",chunksize);
     wbuf=req->wbuf+EXTRA_CHUNK_SIZE-def_bytes;  /*Copy the chunk define in the beggining of chunk .....*/
     memcpy(wbuf,tmpbuf,def_bytes);
     
     req->pstrblock_responce=wbuf;
     req->remain_send_block_bytes=def_bytes+chunksize+2;     

     return req->remain_send_block_bytes;
}


int send_body_data(request_t *req){
     int ret=0;
     if(!req->responce_hasbody)
	  return CI_EOF;

     if((ret=send_current_block_data(req))!=0){
	  return ret;
     }
     ret=start_send_body_chunk(req);
     return ret;
}


int resp_check_body(request_t *req){
     int i;
     ci_encaps_entity_t **e=req->entities;
     for(i=0;e[i]!=NULL;i++)
          if(e[i]->type==ICAP_NULL_BODY)
               return 0;
     return 1;
}


int start_send_data(request_t *req){
    if(!mk_responce_header(req))
	  return CI_ERROR;
    
    req->responce_hasbody=resp_check_body(req);

    req->pstrblock_responce=req->head->buf;
    req->remain_send_block_bytes=req->head->bufused;


    req->responce_status=SEND_RESPHEAD;
    return CI_OK;
}


int send_some_data(request_t *req){
     int i,ret,status;
     ci_encaps_entity_t *e;

     if((status=req->responce_status)<SEND_HEAD3){
	  ret=send_current_block_data(req);
	  if(ret!=0)
	       return ret;
	  status++;
     }


     if(status>SEND_RESPHEAD && status < SEND_BODY){ /*status is SEND_HEAD1 SEND_HEAD2 or SEND_HEAD3    */
	  i=status-SEND_HEAD1;                      /*We have to send next headers block ....*/
	  if((e=req->entities[i])!=NULL && (e->type==ICAP_REQ_HDR || e->type==ICAP_RES_HDR)){

	       req->pstrblock_responce=((ci_header_list_t *)e->entity)->buf;
	       req->remain_send_block_bytes=((ci_header_list_t *)e->entity)->bufused;

	       req->responce_status=status;
	       // return ret=send_current_block_data(req); /**/
	  }
	  else if(req->responce_hasbody){ /*end of headers, going to send body now.A body always follows the res_hdr or req_hdr..... */
	       req->responce_status=SEND_BODY;
	       start_send_body_chunk(req);
	  }
	  else{
	       req->responce_status=SEND_EOF;
//	       req->pstrblock_responce=(char *)eol_str;
//	       req->remain_send_block_bytes=2;
	       req->pstrblock_responce=(char *)NULL;
	       req->remain_send_block_bytes=0;
	       return CI_EOF;
	  }
     }
     

     if(req->responce_status==SEND_BODY){
	  if((ret=send_body_data(req))==CI_EOF){
	       status=req->responce_status=SEND_EOF;
	       req->pstrblock_responce=(char *)eof_str;
	       req->remain_send_block_bytes=5;	       
//	       return req->remains_send_block_bytes; /*Don't do it try to send eof_str now.......*/
	  }
	  else
	       return ret;
     }

     if(req->responce_status==SEND_EOF){
	  if((ret=send_current_block_data(req))!=0)
	       return ret;
	  if(ret==0){
	       return CI_EOF;
	  }
     }
//     ci_debug_printf(1,"Can not be reached ....I thing .... (status=%d, req->responce_status=%d)\n",
//     status,req->responce_status);
     return req->remain_send_block_bytes; /*Can not be reached (I thing)......*/
}


int rest_responce(request_t *req){
     int ret=0;

     if(req->responce_status==SEND_EOF && req->remain_send_block_bytes==0){
	  ci_debug_printf(5,"OK sending all data\n");
	  return CI_OK;
     }

     if(req->responce_status==SEND_NOTHING){ //If nothing has send start sending....
	  if((ret=start_send_data(req))==CI_ERROR){
	       ci_debug_printf(3,"Error sending data in rest_responce\n");
	       return CI_ERROR;
	  }
     }
     
     do{
	  if((ret=wait_for_outgoing_data(req->connection->fd))<=0){
	       ci_debug_printf(1,"Timeout sending data. Ending .......\n");
	       return CI_ERROR; /*Or something that mean timeout better ..........*/
	  }
     }while((ret=send_some_data(req))>=0);


     if(ret==CI_ERROR)
	  return ret;

     return CI_OK;
}


int get_send_body(request_t *req){
     int ret,get_data_ret;

     req->responce_status=SEND_NOTHING;
     while((get_data_ret=get_preview_or_chunk_data(req,0))==CI_OK){
	  ci_debug_printf(10,"OK getting data...\n");
	  if(!(req->data_locked)){
	       if(req->responce_status==SEND_NOTHING){
		    if((ret=start_send_data(req))==CI_ERROR){
			 ci_debug_printf(1,"Error start sending data!!!!!\n");
			 return CI_ERROR;
		    }
	       }
	       if((ret=send_some_data(req))<0)
		    return CI_ERROR;
	  }
	  else{
	      /* ci_debug_printf(10,"Not ready to send data yet\n");*/
	  }
     }
     if(get_data_ret==CI_EOF){ //we have read all data.........
	  return CI_OK;
     }
     ci_debug_printf(5,"What the hell hapens??????? (ret:%d)",get_data_ret);
     return CI_ERROR;
}


void options_responce(request_t *req){
     char buf[256];
     char *str;
     ci_header_list_t *head;
     int i;
     head=req->head;

     reset_header(head);
     add_header(head,"ICAP/1.0 200 OK");
     strcpy(buf,"Methods: ");
     if(ci_method_support(req->current_service_mod->mod_type,ICAP_RESPMOD)){
	  strcat(buf,"RESPMOD");
	  if(ci_method_support(req->current_service_mod->mod_type,ICAP_REQMOD)){
	       strcat(buf,", REQMOD");
	  }
     }else{ /*At least one method must supported. A check for error must exists here..... */
	  strcat(buf,"REQMOD");
     }
     
     add_header(head,buf);
     // add_header(head,(req->current_service_mod->type==ICAP_RESPMOD?"Methods: RESPMOD":"Methods: REQMOD"));
     snprintf(buf,255,"Service: C-Icap server 0.01/%s",((str=req->current_service_mod->mod_short_descr)?str:""));
     buf[255]='\0';
     add_header(head,buf);
     add_header(head,"ISTag: \"5BDEEEA9-12E4-2\"" );
     add_header(head,"Max-Connections: 20");
     add_header(head,"Options-TTL: 3600");
     /* DATE e****************************/
     /* time(&t);*/
     // sprintf(buf,"Date: %s",asctime(localtime(&t)));
     strcpy(buf,"Date: ");
/*     ctime_r(&t,buf+strlen(buf));*/
     ci_strtime(buf+strlen(buf));
     buf[strlen(buf)-1]='\0'; /*Eat the \n at the end of the ctime returned string*/
     add_header(head,buf);
     /********/

     if(req->current_service_mod->mod_options_header){
	  for(i=0;(str=req->current_service_mod->mod_options_header[i])!=NULL&& i<30;i++)/*the i<30 for error handling...*/
	       add_header(head,str);
     }
     ci_request_pack(req);

     req->pstrblock_responce=head->buf;
     req->remain_send_block_bytes=head->bufused;
     
     send_current_block_data(req);

//     if(responce_body)
//	  send_body_responce(req,responce_body);

}



int process_request(request_t *req){
//     void *b;
     int res,preview_status=0,auth_status=CI_ACCESS_ALLOW;


     res=parse_header(req);

     if(res!=EC_100){
	  if(res>=0)
	       ec_responce(req,res); /*Bad request or Service not found or Server error or what else......*/
	  req->keepalive=0; // Error occured, close the connection ......
	  ci_debug_printf(5,"Error parsing headers :(%d)\n",req->head->bufused);
	  return CI_ERROR;
     }

     auth_status=req->access_type;
     if(req->access_type==CI_ACCESS_PARTIAL && (auth_status=access_check_request(req))==CI_ACCESS_DENY){
	  ec_responce(req,EC_401);/*Responce with bad request*/
	  return CI_ERROR; /*Or something that means authentication error*/
     }

     if(res==EC_100)
	  res=parse_encaps_headers(req);

     if(auth_status==CI_ACCESS_HTTP_AUTH && access_authenticate_request(req)==CI_ACCESS_DENY ){
	  ec_responce(req,EC_401);/*Responce with bad request*/
	  return CI_ERROR; /*Or something that means authentication error*/
     }
  

//     debug_print_request(req);


     if(!req->current_service_mod){
	  ci_debug_printf(1,"Service not found\n");
	  ec_responce(req,EC_404);
	  return CI_ERROR;
     }

     if(req->current_service_mod->mod_init_request_data)
	  req->service_data=req->current_service_mod->mod_init_request_data(req->current_service_mod,req);
     else
	  req->service_data=NULL;

     ci_debug_printf(8,"Requested service: %s\n",req->current_service_mod->mod_name);

     switch(req->type){
     case ICAP_OPTIONS:
	  options_responce(req);
	  break;
     case ICAP_REQMOD:
     case ICAP_RESPMOD:
	  preview_status=0;
/*	  if(req->current_service_mod->mod_end_of_headers_handler){
	       req->current_service_mod->mod_end_of_headers_handler(req->service_data,req);
	       }*/
	  if(req->hasbody && req->preview>0 ){
	       if((preview_status=get_preview_or_chunk_data(req,1))==CI_ERROR){
		    ci_debug_printf(5,"An error occured while reading preview data (propably timeout)\n");
		    ec_responce(req,EC_408);
		    /*Responce with error.....*/
		    break;
	       }
	       else if(req->current_service_mod->mod_check_preview_handler){
		    res=req->current_service_mod->mod_check_preview_handler(req->service_data,
									    req->preview_data.buf,
									    req->preview_data.used,
									    req);
		    if(res==EC_204){
			 ec_responce(req,EC_204);
			 break; //Need no any modification.
		    }
		    if(res==CI_ERROR){
			 ci_debug_printf(10,"An error occured in preview handler!!");
			 ec_responce(req,EC_500);
			 break;
		    }
		    if(preview_status>0)
			 ec_responce(req,EC_100);
	       }
	  }
	  else if(req->current_service_mod->mod_check_preview_handler){
		    res=req->current_service_mod->mod_check_preview_handler(req->service_data,NULL,0,req);
		    if(req->allow204 && res==EC_204){
			 ec_responce(req,EC_204);
			 break; //Need no any modification.
		    }
	  }

	  if(req->hasbody && preview_status>=0){
	       ci_debug_printf(9,"Going to get_send_data.....\n");
	       res=get_send_body(req);
	       if(res!=CI_OK){
		    ci_debug_printf(5,"An error occured. Parse error or the client closed the connection (res:%d, preview status:%d)\n",res,preview_status);
		    break;
	       }
	  }
	  
	  if (req->current_service_mod->mod_end_of_data_handler){
	       req->current_service_mod->mod_end_of_data_handler(req->service_data,req);
/*	       while( req->current_service_mod->mod_end_of_data_handler(req,b)== CI_MOD_NOT_READY){
		    //can send some data here .........
		    }
*/
	  }
	  unlock_data(req);

	  if((res=rest_responce(req))!=CI_OK)
	       ci_debug_printf(5,"An error occured while sending rest responce. The client closed the connection (res:%d)\n",res);
	  
	  break;
     default:
	  res=CI_ERROR;
	  break;
     }

     if(req->current_service_mod->mod_release_request_data && req->service_data)
	  req->current_service_mod->mod_release_request_data(req->service_data);

//     debug_print_request(req);
     return res;
}

