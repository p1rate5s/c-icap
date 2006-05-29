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
#include "service.h"
#include "header.h"
#include "body.h"
#include "simple_api.h"
#include "debug.h"



int    url_check_init_service(service_module_t *serv,struct icap_server_conf *server_conf);
void * url_check_init_request_data(service_module_t *serv,request_t *req);
void   url_check_release_data(void *data);
int    url_check_process(request_t *);
int    url_check_check_preview(char *preview_data,int preview_data_len,request_t *);
int    url_check_io(char *rbuf,int *rlen,char *wbuf,int *wlen,int iseof,request_t *req);
//int    url_check_write(char *buf,int len ,int iseof,request_t *req);
//int    url_check_read(char *buf,int len,request_t *req);


char *url_check_options[]={
     "Allow: 204",
     "Transfer-Preview: *",
     NULL
};


//service_module echo={
CI_DECLARE_MOD_DATA service_module_t service={
     "url_check",
     "Url_Check demo service",
     ICAP_REQMOD,
     url_check_options,
     NULL,/* Options body*/
     url_check_init_service, /* init_service*/
     NULL,/*post_init_service*/
     NULL, /*close_Service*/
     url_check_init_request_data,/* init_request_data*/
     url_check_release_data, /*Release request data*/
     url_check_check_preview,
     url_check_process,
     url_check_io,
     NULL,
     NULL
};
 
struct url_check_data{
     ci_cached_file_t *body;
};

enum http_methods {HTTP_UNKNOWN=0,HTTP_GET, HTTP_POST};

struct http_info{
    int http_major;
    int http_minor;
    int method;
    char site[CI_MAXHOSTNAMELEN+1];
    char page[1024]; /*I think it is enough*/
};


int url_check_init_service(service_module_t *serv,struct icap_server_conf *server_conf){
     printf("Initialization of url_check module......\n");
     return CI_OK;
}


void *url_check_init_request_data(service_module_t *serv,request_t *req){
    struct url_check_data *uc=malloc(sizeof(struct url_check_data));
    uc->body=NULL;
    return uc; /*Get from a pool of pre-allocated structs better......*/
}


void url_check_release_data(void *data){
    struct url_check_data *uc=data;
    if(uc->body)
	ci_cached_file_destroy(uc->body);
    free(uc); /*Return object to pool.....*/
}


int get_http_info(request_t *req,ci_headers_list_t *req_header , struct http_info *httpinf){
    char *str;
    int i;

        /*Now get the site name*/
    str=ci_headers_value(req_header,"Host");
    strncpy(httpinf->site,str,CI_MAXHOSTNAMELEN);
    httpinf->site[CI_MAXHOSTNAMELEN]='\0';

    str=req_header->headers[0];
    if(str[0]=='g' || str[0]=='G') /*Get request....*/
	httpinf->method=HTTP_GET;
    else if(str[0]=='p' || str[0]=='P') /*post request....*/
	httpinf->method=HTTP_POST;
    else{
	 httpinf->method=HTTP_UNKNOWN;
	return 0;
    }
    if((str=strchr(str,' '))==NULL){ /*The request must have the form:GETPOST page HTTP/X.X */
	 return 0;
    }
    while(*str==' ') str++;
    i=0;
    while(*str!=' ' && *str!='\0' && i<1022) /*copy page to the struct.*/
	httpinf->page[i++]=*str++;
    httpinf->page[i]='\0';

    if(*str!=' '){ /*Where is the protocol info?????*/
	 return 0;
    }
    while(*str==' ') str++;
    if(*str!='H' || *(str+4)!='/'){ /*Not in HTTP/X.X form*/
	 return 0;
    }
    str+=5;
    httpinf->http_major=strtol(str,&str,10);
    if(*str!='.'){
	 return 0;
    }
    str++;
    httpinf->http_minor=strtol(str,&str,10);

    
    return 1;
}

int check_destination(struct http_info *httpinf){
     ci_debug_printf(9,"URL  to host %s\n",httpinf->site);
     ci_debug_printf(9,"URL  page %s\n",httpinf->page);
     
//    if(strcmp("www.in.gr",httpinf->site)!=0)/*we like header*/
//      return 0;

    if(strstr(httpinf->page,"images/")!=NULL)
	 return 0;

    return 1;
}

char *error_message="<H1>Permition deny!<H1>";

int url_check_check_preview(char *preview_data,int preview_data_len, request_t *req){
    ci_headers_list_t* req_header;
    struct url_check_data *uc=ci_service_data(req);
    struct http_info httpinf;
    int allow=1;

    ci_reqmod_add_header(req,"Via: C-ICAP  0.01/url_check");/*This type of headers must moved to global*/
    if((req_header=ci_reqmod_headers(req))==NULL) /*It is not possible but who knows .....*/
	return CI_ERROR;

    get_http_info(req,req_header, &httpinf);

    ci_debug_printf(9,"URL  to host %s\n",httpinf.site);
    ci_debug_printf(9,"URL  page %s\n",httpinf.page);

    allow=check_destination(&httpinf);


    if(!allow){
	 /*The URL is not a good one so....*/
	 ci_debug_printf(9,"Oh!!! we are going to deny this site.....\n");

	 uc->body=ci_cached_file_new(strlen(error_message)+10);
	 ci_request_create_respmod(req,1,1); /*Build the responce headers*/

	 ci_respmod_add_header(req,"HTTP/1.1 403 Forbidden");/*Send an 403 Forbidden http responce to web client*/
	 ci_respmod_add_header(req,"Server: C-ICAP");
	 ci_respmod_add_header(req,"Content-Type: text/html");
	 ci_respmod_add_header(req,"Content-Language: en");
	 
	 ci_cached_file_write(uc->body,error_message,strlen(error_message),1);

    }
    else{
	 /*if we are inside preview negotiation or client allow204 responces oudsite of preview then*/
	 if(preview_data || ci_req_allow204(req)) 
	      return CI_MOD_ALLOW204;
	 
	 /*
	   Squid does not support preview of data in reqmod requests neither 204 responces outside preview
	   so we need to read all the body if exists and send it back to squid.
	   Allocate a new body for it 
	 */
	 if(ci_req_hasbody(req)){
	      int clen=ci_content_lenght(req)+100;
	      uc->body=ci_cached_file_new(clen);
	 }

    }

    unlock_data(req);
    return CI_MOD_CONTINUE;
}


int url_check_process(request_t *req){

/*
	  printf("Buffer size=%d, Data size=%d\n ",
		 ((struct membuf *)b)->bufsize,((struct membuf *)b)->endpos);
*/  
     return CI_MOD_DONE;     
}

int url_check_io(char *rbuf,int *rlen,char *wbuf,int *wlen,int iseof,request_t *req){
     int ret;
     struct url_check_data *uc=ci_service_data(req);
     if(!uc->body)
	  return CI_ERROR;

     ret=CI_OK;     
     if(wbuf && wlen){
	  *wlen=ci_cached_file_write(uc->body,wbuf,*wlen,iseof);
	  if(*wlen==CI_ERROR)
	       ret=CI_ERROR;
     }
     else if(iseof)
	  ci_cached_file_write(uc->body,NULL,0,iseof);
     
     if(rbuf && rlen){
	  *rlen=ci_cached_file_read(uc->body,rbuf,*rlen);
	  if(*rlen==CI_ERROR)
	       ret=CI_ERROR;
     }
     
     return ret;
}

