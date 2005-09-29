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


#include "simple_api.h"



/*
int ci_req_hasbody(request_t *req){
     int i;
     ci_encaps_entity_t **e=req->entities;
     for(i=0;e[i]!=NULL;i++)
	  if(e[i]->type==ICAP_NULL_BODY)
	       return 0;
     return 1;
}
*/


ci_header_list_t* ci_respmod_headers(request_t *req){
     int i;
     ci_encaps_entity_t **e_list;
     e_list=req->entities;
     for(i=0;e_list[i]!=NULL&& i<3;i++){ /*It is the first or second ellement*/
	  if( e_list[i]->type==ICAP_RES_HDR )
	       return (ci_header_list_t*) e_list[i]->entity;
	  
     }
     return NULL;
}

ci_header_list_t* ci_reqmod_headers(request_t *req){
     ci_encaps_entity_t **e_list;
     e_list=req->entities;
     if(e_list[0]!=NULL && e_list[0]->type==ICAP_REQ_HDR ) /*It is always the first ellement*/
	  return (ci_header_list_t*) e_list[0]->entity;
          
     return NULL;
}



int   ci_respmod_reset_headers(request_t *req){
     ci_header_list_t *heads;
     if(!(heads=ci_respmod_headers(req)))
	  return 0;
     reset_header(heads);
     return 1;
}

ci_header_list_t *  ci_respmod_build_headers(request_t *req){
     ci_encaps_entity_t **e_list,*e;
     if(ci_respmod_headers(req)){
	  return NULL;
     }
     e_list=req->entities;
     if(e_list[0]==NULL){
	  e_list[0]=mk_encaps_entity(ICAP_RES_HDR,0);
	  e=e_list[0];
     }
     else if(e_list[1]==NULL){
	  e_list[1]=mk_encaps_entity(ICAP_RES_HDR,0);
	  e=e_list[1];
     }
     else{
	  e_list[2]=e_list[1];
	  e_list[1]=mk_encaps_entity(ICAP_RES_HDR,0);
	  e=e_list[1];
     }
     return (ci_header_list_t*)e->entity;
}

int  ci_respmod_create(request_t *req, int hasbody){
     int i;
     ci_encaps_entity_t **e_list;
     e_list=req->entities;

     for(i=0;i<3;i++){
          if(req->entities[i]){
               destroy_encaps_entity(req->entities[i]);
	       req->entities[i]=NULL;
	  }
     }
     req->entities[0]=mk_encaps_entity(ICAP_RES_HDR,0);
     if(hasbody)
          req->entities[1]=mk_encaps_entity(ICAP_RES_BODY,0);
     
     return 1;
}


char * ci_respmod_add_header(request_t *req,char *header){
     ci_header_list_t *heads;
     if(!(heads=ci_respmod_headers(req)))
	  return NULL;
     return add_header(heads,header);
}


char * ci_reqmod_add_header(request_t *req,char *header){
     ci_header_list_t *heads;
     if(!(heads=ci_reqmod_headers(req)))
	  return NULL;
     return add_header(heads,header);
}

int ci_respmod_remove_header(request_t *req,char *header){
     ci_header_list_t *heads;
     if(!(heads=ci_respmod_headers(req)))
	  return 0;
     return remove_header(heads,header);
}


int ci_reqmod_remove_header(request_t *req,char *header){
     ci_header_list_t *heads;
     if(!(heads=ci_reqmod_headers(req)))
	  return 0;
     return remove_header(heads,header);
}


char *ci_respmod_get_header(request_t *req,char *head_name){
     ci_header_list_t *heads;
     char *val;
     if(!(heads=ci_respmod_headers(req)))
	  return NULL;
     if(!(val=get_header_value(heads,head_name)))
	  return NULL;
     return val;
}

char *ci_reqmod_get_header(request_t *req,char *head_name){
     ci_header_list_t *heads;
     char *val;
     if(!(heads=ci_reqmod_headers(req)))
	  return NULL;
     if(!(val=get_header_value(heads,head_name)))
	  return NULL;
     return val;
}


ci_off_t ci_content_lenght(request_t *req){
     ci_header_list_t *heads;
     char *val;
     if(!(heads=ci_respmod_headers(req)))
	  return 0;
     if(!(val=get_header_value(heads,"Content-Length")))
	  return 0;
     return ci_strto_off_t(val,NULL,10);
}

char *ci_http_request(request_t *req){
     ci_header_list_t *heads;
     if(!(heads=ci_reqmod_headers(req)))
	  return NULL;
     return heads->headers[0];
}

