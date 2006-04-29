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


#ifndef __HEADERS_H
#define __HEADERS_H

#include "c-icap.h"


enum ci_request_headers { ICAP_AUTHORIZATION, ICAP_ALLOW,
                       ICAP_FROM, ICAP_HOST, ICAP_REFERER,
                       ICAP_USERAGENT,ICAP_PREVIEW
                      };


extern const char *CI_CommonHeaders[];
extern const char *CI_RequestHeaders[];
extern const char *CI_ResponceHeaders[];
extern const char *CI_OptionsHeaders[];


enum ci_encapsulated_entities {ICAP_REQ_HDR, ICAP_RES_HDR,
			       ICAP_REQ_BODY, ICAP_RES_BODY,
			       ICAP_NULL_BODY,ICAP_OPT_BODY };
CI_DECLARE_DATA extern const char *CI_EncapsEntities[];

#ifdef __CYGWIN__

const char *ci_encaps_entity_string(int e);

#else

#define ci_encaps_entity_string(e) (e<=ICAP_OPT_BODY&&e>=ICAP_REQ_HDR?CI_EncapsEntities[e]:"UNKNOWN")

#endif 


typedef struct ci_header_list{
     int size;
     int used;
     char **headers;
     int bufsize;
     int bufused;
     char *buf;
} ci_header_list_t;


typedef struct ci_encaps_entity{
     int start;
     int type;
     void *entity;
} ci_encaps_entity_t;


#define BUFSIZE          4096
#define HEADERSTARTSIZE  64
#define HEADSBUFSIZE     BUFSIZE

CI_DECLARE_FUNC(ci_header_list_t *) mk_header();
CI_DECLARE_FUNC(void)    destroy_header(ci_header_list_t *);
CI_DECLARE_FUNC(int)     set_size_header(ci_header_list_t *h, int size);
CI_DECLARE_FUNC(char *)  add_header(ci_header_list_t *h, char *line);
CI_DECLARE_FUNC(int)     remove_header(ci_header_list_t *h, char *header);
CI_DECLARE_FUNC(char *)  search_header(ci_header_list_t *h, char *header);
CI_DECLARE_FUNC(char *)  get_header_value(ci_header_list_t *h, char *header);
CI_DECLARE_FUNC(void)    reset_header(ci_header_list_t *h);
CI_DECLARE_FUNC(ci_encaps_entity_t) *mk_encaps_entity(int type,int val);
CI_DECLARE_FUNC(void) destroy_encaps_entity(ci_encaps_entity_t *e);
CI_DECLARE_FUNC(int) get_encaps_type(char *buf,int *val,char **endpoint);
CI_DECLARE_FUNC(int)  get_method(char *buf);

CI_DECLARE_FUNC(int)  sizeofheader(ci_header_list_t *h);
CI_DECLARE_FUNC(int)  sizeofencaps(ci_encaps_entity_t *e);
CI_DECLARE_FUNC(void) ci_headers_pack(ci_header_list_t *h);
CI_DECLARE_FUNC(int)  ci_headers_unpack(ci_header_list_t *h);
#endif
