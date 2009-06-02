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
#include "common.h"
#include "request.h"
#include "cfg_param.h"
#include "debug.h"
#include "simple_api.h"
#include "acl.h"
#include "access.h"
#include "mem.h"



int cfg_acl_add(char *directive, char **argv, void *setdata);
struct ci_conf_entry acl_conf_variables[] = {
     {"acl", NULL, cfg_acl_add, NULL},
     {NULL, NULL, NULL, NULL}
};

/*standard acl types */

/*Spec types:
  username: user,
  servicename: service
  requet_type: type
  port : port
  src_ip: src
  dst_ip: srvip
*/

const void *get_user(ci_request_t *req, char *param){
    return req->user;
}
const void *get_service(ci_request_t *req, char *param){
    return req->service;
}

const void *get_reqtype(ci_request_t *req, char *param){
    return ci_method_string(req->type);
}

const void *get_port(ci_request_t *req, char *param){
    return &req->connection->srvaddr.ci_sin_port;
}

const void *get_client_ip(ci_request_t *req, char *param){
    return &(req->connection->claddr);
}

const void *get_srv_ip(ci_request_t *req, char *param){
    return &(req->connection->srvaddr);
}

ci_acl_type_t acl_user={
     "user",
     get_user,
     &ci_str_ops
};

ci_acl_type_t acl_service={
     "service",
     get_service,
     &ci_str_ops
};

ci_acl_type_t acl_req_type={
     "type",
     get_reqtype,
     &ci_str_ops
};

ci_acl_type_t acl_tcp_port={
     "port",
     get_port,
     &ci_int32_ops
};

ci_acl_type_t acl_tcp_src={
     "src",
     get_client_ip,
     &ci_ip_sockaddr_ops
};

ci_acl_type_t acl_tcp_srvip={
     "srvip",
     get_srv_ip,
     &ci_ip_sockaddr_ops
};



/********************************************************************************/
/*   ci_access_entry api   functions                                            */

ci_access_entry_t *ci_access_entry_new(ci_access_entry_t **list, int type)
{
     ci_access_entry_t *access_entry, *cur;

     if (list == NULL)
	  return NULL;

     if(!(access_entry = malloc(sizeof(ci_access_entry_t))))
	 return NULL;
 
     access_entry->type = type;
     access_entry->spec_list = NULL;
     access_entry->next = NULL;

     if (*list == NULL){
	  *list = access_entry;
     }
     else {
	  cur = *list;
	  while (cur->next!=NULL)
	       cur = cur->next;
	  cur->next = access_entry;
     }
     return access_entry;
}

void ci_access_entry_release(ci_access_entry_t *list)
{
    ci_access_entry_t *access_entry;
    ci_specs_list_t *spec_list, *cur;
    if(!list)
	return;

    access_entry = list;
    while (list) {
	access_entry = list;
	list = list->next;
	spec_list = access_entry->spec_list;

	while(spec_list) {
	    cur = spec_list;
	    spec_list = spec_list->next;
	    free(cur);
	}
	free(access_entry);
    }

}

const ci_acl_spec_t *ci_access_entry_add_acl(ci_access_entry_t *access_entry, const ci_acl_spec_t *acl){
     struct ci_specs_list *spec_list,*spec_entry;
     if (access_entry == NULL)
	  return NULL;

     spec_entry = malloc(sizeof(struct ci_specs_list));
     if (spec_entry == NULL)
	  return NULL;

     spec_entry->next = NULL;
     spec_entry->spec = acl;
     if (access_entry->spec_list == NULL) {
	  access_entry->spec_list = spec_entry;
     }
     else {
	  spec_list = access_entry->spec_list;
	  while (spec_list->next != NULL)
	       spec_list = spec_list->next;
	  spec_list->next = spec_entry;
     }
     return acl;
}

/*********************************************************************************/
/*ci_acl_spec functions                                                          */

ci_acl_spec_t *  ci_acl_spec_new(char *name, char *type, char *param, struct ci_acl_type_list *list, ci_acl_spec_t **spec_list)
{
     ci_acl_spec_t *spec,*cur;
     const ci_acl_type_t *acl_type;
     acl_type = ci_acl_typelist_search(list, type);
     if (!acl_type)
	  return NULL;
     
     if (!(spec = malloc(sizeof( ci_acl_spec_t))))
	  return NULL;

     strncpy(spec->name, name, MAX_NAME_LEN);
     spec->name[MAX_NAME_LEN] = '\0';
     if(param) 
	 if (!(spec->parameter = strdup(param)))
	     return NULL;/*leak but if a simple strdup fails who cares....*/
     else
	 spec->parameter = NULL;
     spec->type = acl_type;
     spec->data = NULL;
     spec->next = NULL;

     if (spec_list!=NULL){
	  if (*spec_list!=NULL){
	       cur = *spec_list;
	       while (cur->next!=NULL)
		    cur = cur->next;
	       cur->next = spec;
	  }
	  else
	       *spec_list = spec;
     }     
     return spec;
}

ci_acl_data_t *ci_acl_spec_new_data(ci_acl_spec_t *spec, char *val)
{
     ci_acl_data_t *new_data, *list;
     const ci_type_ops_t *ops;
     void *data;
     
     if (!spec)
	  return NULL;
     
     ops = spec->type->type;
     data = ops->dup(val, default_allocator);
     if (!data)
	 return NULL;

     new_data = malloc(sizeof(ci_acl_data_t));
     new_data->data = data;
     new_data->next = NULL;
     if ((list=spec->data) != NULL) {
	 while (list->next != NULL)
	       list = list->next;
	  list->next = new_data;
     }
     else
	  spec->data = new_data;
     return new_data;
}

ci_acl_spec_t *ci_acl_spec_search(ci_acl_spec_t *list, char *name)
{
     ci_acl_spec_t *spec;
     ci_debug_printf(9,"In search specs list %p,name %s\n", list, name);
     if (!list || !name)
	  return NULL;
     spec = list;
     while (spec!= NULL) {
	 ci_debug_printf(9,"Checking name:%s with specname %s\n", name, spec->name);
	  if (strcmp(spec->name, name) == 0 ) {
		  return spec;
	  }
	  spec = spec->next;
     }
     return NULL;
}


void ci_acl_spec_release(ci_acl_spec_t *cur)
{
     ci_acl_data_t *dhead, *dtmp;
     const ci_type_ops_t *ops;
     dhead = cur->data;
     ops = cur->type->type;
     while (dhead) {
	  dtmp = dhead;
	  dhead = dhead->next;
	  ops->free(dtmp->data, default_allocator);
	  free(dtmp);
     }
}

void ci_acl_spec_list_release(ci_acl_spec_t *spec)
{
     ci_acl_spec_t *cur;
     while (spec) {
	  cur=spec;
	  spec=spec->next;
	  ci_acl_spec_release(cur);
     }
}


/*******************************************************************/
/* ci_acl_type functions                                           */
#define STEP 32

int ci_acl_typelist_init(struct ci_acl_type_list *list)
{
     list->acl_type_list = malloc(STEP*sizeof(ci_acl_type_t));
     list->acl_type_list_size = STEP;
     list->acl_type_list_num = 0;
     return 1;
}

int ci_acl_typelist_add(struct ci_acl_type_list *list,ci_acl_type_t *type)
{
     ci_acl_type_t *cur;
     if (list->acl_type_list_num == list->acl_type_list_size) {
	  list->acl_type_list_size += STEP;
	  list->acl_type_list = realloc(list->acl_type_list, 
					list->acl_type_list_size*sizeof(ci_acl_type_t));
     }

     cur = &(list->acl_type_list[list->acl_type_list_num]);
     strncpy(cur->name, type->name, MAX_NAME_LEN);
     cur->name[MAX_NAME_LEN] = '\0';
     cur->type = type->type;
     cur->get_test_data = type->get_test_data;
     list->acl_type_list_num++;
     return 1;
}

const ci_acl_type_t *ci_acl_typelist_search(struct ci_acl_type_list *list,char *name)
{
     int i;
     for (i=0; i<list->acl_type_list_num; i++) {
	  if(strcmp(list->acl_type_list[i].name,name)==0)
	       return (const ci_acl_type_t *)&list->acl_type_list[i];
     }
     return NULL;
}

int ci_acl_typelist_release(struct ci_acl_type_list *list)
{
     free(list->acl_type_list);
     list->acl_type_list_size = 0;
     list->acl_type_list_num = 0;
     return 1;
}

int ci_acl_typelist_reset(struct ci_acl_type_list *list)
{
     list->acl_type_list_num = 0;
     return 1;
}



/*********************************************************************************/

int spec_data_check(const ci_acl_spec_t *spec, const void *req_raw_data)
{
//    int (*comp)(void *req_spec, void *acl_spec);
    struct ci_acl_data *spec_data=spec->data;
    const ci_type_ops_t *ops = spec->type->type;
    
    ci_debug_printf(9,"Check request with ci_acl_spec_t:%s\n", spec->name);
    while (spec_data!=NULL) {
	if (ops->equal(spec_data->data, (void *)req_raw_data)) {
	    ci_debug_printf(9,"The ci_acl_spec_t:%s matches\n", spec->name);
	    return 1;
	}
	spec_data=spec_data->next;
    }
    return 0;
}

int request_match_specslist(ci_request_t *req, const struct ci_specs_list *spec_list)
{
    const ci_acl_spec_t *spec;
    const ci_acl_type_t *type;
    
    while (spec_list!=NULL) {
	spec = spec_list->spec;
	type = spec->type;
	if (!spec_data_check(spec, type->get_test_data(req, spec->parameter)))
	    return 0;
	spec_list=spec_list->next;
    }
    return 1;
}

int access_entry_match_request(ci_access_entry_t *access_entry, ci_request_t *req)
{
    struct ci_specs_list *spec_list;

    if (!access_entry)
	return CI_ACCESS_ALLOW;

    while(access_entry) {
	ci_debug_printf(9,"Check request with an access entry\n");
	spec_list = access_entry->spec_list;
	if (spec_list->spec && request_match_specslist(req, spec_list))
	    return access_entry->type;

	access_entry=access_entry->next;
    }
    return CI_ACCESS_UNKNOWN;
}


/**********************************************************************************/
/* acl library functions                                                          */

static struct ci_acl_type_list types_list;
static struct ci_acl_spec *specs_list;

extern ci_acl_type_t acl_user;
extern ci_acl_type_t acl_service;
extern ci_acl_type_t acl_req_type;
extern ci_acl_type_t acl_tcp_port;
extern ci_acl_type_t acl_tcp_src;
extern ci_acl_type_t acl_tcp_srvip;

static int acl_load_defaults()
{
     ci_acl_typelist_add(&types_list,&acl_tcp_port);
     ci_acl_typelist_add(&types_list,&acl_service);
     ci_acl_typelist_add(&types_list,&acl_req_type);
     ci_acl_typelist_add(&types_list,&acl_user);
     ci_acl_typelist_add(&types_list,&acl_tcp_src);
     ci_acl_typelist_add(&types_list,&acl_tcp_srvip);
     return 1;
}

void ci_acl_init()
{
     ci_acl_typelist_init(&types_list);
     acl_load_defaults();
     specs_list = NULL;
}

void ci_acl_reset()
{
     ci_acl_spec_list_release(specs_list);
     specs_list = NULL;
     ci_acl_typelist_reset(&types_list);
     acl_load_defaults();
}

const ci_acl_spec_t *ci_acl_search(char *name){
    return (const ci_acl_spec_t *)ci_acl_spec_search(specs_list, name);
}

const ci_acl_type_t *ci_acl_type_search(char *name){
     return ci_acl_typelist_search(&types_list, name);
}

int cfg_acl_add(char *directive, char **argv, void *setdata)
{
    char *s, *acl_name,*acl_type, *param=NULL;
     int argc;
     ci_acl_spec_t *spec;
     const ci_acl_type_t *spec_type;

     if (!argv[0] || !argv[1] || !argv[2]) /* at least an argument */
	 return 0;
     
     
     acl_name = argv[0];
     acl_type = argv[1];
     if ((s=strchr(argv[1],'{')) != NULL) {
	 *s='\0';
	 param=s+1;
	 if((s=strchr(param,'}')) != NULL)
	     s= '\0';
     }

     if ((spec=ci_acl_spec_search(specs_list, acl_name)) != NULL){
	  spec_type = ci_acl_typelist_search(&types_list, acl_type);
	  if(spec_type != spec->type){
	       ci_debug_printf(1, "The acl type:%s does not much with type of existing acl \"%s\"", 
			       acl_type,acl_name);
	       return 0;
	  }
     }
     else {
	 ci_debug_printf(1, "New ACL with name:%s and  ACL Type: %s{%s}\n", argv[0], argv[1],param?param:"NULL");
	  spec = ci_acl_spec_new(acl_name, acl_type, param, &types_list, &specs_list);
     }

     if (!spec){
	  ci_debug_printf(1, "Error in acl:%s! Maybe the acl type \"%s\" does not exists!\n",
			  acl_name,acl_type);
	  return 0;
     }
     for (argc = 2; argv[argc] != NULL; argc++){
	  ci_debug_printf(1, "Adding to acl %s the data %s\n", acl_name, argv[argc]);
	  ci_acl_spec_new_data(spec, argv[argc]);
     }	  
     return 1;
}

