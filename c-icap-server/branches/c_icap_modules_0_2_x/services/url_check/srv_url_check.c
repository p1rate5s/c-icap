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
#include "lookup_table.h"
#include "debug.h"
#include "access.h"
#include "acl.h"
#include "../../common.h"
#include "commands.h"
#include "txt_format.h"
#include "txtTemplate.h"
#if defined(HAVE_BDB)
#include "sguardDB.h"
#endif
#include "url_check_body.h"

/*Structs for this module */
enum http_methods { METHOD_UNKNOWN = 0, 
                    HTTP_GET,
                    HTTP_POST,
                    HTTP_PUT,
                    HTTP_HEAD,
                    HTTP_CONNECT,
                    HTTP_TRACE,
                    HTTP_OPTIONS,
                    HTTP_DELETE,
                    METHOD_END
};

const char *http_methods_str[] = {
    "UNKNOWN",
    "GET",
    "POST",
    "PUT",
    "HEAD",
    "CONNECT",
    "TRACE",
    "OPTIONS",
    "DELETE",
    NULL
};


#define CHECK_HOST     0x01
#define CHECK_URL      0x02
#define CHECK_FULL_URL 0x04
#define CHECK_DOMAIN   0x08
#define CHECK_SRV_IP   0x10
#define CHECK_SRV_NET  0x20
#define CHECK_SIMPLE_URL 0x40

#define MAX_URL_SIZE  65536
#define MAX_PAGE_SIZE (MAX_URL_SIZE - CI_MAXHOSTNAMELEN)

const char *protos[] = {"", "http", "https", "ftp", NULL};
enum proto {UNKNOWN=0, HTTP, HTTPS, FTP};

struct http_info {
    int http_major;
    int http_minor;
    int method;
    unsigned int port;
    int proto;
    char host[CI_MAXHOSTNAMELEN + 1];
    char server_ip[64];                   /*I think ipv6 address needs about 32 bytes*/
    char site[CI_MAXHOSTNAMELEN + 1];
    char url[MAX_URL_SIZE];              /* I think it is enough */
    char *args;
};

#define _MATCHDB_SZ 1024
#define _DB_NAME_SIZE 128
struct match_info {
    char matched_dbs[_MATCHDB_SZ];
    int match_length;
    char last_subcat[_DB_NAME_SIZE];
    char action_db[_DB_NAME_SIZE];
    int action;
};

static void match_info_init(struct match_info *match_info);
static void match_info_append_db(struct match_info *match_info, const char *, const char *);

enum {SBC_EQ = 1, SBC_LESS, SBC_GREATER};
struct subcats_data{
    const char *str;
    int op;
    int score;
};

enum lookupdb_types {DB_INTERNAL, DB_SG, DB_LOOKUP};

struct lookup_db {
  char *name;
  int type;
  unsigned int check;
  void *db_data;
  void * (*load_db)(struct lookup_db *db, const char *path);
    int    (*lookup_db)(struct lookup_db *db, struct http_info *http_info, struct match_info *match_info, ci_ptr_vector_t *subcats);
  void   (*release_db)(struct lookup_db *db);
  struct lookup_db *next;
};

static struct lookup_db *LOOKUP_DBS = NULL;

static int add_lookup_db(struct lookup_db *ldb);
static struct lookup_db *new_lookup_db(const char *name, int type,
				unsigned int check,
				void *(*load_db)(struct lookup_db *ldb, const char *path),
				int (*lookup_db)(struct lookup_db *ldb,
                                                 struct http_info *http_info,
                                                 struct match_info *match_info,
                                                 ci_ptr_vector_t *subcats),
				void (*release_db)(struct lookup_db *ldb)
				);
/* ALL lookup_db functions*/
static int all_lookup_db(struct lookup_db *ldb, struct http_info *http_info, struct match_info *match_info, ci_ptr_vector_t *subcats);
static void release_lookup_dbs();

enum actions_enum { DB_ERROR=-1, DB_BLOCK=0, DB_PASS, DB_MATCH, DB_ACT_MAX};

static const char *actions_str[] = {
    "BLOCKED",
    "ALLOWED",
    "MATCHED"
};

#define ACTION_STR(id)(id>=0 && id<DB_ACT_MAX?actions_str[id]:"UNKNWON")

struct access_db {
  struct lookup_db *db;
  ci_ptr_vector_t *subcats;
  int pass;
  struct access_db *next;
};

struct profile {
  char *name;
  ci_access_entry_t *access_list;
  struct access_db *dbs;
  struct profile *next;
};

static struct profile *PROFILES = NULL;
int EARLY_RESPONSES = 1;

int url_check_init_service(ci_service_xdata_t * srv_xdata,
                           struct ci_server_conf *server_conf);
void *url_check_init_request_data(ci_request_t * req);
void url_check_release_data(void *data);
int url_check_process(ci_request_t *);
int url_check_check_preview(char *preview_data, int preview_data_len,
                            ci_request_t *);
int url_check_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof,
                 ci_request_t * req);
void url_check_close_service();
//int    url_check_write(char *buf,int len ,int iseof,ci_request_t *req);
//int    url_check_read(char *buf,int len,ci_request_t *req);

/*Profile functions */
static struct profile *profile_search(const char *name);
static struct profile *profile_select(ci_request_t *req);


/*********************/
/* Formating table   */

int fmt_srv_urlcheck_http_url(ci_request_t *req, char *buf, int len, const char *param);
int fmt_srv_urlcheck_host(ci_request_t *req, char *buf, int len, const char *param);
int fmt_srv_urlcheck_matched_dbs(ci_request_t *req, char *buf, int len, const char *param);
int fmt_srv_urlcheck_blocked_db(ci_request_t *req, char *buf, int len, const char *param);
struct ci_fmt_entry srv_urlcheck_format_table [] = {
    {"%UU", "The HTTP url", fmt_srv_urlcheck_http_url},
    {"%UH", "The HTTP host", fmt_srv_urlcheck_host},
    {"%UM", "The matched Categories", fmt_srv_urlcheck_matched_dbs},
    {"%UB", "The blocked category", fmt_srv_urlcheck_blocked_db},
    { NULL, NULL, NULL}
};


/*Config functions*/
int cfg_load_sg_db(const char *directive, const char **argv, void *setdata);
int cfg_load_lt_db(const char *directive, const char **argv, void *setdata);
int cfg_profile(const char *directive, const char **argv, void *setdata);
int cfg_profile_access(const char *directive, const char **argv, void *setdata);
/*Configuration Table .....*/
static struct ci_conf_entry conf_variables[] = {
#if defined(HAVE_BDB)
  {"LoadSquidGuardDB", NULL, cfg_load_sg_db, NULL},
#endif
  {"LookupTableDB", NULL, cfg_load_lt_db, NULL},
  {"Profile", NULL, cfg_profile, NULL},
  {"ProfileAccess", NULL, cfg_profile_access, NULL},
  {"EarlyResponses", &EARLY_RESPONSES, ci_cfg_onoff, NULL},
  {NULL, NULL, NULL, NULL}
};

CI_DECLARE_MOD_DATA ci_service_module_t service = {
     "url_check",
     "Url_Check demo service",
     ICAP_REQMOD,
     url_check_init_service,    /* init_service */
     NULL,                      /*post_init_service */
     url_check_close_service,                      /*close_Service */
     url_check_init_request_data,       /* init_request_data */
     url_check_release_data,    /*Release request data */
     url_check_check_preview,
     url_check_process,
     url_check_io,
     conf_variables,
     NULL
};

static int URL_CHECK_DATA_POOL = -1;
struct url_check_data {
     struct body_data body;
     struct http_info httpinf;
     int denied;
    struct match_info match_info;
};


int url_check_init_service(ci_service_xdata_t * srv_xdata,
                           struct ci_server_conf *server_conf)
{
     unsigned int xops;
     struct lookup_db *int_db;
     ci_debug_printf(2, "Initialization of url_check module......\n");
     ci_service_set_preview(srv_xdata, 0);
     xops = CI_XCLIENTIP | CI_XSERVERIP;
     xops |= CI_XAUTHENTICATEDUSER | CI_XAUTHENTICATEDGROUPS;
     ci_service_set_xopts(srv_xdata, xops);

     /*initialize mempools          */
     URL_CHECK_DATA_POOL = ci_object_pool_register("url_check_data", 
						   sizeof(struct url_check_data));

     if (URL_CHECK_DATA_POOL < 0)
	 return CI_ERROR;
     /*Add internal database lookups*/
     int_db = new_lookup_db("ALL", DB_INTERNAL, CHECK_HOST, NULL,
			    all_lookup_db,
			    NULL);
     if(int_db)
       return add_lookup_db(int_db);

     return CI_OK;
}

void url_check_close_service()
{
    ci_object_pool_unregister(URL_CHECK_DATA_POOL);
    release_lookup_dbs();
}


void *url_check_init_request_data(ci_request_t * req)
{
     struct url_check_data *uc = ci_object_pool_alloc(URL_CHECK_DATA_POOL);
     uc->denied = 0;
     memset(&uc->body, 0, sizeof(struct body_data));
     match_info_init(&uc->match_info);
     return uc;      /*Get from a pool of pre-allocated structs better...... */
}


void url_check_release_data(void *data)
{
     struct url_check_data *uc = data;
     if (uc->body.type)
          body_data_destroy(&uc->body);

     ci_object_pool_free(uc);    /*Return object to pool..... */
}

int get_protocol(const char *str,int size) 
{
    int i;
    for(i=0; protos[i]!=NULL; i++) {
	if(strncmp(str,protos[i],size)==0)
	    return i;
    }
    return 0;
}

int strncasecmp_word(const char *word, const char *buf, const char **e)
{
    const char *s = word;
    const char *d = buf;
    while(*s && *d && !strchr(" \t\n\r", *d)) {
        if (tolower(*s) != tolower(*d))
            return -1;
        s++, d++;
    }
    *e = d;
    return 0;
}

int get_method(const char *buf, const char **end)
{
    const char *s;
    size_t l;
    int i;
    l = strspn(buf, " \n\r\t");
    s = buf+l;
    for (i = 1; i < METHOD_END;i++) {
        if (strncasecmp_word(http_methods_str[i], s, end) == 0) {
            return i;
        }
    }
    l = strcspn(s, " \n\r\t");
    *end = s + l;
    return METHOD_UNKNOWN;
}

int parse_connect_url(struct http_info *httpinf, const char *buf, const char **end)
{
    const char *str = buf;
    char *e;
    size_t ulen = 0;
    while (*str != '\0' && *str != ' ' &&  *str != ':' &&
           *str != '\r' && *str != '\n' 
           && *str != '\t') {
        httpinf->url[ulen] = tolower(*str);
        httpinf->site[ulen] = httpinf->url[ulen] ;
        ulen++;
        str++;
    }
    httpinf->url[ulen] = '\0';
    httpinf->site[ulen] = '\0';
    if(*str==':'){
        httpinf->port = strtol(str+1,&e,10);
        if(!e) { /*parse error*/
            *end = e;
            return 0;
        }
        str = e;
    }
    *end = str;
    httpinf->proto = HTTPS;
    return 1;
}

/*Macro to convert a char hex digit to numeric*/
#define ctox(h) (h >= 'A'? (toupper(h) - 'A' + 10) : toupper(h) - '0')

int parse_url(struct http_info *httpinf, const char *buf, const char **end)
{
    char c;
    char *tmp;
    const char *str = buf;
    size_t url_len;
    if ((tmp=strstr(str,"://"))) {	 
        httpinf->proto = get_protocol(str, tmp-str);
        str = tmp+3;
        url_len = 0;
        while(*str != ':' && *str != '/'  && *str != ' ' && *str != '\0' && url_len < CI_MAXHOSTNAMELEN){
            httpinf->site[url_len] = tolower(*str); /*Is it possible to give us hostname with uppercase letters?*/
            httpinf->url[url_len] = httpinf->site[url_len];
            url_len++;
            str++;
        }
        httpinf->site[url_len] = '\0';
        httpinf->url[url_len] = '\0';
        if(*str==':'){
            httpinf->port = strtol(str+1,&tmp,10);
            if(!tmp || *tmp!='/') {
                *end = str;
                return 0;
            }
            /*Do we want the port contained into URL? if no:*/
            /*str = tmp;*/
        }
    } else {
        strcpy(httpinf->url, httpinf->host);
        strcpy(httpinf->site, httpinf->host);
        url_len = strlen(httpinf->url);
        // httpinf->port = 80;
        httpinf->proto = HTTP;
    }

    while (*str != ' ' && *str != '\0' && url_len < MAX_PAGE_SIZE) {  /*copy page to the struct. */
        if (*str == '?' && ! httpinf->args) {
            httpinf->url[url_len++] = *str++;
            httpinf->args = &(httpinf->url[url_len]);             
        } else  if (*str == '%' && 
                    isxdigit(*(str+1)) && 
                    /* only printable ascii,  0x20 <= ascii  <= 0x7e :*/
                    *(str+1) <= '7' && *(str+1) >= '2' &&
                    isxdigit(*(str+2)) ) {
             
            c  = 16 * ctox(*(str+1)) + ctox(*(str+2));
            /*if it is not space, '+', '%' and it is not 7f=127*/
            if (strchr(" +%?", c) == NULL && c < 127) {
                httpinf->url[url_len++] = c;
                str += 3;
            }
            else
                httpinf->url[url_len++] = *str++;
        }
        else //TODO: maybe convert to %xx any non asciii char
            httpinf->url[url_len++] = *str++;
    }

    httpinf->url[url_len] = '\0';
    *end = str;
    return 1;
}

int get_http_info(ci_request_t * req, ci_headers_list_t * req_header,
                  struct http_info *httpinf)
{
     const char *str;
     char *tmp;

     /*Initialize htto_info struct*/
     httpinf->url[0]='\0';
     httpinf->args = NULL;
     httpinf->site[0] = '\0';
     httpinf->host[0] = '\0';
     httpinf->server_ip[0] = '\0';
     httpinf->method = METHOD_UNKNOWN;
     httpinf->port = 0;
     httpinf->proto = UNKNOWN;
     httpinf->http_major = -1;
     httpinf->http_minor = -1;

     /*Now get the site name */
     str = ci_headers_value(req_header, "Host");
     if (str) {
          tmp = httpinf->host;
          for (tmp = httpinf->host; *str != '\0' && (tmp - httpinf->host) < CI_MAXHOSTNAMELEN; tmp++,str++)
               *tmp = tolower(*str); 
          *tmp = '\0';
          httpinf->host[CI_MAXHOSTNAMELEN] = '\0';
     }

     /*
       When x-server-ip implemented in c-icap (and squid3)
       strcpy(http->inf,req->xserverip);
       else do a getipbyname
     */

     str = req_header->headers[0];
     httpinf->method = get_method(str, &str);
     while (*str == ' ') str++;

     if (httpinf->method == HTTP_CONNECT) {
         if (!parse_connect_url(httpinf, str, &str))
             return 0;
     }
     else if (!parse_url(httpinf, str, &str))
         return 0;

     if (*str != ' ') {         /*Where is the protocol info????? */
          return 0;
     }
     while (*str == ' ')
          str++;
     if (*str != 'H' || *(str + 4) != '/') {    /*Not in HTTP/X.X form */
          return 0;
     }
     str += 5;
     httpinf->http_major = strtol(str, &tmp, 10);
     if (!tmp || *tmp != '.') {
          return 0;
     }
     str = tmp + 1;
     httpinf->http_minor = strtol(str, NULL, 10);

     return 1;
}

static int profile_access(struct profile *prof, struct http_info *info, struct match_info *match_info);

int url_check_check_preview(char *preview_data, int preview_data_len,
                            ci_request_t * req)
{
     ci_headers_list_t *req_header;
     ci_membuf_t *err_page;
     char buf[256];
     const char *lang;
     struct url_check_data *uc = ci_service_data(req);     
     struct profile *profile;
     int clen = 0;
     int pass = DB_PASS;

     if ((req_header = ci_http_request_headers(req)) == NULL) /*It is not possible but who knows ..... */
          return CI_ERROR;

     if (!get_http_info(req, req_header, &uc->httpinf)) { /*Unknown method or something else...*/
         ci_debug_printf(2, "srv_url_check: Can not get required information to process request. Firstline: %s\n", req_header->headers[0]);
	 return CI_MOD_ALLOW204;
     }

     ci_debug_printf(9, "srv_url_check: URL  to host %s\n", uc->httpinf.site);
     ci_debug_printf(9, "srv_url_check: URL  page %s\n", uc->httpinf.url);

     profile = profile_select(req);

     if (!profile) {
          ci_debug_printf(1, "srv_url_check: No Profile configured! Allowing the request...\n");
	  return CI_MOD_ALLOW204;
     }
     
     snprintf(buf, sizeof(buf), "X-ICAP-Profile: %s", profile->name);
     buf[sizeof(buf)-1] = '\0';
     ci_icap_add_xheader(req, buf);

     if ((pass=profile_access(profile, &uc->httpinf, &uc->match_info)) == DB_ERROR) {
          ci_debug_printf(1,"srv_url_check: Error searching in profile! Allow the request\n");
	  return CI_MOD_ALLOW204;
     }
     
     if (uc->match_info.matched_dbs[0]) {
         ci_request_set_str_attribute(req,"url_check:matched_cat", uc->match_info.matched_dbs);
         snprintf(buf, sizeof(buf), "X-Attribute: %s", uc->match_info.matched_dbs);
         buf[sizeof(buf)-1] = '\0';
         ci_icap_add_xheader(req, buf);         
     }
     if (uc->match_info.match_length) {
         snprintf(buf, sizeof(buf), "X-Attribute-Prefix: %d", uc->match_info.match_length);
         buf[sizeof(buf)-1] = '\0';
         ci_icap_add_xheader(req, buf);         
     }
     if (uc->match_info.action >=0) {
         ci_request_set_str_attribute(req,"url_check:action", ACTION_STR(uc->match_info.action));
         snprintf(buf, sizeof(buf), "X-Response-Info: %s", ACTION_STR(uc->match_info.action));
         buf[sizeof(buf)-1] = '\0';
         ci_icap_add_xheader(req, buf);
         if (uc->match_info.action_db[0] != '\0') {
             if (uc->match_info.last_subcat[0] != '\0') {
                 snprintf(buf, sizeof(buf), "%s{%s}", uc->match_info.action_db, uc->match_info.last_subcat);
                 buf[sizeof(buf)-1] = '\0';
                 ci_request_set_str_attribute(req,"url_check:action_cat", buf);
                 snprintf(buf, sizeof(buf), "X-Response-Desc: URL category %s{%s} is %s", uc->match_info.action_db, uc->match_info.last_subcat, ACTION_STR(uc->match_info.action));
                 ci_debug_printf(5, "srv_url_check: %s: %s{%s}, http url: %s\n",
                        ACTION_STR(uc->match_info.action),
                        uc->match_info.action_db,
                        uc->match_info.last_subcat,
                        uc->httpinf.url);
             }
             else {
                 ci_request_set_str_attribute(req,"url_check:action_cat", uc->match_info.action_db);
                 snprintf(buf, sizeof(buf), "X-Response-Desc: URL category %s is %s", uc->match_info.action_db, ACTION_STR(uc->match_info.action));
                 snprintf(buf, sizeof(buf), "X-Response-Desc: URL category %s is %s", uc->match_info.action_db, ACTION_STR(uc->match_info.action));
                 ci_debug_printf(5, "srv_url_check: %s: %s, http url: %s\n",
                        ACTION_STR(uc->match_info.action),
                        uc->match_info.action_db,
                        uc->httpinf.url);
             }
             buf[sizeof(buf)-1] = '\0';
             ci_icap_add_xheader(req, buf);
         }
     }

     /*
       TODO: When 206 ICAP responses be supported implement configuration parameter
       which appends HTTP headers if any URL matches.
       This will allow user implement services which just append an HTTP header with
       informations about site and let http proxy to decide for an action.
     */

     if (pass == DB_BLOCK) {
          /*The URL is not a good one so.... */
          ci_debug_printf(9, "srv_url_check: Oh!!! we are going to deny this site.....\n");

          uc->denied = 1;
          ci_http_response_create(req, 1, 1); /*Build the responce headers */

          ci_http_response_add_header(req, "HTTP/1.0 403 Forbidden"); /*Send an 403 Forbidden http responce to web client */
          ci_http_response_add_header(req, "Server: C-ICAP");
          ci_http_response_add_header(req, "Content-Type: text/html");
          ci_http_response_add_header(req, "Connection: close");

	  err_page = ci_txt_template_build_content(req, "srv_url_check", "DENY", srv_urlcheck_format_table);
          lang = ci_membuf_attr_get(err_page, "lang");
          if (lang) {
              snprintf(buf, sizeof(buf), "Content-Language: %s", lang);
              buf[sizeof(buf)-1] = '\0';
              ci_http_response_add_header(req, buf);
          }
          else
              ci_http_response_add_header(req, "Content-Language: en");
	  /*Are we sure that the txt_template code does not return a NULL page?
	    Well, yes ...
	   */
          body_data_init(&uc->body, ERROR_PAGE, 0, err_page);
     }
     else {
          /*if we are inside preview negotiation or client allow204 responces oudsite of preview then */
          if (preview_data || ci_req_allow204(req))
               return CI_MOD_ALLOW204;

          /*
             icap client does not support preview of data in reqmod requests neither 204 responces outside preview
             so we need to read all the body if exists and send it back to client.
             Allocate a new body for it 
           */
          if (ci_req_hasbody(req)) {
               clen = ci_http_content_length(req);
               body_data_init(&uc->body, EARLY_RESPONSES?RING:CACHED, clen, NULL);
          }

     }

     unlock_data(req);
     return CI_MOD_CONTINUE;
}


int url_check_process(ci_request_t * req)
{

/*
	  printf("Buffer size=%d, Data size=%d\n ",
		 ((struct membuf *)b)->bufsize,((struct membuf *)b)->endpos);
*/
     return CI_MOD_DONE;
}

int url_check_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof,
                 ci_request_t * req)
{
     int ret;
     struct url_check_data *uc = ci_service_data(req);

     /*Here we are only if we */
     if (!uc->body.type)
          return CI_ERROR;

     ret = CI_OK;

     if (rlen && rbuf) {
         *rlen = body_data_write(&uc->body, rbuf, *rlen, iseof);
         if (*rlen == CI_ERROR)
             ret = CI_ERROR;
     }
     else if (iseof)
         body_data_write(&uc->body, NULL, 0, iseof); /*should return ret = CI_OK*/

     if (uc->body.type && wbuf && wlen) {
         if (EARLY_RESPONSES || body_data_haseof((&uc->body))) {
             *wlen = body_data_read(&uc->body, wbuf, *wlen);
             if (*wlen == CI_ERROR)
                 ret = CI_ERROR;
         }
         else {
             ci_debug_printf(9, "srv_url_check: Does not allow early responses, wait for eof before send data\n");
             *wlen = 0;
         }
     }

     return ret;
}

/*********************************************/
void match_info_init(struct match_info *match_info)
{
    match_info->matched_dbs[0] = '\0';
    match_info->match_length = 0;
    match_info->action_db[0] = '\0';
    match_info->action = -1;
    match_info->last_subcat[0] = '\0';
}

void match_info_append_db(struct match_info *match_info, const char *db_name, const char *sub_cats)
{
    int len = strlen(match_info->matched_dbs);
    if (len >0 ) {/*if it is not empty*/
        if (_MATCHDB_SZ - len < 3)
            return; /*no space left*/
        match_info->matched_dbs[len++] = ',';
        match_info->matched_dbs[len++] = ' ';
        match_info->matched_dbs[len] = '\0';
    }
    if (!sub_cats) {
        /*strncat always put a '\0' at the end*/
        strncat(match_info->matched_dbs + len, db_name, _MATCHDB_SZ-len);
        match_info->last_subcat[0] = '\0';
    } else {
        snprintf(match_info->matched_dbs + len, _MATCHDB_SZ-len, "%s{%s}", db_name, sub_cats);
        match_info->matched_dbs[_MATCHDB_SZ - 1] = '\0';
        strncpy(match_info->last_subcat, sub_cats, _DB_NAME_SIZE);
        match_info->last_subcat[_DB_NAME_SIZE - 1] = '\0';
    }   
}

/******************************************************************/
/* Lookup databases functions                                     */

struct lookup_db *new_lookup_db(const char *name,
				int type,
				unsigned int check,
				void *(*load_db)(struct lookup_db *,const char *path),
				int (*lookup_db)(struct lookup_db *ldb, 
                                                 struct http_info *http_info,
                                                 struct match_info *match_info,
                                                 ci_ptr_vector_t *subcats),
				void (*release_db)(struct lookup_db *ldb)
				)
{
  struct lookup_db *ldb = malloc(sizeof(struct lookup_db));
  
  if(!ldb)
    return NULL;

  ldb->name = strdup(name);
  ldb->type = type;
  ldb->check = check;
  ldb->db_data = NULL;
  ldb->load_db = load_db;
  ldb->lookup_db = lookup_db;
  ldb->release_db = release_db;
  ldb->next = NULL;
  return ldb;
}

int add_lookup_db(struct lookup_db *ldb)
{
  struct lookup_db *tmp_ldb;

  if(!ldb)
    return 0;

  ldb->next=NULL;

  if(LOOKUP_DBS == NULL){
    LOOKUP_DBS=ldb;
    return 1;
  }
  
  tmp_ldb = LOOKUP_DBS;
  while(tmp_ldb->next != NULL) tmp_ldb = tmp_ldb->next;
  
  tmp_ldb->next=ldb;
  return 1;
}

struct lookup_db *search_lookup_db(const char *name)
{
  struct lookup_db *tmp_ldb;
  if((tmp_ldb=LOOKUP_DBS) == NULL)
    return NULL;
  
  while((tmp_ldb != NULL) && (strcmp(tmp_ldb->name,name) != 0))
    tmp_ldb=tmp_ldb->next;
  
  return tmp_ldb;
}

void release_lookup_dbs()
{
  struct lookup_db *tmp_ldb;

  while((tmp_ldb = LOOKUP_DBS)){
    LOOKUP_DBS=LOOKUP_DBS->next;
    free(tmp_ldb->name);
    if(tmp_ldb->release_db)
      tmp_ldb->release_db(tmp_ldb);
    free(tmp_ldb);
  }
}

/*****************************************************************/
/* Profile definitions                                           */

struct profile *profile_select(ci_request_t *req)
{
  struct profile *tmp_profile, *default_profile;
  default_profile = NULL;
  tmp_profile = PROFILES;
  while(tmp_profile) {

    if (tmp_profile->access_list &&
	(ci_access_entry_match_request(tmp_profile->access_list, 
				       req) == CI_ACCESS_ALLOW)) {
        return tmp_profile;
    }
    
    if (strcmp(tmp_profile->name,"default")==0)
        default_profile = tmp_profile;

    tmp_profile = tmp_profile->next;
  }
  return default_profile;
}

struct profile *profile_search(const char *name)
{
  struct profile *tmp_profile;
  tmp_profile = PROFILES;
  while(tmp_profile) {
    if(strcmp(tmp_profile->name,name)==0)
      return tmp_profile;
    tmp_profile = tmp_profile->next;
  }
  return NULL;
}

struct profile *profile_check_add(const char *name)
{
  struct profile *tmp_profile;
  if((tmp_profile=profile_search(name)))
    return tmp_profile;

  /*Else create a new one and add it to the head of the list*/
  if(!(tmp_profile = malloc(sizeof(struct profile))))
    return NULL;
  tmp_profile->name = strdup(name);
  tmp_profile->access_list = NULL;
  tmp_profile->dbs = NULL;
  tmp_profile->next = PROFILES;

  ci_debug_printf(2, "srv_url_check: Add profile :%s\n", name);

  return (PROFILES = tmp_profile);
}

struct access_db *profile_add_db(struct profile *prof, struct lookup_db *db, int type, ci_ptr_vector_t *cats)
{
  struct access_db *new_adb,*tmp_adb;
  if(!prof || !db)
    return NULL;
  
  new_adb = malloc(sizeof(struct access_db));
  new_adb->db = db;
  new_adb->subcats = cats;
  new_adb->pass = type;
  new_adb->next = NULL;
  
  tmp_adb = prof->dbs;
  if (!tmp_adb)
    return (prof->dbs = new_adb);

  while(tmp_adb->next!= NULL) 
    tmp_adb = tmp_adb->next;
  
  tmp_adb->next = new_adb;
  
  return new_adb;
}

int profile_access(struct profile *prof, struct http_info *info, struct match_info *match_info)
{
  struct access_db *adb;
  struct lookup_db *db = NULL;
  adb=prof->dbs;
  while (adb) {
    db=adb->db;
    if(!db) {
      ci_debug_printf(1, "srv_url_check: Empty access DB in profile %s! is this possible????\n",
		      prof->name);
      return DB_ERROR;
    }

    if(!db->lookup_db) {
      ci_debug_printf(1, "srv_url_check: The db %s in profile %s has not an lookup_db method implemented!\n",
		      db->name,
		      prof->name);
      return DB_ERROR;
    }
    ci_debug_printf(5, "srv_url_check: Going to check the db %s for %s request\n", db->name, ACTION_STR(adb->pass));

    if (db->lookup_db(db, info, match_info, adb->subcats)) {
	ci_debug_printf(5, "srv_url_check: The db :%s matches! \n", db->name);
        match_info->action = adb->pass;
        if(match_info->action != DB_MATCH) {/*if it is DB_MATCH just continue checking*/
            strncpy(match_info->action_db, db->name, _DB_NAME_SIZE);
            match_info->action_db[_DB_NAME_SIZE - 1] = '\0';
            return match_info->action;
        }
    }
    adb=adb->next;
  }
  if(match_info->action < 0)
      match_info->action = DB_PASS;

  return DB_PASS;
}

/*Should be moved to a utility library*/
static void str_trim(char *str)
{
    char *s, *e;

    if (!str)
        return;

    s = str;
    e = NULL;
    while (*s == ' ' && s != '\0'){
        e = s;
        while (*e != '\0'){
            *e = *(e+1);
            e++;
        }
    }

    /*if (e) e--;  else */
    e = str+strlen(str);
    while(*(--e) == ' ' && e >= str) *e = '\0';
}

static char *parse_argument(const char *arg, ci_ptr_vector_t **params)
{
    struct subcats_data *sdata;
    char *s, *name;
    size_t len, k;
    if (!params)
        return strdup(arg);

    *params = NULL;
    name = strdup(arg);
    if ((s = index(name, '{')) != NULL) {
        *s = '\0';
        s++;
        while((len = strcspn(s, ",}")) != 0) {
             s[len] = '\0';
             str_trim(s);
             if (strlen(s) != 0) {
                 if (*params == NULL)
                     *params = ci_ptr_vector_create(1024);
                 
                 sdata = malloc(sizeof(struct subcats_data));
                 if (!sdata) {
                     free(name);
                     return NULL;
                 }

                 /*Check if there is the operator '>' or '<'*/
                 k = strcspn(s, "<>");
                 if (k != 0 && (s[k] == '>' || s[k] == '<')) {
                     sdata->op = (s[k] == '>' ? SBC_GREATER : SBC_LESS);
                     s[k] = '\0';
                     sdata->score = strtol(s+k+1, NULL, 10);
                     if (sdata->score <=0 ) {
                         ci_debug_printf(5, "srv_url_check: Parse error: cat: %s, op: %d, score: %d (in %s)\n", 
                                         s, sdata->op, sdata->score, s+k+1);
                         free(sdata);
                         free(name);
                         return NULL;
                     }
                 }
                 else {
                     sdata->op = 0;
                     sdata->score = 0;
                 }
                 sdata->str = strdup(s); 
                 (void)ci_ptr_vector_add(*params, sdata);
                 ci_debug_printf(5, "{%s%c%d}", sdata->str,
                                 (sdata->op <= SBC_EQ? '=': (sdata->op == SBC_GREATER ? '>' :'<')),
                                 sdata->score
                     );
             }
             s += len+1;
        }
    }
    return name;
}

int cfg_profile(const char *directive, const char **argv, void *setdata)
{
  int i,type=0;
  struct profile *prof;
  struct lookup_db *db;
  ci_ptr_vector_t *cats;
  char *db_name;

  if(!argv[0] || !argv[1] || !argv[2])
    return 0;
  
  prof=profile_check_add(argv[0]);

  if(strcasecmp(argv[1],"pass")==0)
    type = DB_PASS;
  else if(strcasecmp(argv[1],"block")==0)
    type = DB_BLOCK;
  else if(strcasecmp(argv[1],"match")==0)
    type = DB_MATCH;
  else {
    ci_debug_printf(1, "srv_url_check: Configuration error, expecting pass/block got %s\n", argv[1]);
    return 0;
  }

  ci_debug_printf(2, "srv_url_check: Add dbs to profile %s: ", argv[0]);

  for(i=2; argv[i] != NULL; i++) {
    cats = NULL;
    db_name = parse_argument(argv[i], &cats);
    if (!db_name) {
        ci_debug_printf(1, "srv_url_check: Configuration error or error allocation memory: %s ... %s\n", argv[0], argv[i]);
        return 0;
    }
    db=search_lookup_db(db_name);
    if(!db) {
      ci_debug_printf(1,"srv_url_check: WARNING the lookup db %s does not exists!\n", db_name);
    }
    else {
      ci_debug_printf(2,"%s ",db_name);
      profile_add_db(prof, db, type, cats);
    }
    free(db_name);
    db_name = NULL;
  }
  ci_debug_printf(2,"\n");
  return 1;
}

int cfg_profile_access(const char *directive, const char **argv, void *setdata)
{
   struct profile *prof;
   ci_access_entry_t *access_entry;
   int argc, error;
   const char *acl_spec_name;

   if(!argv[0] || !argv[1])
    return 0;

   if (!(prof = profile_search(argv[0]))) {
       ci_debug_printf(1, "srv_url_check: Error: Unknown profile %s!", argv[0]);
       return 0;
   }
    
   if ((access_entry = ci_access_entry_new(&(prof->access_list), 
					   CI_ACCESS_ALLOW))  == NULL) {
         ci_debug_printf(1, "srv_url_check: Error creating access list for cfg profiles!\n");
         return 0;
     }
   
   error = 0;
   for (argc = 1; argv[argc]!= NULL; argc++) {
       acl_spec_name = argv[argc];
          /*TODO: check return type.....*/
          if (!ci_access_entry_add_acl_by_name(access_entry, acl_spec_name)) {
	      ci_debug_printf(1,"srv_url_check: Error adding acl spec: %s in profile %s."
			        " Probably does not exist!\n", 
			      acl_spec_name, prof->name);
              error = 1;
          }
          else
	    ci_debug_printf(2,"\tAdding acl spec: %s in profile %s\n", acl_spec_name, prof->name);
     }

     if (error)
         return 0;

     return 1;
}

/*****************************************************************/
/* SguidGuard Databases                                          */

#if defined(HAVE_BDB)
void *sg_load_db(struct lookup_db *db, const char *path)
{
  sg_db_t *sg_db;
  sg_db = sg_init_db( db->name, path, 0);
  return (db->db_data = (void *)sg_db);
}

int sg_lookup_db(struct lookup_db *ldb, struct http_info *http_info, struct match_info *match_info, ci_ptr_vector_t *subcats)
{
  sg_db_t *sg_db = (sg_db_t *)ldb->db_data;
  if (!sg_db) {
       ci_debug_printf(1, "srv_url_check: sg_db %s is not open? \n", ldb->name);
       return 0;
  }
  ci_debug_printf(5, "srv_url_check: sg_db: checking domain %s \n", http_info->site);
  if( sg_domain_exists(sg_db, http_info->site) ) {
      match_info_append_db(match_info,  sg_db->domains_db_name, NULL);
    return 1;
  }
  ci_debug_printf(5, "srv_url_check: sg_db: checking url %s \n", http_info->url);
  if (sg_url_exists(sg_db,http_info->url)) {
      match_info_append_db(match_info, sg_db->urls_db_name, NULL);
    match_info->match_length = strlen(http_info->url);
    return 1;
  }

  return 0;
}

void sg_release_db(struct lookup_db *ldb)
{
  sg_db_t *sg_db = (sg_db_t *)ldb->db_data;
  if (!sg_db) {
       ci_debug_printf(9, "srv_url_check: sg_release_db: sg_db is not open? \n");
       return;
  }
  sg_close_db(sg_db);
  ldb->db_data = NULL;
}

struct command_sg_db_data {
   char path[CI_MAX_PATH];
   struct lookup_db *ldb;
};

void command_open_sg_db(const char *name, int type, void *data)
{
  struct command_sg_db_data *sg_data;
  struct lookup_db *ldb;
  sg_db_t *sg_db;
  sg_data = (struct command_sg_db_data *)data;
  ldb = (struct lookup_db *)sg_data->ldb;
  sg_db = sg_init_db(ldb->name, sg_data->path, 0);
  ldb->db_data = (void *)sg_db;

  free(sg_data);
}


int cfg_load_sg_db(const char *directive, const char **argv, void *setdata) 
{
  struct lookup_db *ldb;
  struct command_sg_db_data *db_data;

  if (argv == NULL || argv[0] == NULL || argv[1] == NULL) {
    ci_debug_printf(1, "srv_url_check: Missing arguments in directive:%s\n", directive);
    return 0;
  }

  ldb = new_lookup_db(argv[0], 
		      DB_SG, 
		      CHECK_HOST|CHECK_URL,
		      sg_load_db,
		      sg_lookup_db,
		      sg_release_db);


  if(ldb) {
    db_data = malloc(sizeof(struct command_sg_db_data));
    if (!db_data)
      return 0;
    strncpy(db_data->path, argv[1], CI_MAX_PATH);
    db_data->path[CI_MAX_PATH-1] = '\0';
    db_data->ldb = ldb;
    register_command_extend("open_sg_db", CHILD_START_CMD, db_data,
			    command_open_sg_db);
    return add_lookup_db(ldb);
  }
  
  return 0;
}
#endif

/*****************************************************************/
/* c-icap lookup table databases                                 */


void *lt_load_db(struct lookup_db *db, const char *path)
{
  struct ci_lookup_table *lt_db;
  lt_db = ci_lookup_table_create(path);
  if(lt_db && !ci_lookup_table_open(lt_db)) {
    ci_lookup_table_destroy(lt_db);
    lt_db = NULL;
  }
  return (db->db_data = (void *)lt_db);
}

char *find_last(char *s,char *e,const char accept)
{
  char *p;
  p = e;
  while(p >= s) {
      if(accept == *p)
	  return p;
      p--;
  }
  return NULL;
}

typedef struct subcats_data cmp_data;
static int cmp_fn(cmp_data *cmp, const struct subcats_data *cfg)
{
    cmp->op = 0;
    if (cfg->str && cmp->str && strcmp(cmp->str, cfg->str) ==0) {
        switch(cfg->op) {
        case SBC_LESS:
            if (cmp->score < cfg->score)
                cmp->op = 1; /*matches*/
            break;
        case SBC_GREATER:
            if (cmp->score > cfg->score)
                cmp->op = 1; /*matches*/
            break;
        default:
            cmp->op = 1;
            break;
        }
        if (cfg->op > 0) {
            ci_debug_printf(5, "srv_url_check: Matches sub category: %s, requires score: %d%c%d %s matches\n", 
                            cmp->str, cmp->score, cfg->op == SBC_LESS? '<' : '>', cfg->score, cmp->op? "" : "not");
        } else {
            ci_debug_printf(5, "srv_url_check: Matches sub category: %s\n", cmp->str);
        }
        return cmp->op;
    }
    return 0;
}

static const char *check_sub_categories(const char *key, char **vals, ci_ptr_vector_t *subcats, char *str_cats, size_t str_cats_size)
{
    int i, len;
    char buf[1024], *e;
    cmp_data cmp;
    if (!subcats)
        return key;

    /*if sub-categories defined but no vals returned, do not match */
    if (!vals)
        return NULL;
    
    for (i = 0; vals[i] != NULL; i++) {
        if ((e = strchr(vals[i], ':')) != NULL) {
            /*We found a value in the form "value:score".
              Split score from string, to pass it for check with subcategories.
            */
            cmp.score = strtol(e+1, NULL, 10);
            if (cmp.score <= 0) {
                cmp.str = vals[i];
                cmp.score = 0;
            } else {
                /* a valid score found */
                len = e - vals[i];
                strncpy(buf, vals[i], len);
                buf[len] = '\0';
                cmp.str = buf;
            }
        } else {
            cmp.str = vals[i];
            cmp.score = 0;
        }

        cmp.op = 0;
        ci_ptr_vector_iterate(subcats, &cmp, (int (*)(void *, const void *))cmp_fn);
        if (cmp.op != 0) {
            strncpy(str_cats, cmp.str, str_cats_size);
            str_cats[str_cats_size-1] = '\0';
            return key;
        }
    }
    
    return NULL;
}

int lt_lookup_db(struct lookup_db *ldb, struct http_info *http_info, struct match_info *match_info, ci_ptr_vector_t *subcats)
{
  char str_subcats[1024];
  char **vals=NULL;
  const char *ret = NULL;
  char *s, *snext, *e, *end, store;
  int len, full_url =0;
  struct ci_lookup_table *lt_db = (struct ci_lookup_table *)ldb->db_data;
  switch(ldb->check) {
  case CHECK_HOST:
      ret = ci_lookup_table_search(lt_db, http_info->site, &vals);
      if (ret) {
          if (subcats)
              ret = check_sub_categories(ret, vals, subcats, str_subcats, sizeof(str_subcats));
          if (vals) {
              ci_lookup_table_release_result(lt_db, (void **)vals);
              vals = NULL;
          }
      }
      break;
  case CHECK_DOMAIN:
      s = http_info->site;
      s--;   /* :-) */
      do {
	  s++;
	  ci_debug_printf(5, "srv_url_check: Checking  domain %s ....\n", s);
	  ret = ci_lookup_table_search(lt_db, s, &vals);
          if (ret) {
              if (subcats)
                  ret = check_sub_categories(ret, vals, subcats, str_subcats, sizeof(str_subcats));
              if (vals) {
                  ci_lookup_table_release_result(lt_db, (void **)vals);
                  vals = NULL;
              }
          }
      } while (!ret && (s=strchr(s, '.')));
      break;
  case CHECK_FULL_URL:
      full_url = 1;
  case CHECK_URL:
      /*for www.site.com/to/path/page.html need to test:

	www.site.com/to/path/page.html
	www.site.com/to/path/
	www.site.com/to/
	www.site.com/

	site.com/to/path/page.html
	site.com/to/path/
	site.com/to/
	site.com/

	com/to/path/page.html
	com/to/path/
	com/to/
	com/
       */
      s = http_info->url;
      if (!full_url && http_info->args)
	  end = http_info->args;
      else {
	  len = strlen(http_info->url);
	  end = s+len;
      }
      s--;
      do {
	  s++;
	  e = end; /*Point to the end of string*/
	  snext = strpbrk(s, "./");
	  if(!snext || *snext == '/') /*Do not search the top level domains*/
	      break;
	  do {
	      store = *e;
	      *e = '\0'; /*cut the string exactly here (the http_info->url must not change!) */
	      ci_debug_printf(9,"srv_url_check: Going to check url: %s\n", s);
	      ret = ci_lookup_table_search(lt_db, s, &vals);
              if (ret) {
                  if (subcats)
                      ret = check_sub_categories(ret, vals, subcats, str_subcats, sizeof(str_subcats));
                  if (vals) {
                      ci_lookup_table_release_result(lt_db, (void **)vals);
                      vals = NULL;
                  }
                  match_info->match_length = strlen(s);
              }

	      *e = store; /*... and restore string to its previous state :-), 
			    the http_info->url must not change */
	      if (full_url && e > http_info->args)
		  e = http_info->args;
	      else
		  e = find_last(s, e-1, '/' );
	  } while(!ret && e);
      } while (!ret && (s = snext));
      

      break;
  case CHECK_SIMPLE_URL:
      s = http_info->url;
      ci_debug_printf(5, "srv_url_check: Checking  URL %s ....\n", s);
      ret = ci_lookup_table_search(lt_db, s, &vals);
      if (ret) {
          if (subcats)
              ret = check_sub_categories(ret, vals, subcats, str_subcats, sizeof(str_subcats));
          if (vals) {
              ci_lookup_table_release_result(lt_db, (void **)vals);
              vals = NULL;
          }
      }
      break;

  case CHECK_SRV_IP:
      break;
  case CHECK_SRV_NET:
      break;
  default:
      /*nothing*/
      break;
  }
  
  if (ret) {
      match_info_append_db(match_info, ldb->name, (subcats!= NULL ? str_subcats : NULL));
      return 1;
  }

  return 0;
}

void lt_release_db(struct lookup_db *ldb)
{
  struct ci_lookup_table *lt_db = (struct ci_lookup_table *)ldb->db_data;
  ci_debug_printf(5, "srv_url_check: Destroy lookup table %s\n", lt_db->path);
  ci_lookup_table_destroy(lt_db);
  ldb->db_data = NULL;
}


int cfg_load_lt_db(const char *directive, const char **argv, void *setdata) 
{
  struct lookup_db *ldb;
  unsigned int check;
  if (argv == NULL || argv[0] == NULL || argv[1] == NULL || argv[2] == NULL) {
    ci_debug_printf(1, "srv_url_check: Missing arguments in directive:%s\n", directive);
    return 0;
  }

  if(strcmp(argv[1],"host")==0)
    check = CHECK_HOST;
  else if(strcmp(argv[1],"url")==0)
    check = CHECK_URL;
  else if(strcmp(argv[1],"full_url")==0)
      check = CHECK_FULL_URL;
  else if(strcmp(argv[1],"url_simple_check")==0)
      check = CHECK_SIMPLE_URL;
  else if(strcmp(argv[1],"domain")==0)
    check = CHECK_DOMAIN;
  /* Not yet implemented
  else if(strcmp(argv[1],"server_ip")==0)
      check = CHECK_SRV_IP;
  else if(strcmp(argv[1],"server_net")==0)
      check = CHECK_SRV_NET;
  */
  else {
    ci_debug_printf(1, "srv_url_check: Wrong argument %s for directive %s\n", 
		    argv[1], directive);
    return 0;
  }
  
  ldb = new_lookup_db(argv[0],
		      DB_LOOKUP, 
		      check,
		      lt_load_db,
		      lt_lookup_db,
		      lt_release_db);
  if(ldb) {
    if(!ldb->load_db(ldb, argv[2])) {
      free(ldb);
      return 0;
    }
    return add_lookup_db(ldb);
  }
  
  return 0;
}

/**********************************************************************/
/* Other */
int all_lookup_db(struct lookup_db *ldb, struct http_info *http_info, struct match_info *match_info, ci_ptr_vector_t *subcats)
{
    match_info_append_db(match_info, ldb->name, NULL);
  return 1;
}


/*****************************/
/* Formating table functions */
int fmt_srv_urlcheck_http_url(ci_request_t *req, char *buf, int len, const char *param)
{
    struct url_check_data *uc = ci_service_data(req);  
    /*Do notwrite more than 512 bytes*/
    return snprintf(buf, (len < 512? len:512), "%s://%s", protos[uc->httpinf.proto], uc->httpinf.url);
}

int fmt_srv_urlcheck_host(ci_request_t *req, char *buf, int len, const char *param)
{
    struct url_check_data *uc = ci_service_data(req);  
    return snprintf(buf, len, "%s", uc->httpinf.host);
}

int fmt_srv_urlcheck_matched_dbs(ci_request_t *req, char *buf, int len, const char *param)
{
    struct url_check_data *uc = ci_service_data(req);  
    return snprintf(buf, len, "%s", uc->match_info.matched_dbs);
}

int fmt_srv_urlcheck_blocked_db(ci_request_t *req, char *buf, int len, const char *param)
{
    struct url_check_data *uc = ci_service_data(req);  
    if (uc->match_info.action < 0)
        return 0;
    if (uc->match_info.last_subcat[0] != '\0')
        return snprintf(buf, len, "%s{%s}", uc->match_info.action_db, uc->match_info.last_subcat);
    else
        return snprintf(buf, len, "%s", uc->match_info.action_db);
}

