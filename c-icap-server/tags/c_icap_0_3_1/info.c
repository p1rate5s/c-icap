/*
 *  Copyright (C) 2004-2009 Christos Tsantilas
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA.
 */

#include "common.h"
#include "c-icap.h"
#include "service.h"
#include "header.h"
#include "body.h"
#include "simple_api.h"
#include "stats.h"
#include "proc_threads_queues.h"
#include "debug.h"

int info_init_service(ci_service_xdata_t * srv_xdata,
                      struct ci_server_conf *server_conf);
int info_check_preview_handler(char *preview_data, int preview_data_len,
                               ci_request_t *);
int info_end_of_data_handler(ci_request_t * req);
void *info_init_request_data(ci_request_t * req);
void info_close_service();
void info_release_request_data(void *data);
int info_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof,
            ci_request_t * req);

CI_DECLARE_MOD_DATA ci_service_module_t info_service = {
     "info",                         /* mod_name, The module name */
     "C-icap run-time information",            /* mod_short_descr,  Module short description */
     ICAP_REQMOD,                    /* mod_type, The service type is request modification */
     info_init_service,              /* mod_init_service. Service initialization */
     NULL,                           /* post_init_service. Service initialization after c-icap 
					configured. Not used here */
     info_close_service,           /* mod_close_service. Called when service shutdowns. */
     info_init_request_data,         /* mod_init_request_data */
     info_release_request_data,      /* mod_release_request_data */
     info_check_preview_handler,     /* mod_check_preview_handler */
     info_end_of_data_handler,       /* mod_end_of_data_handler */
     info_io,                        /* mod_service_io */
     NULL,
     NULL
};

struct info_req_data {
     ci_membuf_t *body;
     int txt_mode;
     int childs;
     int *child_pids;
     int free_servers;
     int used_servers;
     unsigned int closing_childs;
     int *closing_child_pids;
     unsigned int started_childs;
     unsigned int closed_childs;
     unsigned int crashed_childs;
     struct stat_memblock *collect_stats;
};

extern struct childs_queue *childs_queue;
extern ci_proc_mutex_t accept_mutex;

int build_statistics(struct info_req_data *info_data);

int info_init_service(ci_service_xdata_t * srv_xdata,
                      struct ci_server_conf *server_conf)
{
     ci_service_set_xopts(srv_xdata,  CI_XAUTHENTICATEDUSER|CI_XAUTHENTICATEDGROUPS);
     return CI_OK;
}

void info_close_service() 
{
     ci_debug_printf(5,"Service %s shutdown!\n", info_service.mod_name);
}

void *info_init_request_data(ci_request_t * req)
{
     struct info_req_data *info_data;

     info_data = malloc(sizeof(struct info_req_data));

     info_data->body = ci_membuf_new(4096);
     info_data->childs = 0;
     info_data->child_pids = malloc(childs_queue->size * sizeof(int));
     info_data->free_servers = 0;
     info_data->used_servers = 0;
     info_data->closing_childs = 0;
     info_data->closing_child_pids = malloc(childs_queue->size * sizeof(int));
     info_data->started_childs = 0;
     info_data->closed_childs = 0;
     info_data->crashed_childs = 0;
     info_data->txt_mode = 0;
     if (req->args) {
          if (strstr(req->args, "view=text"))
              info_data->txt_mode = 1;
     }
     
     info_data->collect_stats = malloc(ci_stat_memblock_size());
     info_data->collect_stats->sig = 0xFAFA;
     stat_memblock_fix(info_data->collect_stats);
     ci_stat_memblock_reset(info_data->collect_stats);

     return info_data;
}

void info_release_request_data(void *data)
{
    struct info_req_data *info_data = (struct info_req_data *)data;
    
    if (info_data->body)
	ci_membuf_free(info_data->body);

    if (info_data->collect_stats)
        free(info_data->collect_stats);

    free(info_data);
}


int info_check_preview_handler(char *preview_data, int preview_data_len,
                               ci_request_t * req)
{
     struct info_req_data *info_data = ci_service_data(req);

     if (ci_req_hasbody(req))
         return CI_MOD_ALLOW204;
     
     ci_req_unlock_data(req);
    
     ci_http_response_create(req, 1, 1); /*Build the responce headers */

     ci_http_response_add_header(req, "HTTP/1.0 200 OK");
     ci_http_response_add_header(req, "Server: C-ICAP");
     ci_http_response_add_header(req, "Content-Type: text/html");
     ci_http_response_add_header(req, "Content-Language: en");
     ci_http_response_add_header(req, "Connection: close");
     if (info_data->body) {
         build_statistics (info_data);
     }
     
     return CI_MOD_CONTINUE;
}

int info_end_of_data_handler(ci_request_t * req)
{
  return CI_MOD_DONE;
}

int info_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof,
            ci_request_t * req)
{
     int ret;
     struct info_req_data *info_data = ci_service_data(req);
     ret = CI_OK;

     if (wbuf && wlen) {
         if (info_data->body)	 
             *wlen = ci_membuf_read(info_data->body, wbuf, *wlen);
	 else
	     *wlen = CI_EOF;
     }

     return ret;
}

/*Statistisc implementation .....*/

void fill_queue_statistics(struct childs_queue *q, struct info_req_data *info_data)
{

    int i;
    int requests = 0;
    struct stat_memblock *stats, copy_stats;
    struct server_statistics *srv_stats;
     if (!q->childs)
          return;

     /*Merge childs data*/
     for (i = 0; i < q->size; i++) {
          if (q->childs[i].pid != 0 && q->childs[i].to_be_killed == 0) {
               if (info_data->child_pids)
                   info_data->child_pids[info_data->childs] = q->childs[i].pid;
               info_data->childs++;
               info_data->free_servers += q->childs[i].freeservers;
               info_data->used_servers += q->childs[i].usedservers;
               requests += q->childs[i].requests;

	       stats = q->stats_area + i * (q->stats_block_size);
	       copy_stats.counters64_size = stats->counters64_size;
	       copy_stats.counterskbs_size = stats->counterskbs_size;
	       copy_stats.counters64 = (void *)stats + _CI_ALIGN(sizeof(struct stat_memblock));
	       copy_stats.counterskbs = (void *)stats + _CI_ALIGN(sizeof(struct stat_memblock)) 
		 + stats->counters64_size*sizeof(uint64_t);

	       ci_stat_memblock_merge(info_data->collect_stats, &copy_stats);
          }
          else if (q->childs[i].pid != 0 && q->childs[i].to_be_killed) {
               if (info_data->closing_child_pids)
                   info_data->closing_child_pids[info_data->closing_childs] = q->childs[i].pid;
               info_data->closing_childs++;
          }
     }
     /*Merge history data*/
     stats = q->stats_area + q->size * q->stats_block_size;
     copy_stats.counters64_size = stats->counters64_size;
     copy_stats.counterskbs_size = stats->counterskbs_size;
     copy_stats.counters64 = (void *)stats + _CI_ALIGN(sizeof(struct stat_memblock));
     copy_stats.counterskbs = (void *)stats + _CI_ALIGN(sizeof(struct stat_memblock)) 
       + stats->counters64_size*sizeof(uint64_t);

     ci_stat_memblock_merge(info_data->collect_stats, &copy_stats);     

     srv_stats = 
         (struct server_statistics *)(q->stats_area + q->size * q->stats_block_size + q->stats_block_size);
     /*Compute server statistics*/
     info_data->started_childs = srv_stats->started_childs;
     info_data->closed_childs = srv_stats->closed_childs;
     info_data->crashed_childs = srv_stats->crashed_childs;
}

struct stats_tmpl {
   char *gen_template;
   char *statsHeader;
   char *statsEnd;
   char *childsHeader;
   char *childs_tmpl;
   char *childsEnd;
   char *closingChildsHeader;
   char *semaphores_tmpl;
   char *sharedMem_tmpl;
   char *statline_tmpl_int;
   char *statline_tmpl_kbs;
};

struct stats_tmpl txt_tmpl = {
  "Running Servers Statistics\n===========================\n"\
  "Childs number: %d\nFree Servers: %d\nUsed Servers: %d\n"\
  "Started Processes: %u\nClosed Processes: %u\nCrashed Processes: %u\n"\
  "Closing Processes: %u"\
  "\n\n",
  "\n%s Statistics\n==================\n",
  "",
  "Child pids:",
  " %d",
  "\n",
  "Closing childs pids:",
  "%s semaphores in use: %s\n",
  "%s shared mem in use: %s\n",
  "%s : %lld\n",
  "%s : %lld Kbs %d bytes\n"
};

struct stats_tmpl html_tmpl = {
  "<H1>Running Servers Statistics</H1>\n"\
  "<TABLE>"                                     \
  "<TR><TH>Childs number:</TH><TD> %d<TD>"                     \
  "<TR><TH>Free Servers:</TH><TD> %d<TD>"                      \
  "<TR><TH>Used Servers:</TH><TD> %d<TD>"                      \
  "<TR><TH>Started Processes :</TH><TD> %u<TD>"                \
  "<TR><TH>Closed Processes: </TH><TD>%u<TD>"                  \
  "<TR><TH>Crashed Processes: </TH><TD>%u<TD>"                 \
  "<TR><TH>Closing Processes: </TH><TD>%u<TD>"                 \
  "</TABLE>\n",
  "<H1>%s Statistics</H1>\n<TABLE>",
  "</TABLE>",
  "<TABLE> <TR><TH>Child pids:</TH>",
  "<TD> %d</TD>",
  "</TR></TABLE>\n",
  "<TABLE> <TR><TH>Closing childs pids:</TH>",
  "<TR><TH>%s semaphores in use:</TH><TD>%s</TD>\n",
  "<TR><TH>%s shared mem in use:</TH><TD>%s</TD>\n",
  "<TR><TH>%s:</TH><TD>  %lld</TD>\n",
  "<TR><TH>%s:</TH><TD>  %lld Kbs %d bytes</TD>\n"
};

#define LOCAL_BUF_SIZE 1024
int build_statistics(struct info_req_data *info_data)
{    
     char buf[LOCAL_BUF_SIZE];
     char buf2[LOCAL_BUF_SIZE];
     int sz, gid, k;
     char *stat_group;
     struct stats_tmpl *tmpl;

     if (info_data->txt_mode)
          tmpl = &txt_tmpl;
     else
          tmpl = &html_tmpl;

     if (!info_data->body)
       return 0;
	    
     fill_queue_statistics(childs_queue, info_data);

     sz = snprintf(buf, LOCAL_BUF_SIZE,tmpl->gen_template,
		   info_data->childs,
		   info_data->free_servers,
		   info_data->used_servers,
                   info_data->started_childs,
                   info_data->closed_childs,
                   info_data->crashed_childs,
                   info_data->closing_childs
         );

     if (sz > LOCAL_BUF_SIZE) 
         sz = LOCAL_BUF_SIZE;

     ci_membuf_write(info_data->body,buf, sz, 0);

     /*print childs pids ...*/
     ci_membuf_write(info_data->body, tmpl->childsHeader, strlen(tmpl->childsHeader), 0);
     for (k =0; k < info_data->childs; k++) {
          sz = snprintf(buf, LOCAL_BUF_SIZE, tmpl->childs_tmpl, info_data->child_pids[k]);
          if (sz > LOCAL_BUF_SIZE) 
              sz = LOCAL_BUF_SIZE;
          ci_membuf_write(info_data->body,buf, sz, 0);
     } 
     ci_membuf_write(info_data->body, tmpl->childsEnd, strlen(tmpl->childsEnd), 0);

     /*print closing childs pids ...*/
     ci_membuf_write(info_data->body, tmpl->closingChildsHeader, strlen(tmpl->closingChildsHeader), 0);
     for (k =0; k < info_data->closing_childs; k++) {
          sz = snprintf(buf, LOCAL_BUF_SIZE, tmpl->childs_tmpl, info_data->closing_child_pids[k]);
          if (sz > LOCAL_BUF_SIZE) 
              sz = LOCAL_BUF_SIZE;
          ci_membuf_write(info_data->body,buf, sz, 0);
     } 
     ci_membuf_write(info_data->body, tmpl->childsEnd, strlen(tmpl->childsEnd), 0);

     /*Print semaphores*/ /*Print shared mem info*/
#if defined(USE_SYSV_IPC_MUTEX)
     snprintf(buf2, LOCAL_BUF_SIZE, "%d %d", accept_mutex, childs_queue->queue_mtx);
     sz = snprintf(buf, LOCAL_BUF_SIZE, tmpl->semaphores_tmpl, "IPC", buf2);
#elif defined(USE_POSIX_SEMAPHORES)
     snprintf(buf2, LOCAL_BUF_SIZE, "%p %p", &accept_mutex, &childs_queue->queue_mtx);
     sz = snprintf(buf, LOCAL_BUF_SIZE, tmpl->semaphores_tmpl, "POSIX", buf2);
#elif defined(USE_POSIX_FILE_LOCK)
     snprintf(buf2, LOCAL_BUF_SIZE, "%s %s", accept_mutex.filename, &childs_queue->queue_mtx.filename);
     sz = snprintf(buf, LOCAL_BUF_SIZE, tmpl->semaphores_tmpl, "Lockfile", buf2);
#else
     sz = snprintf(buf, LOCAL_BUF_SIZE, tmpl->sharedMem_tmpl, "Unknown", "Unknown");
#endif
     ci_membuf_write(info_data->body,buf, sz, 0);

/*Print shared mem*/
#if defined(USE_SYSV_IPC)
     snprintf(buf2, LOCAL_BUF_SIZE, "%d %d kbs", childs_queue->shmid, (childs_queue->shared_mem_size/1024));
     sz = snprintf(buf, LOCAL_BUF_SIZE, tmpl->sharedMem_tmpl, "IPC", buf2);
#elif defined(USE_POSIX_MAPPED_FILES)
     snprintf(buf2, LOCAL_BUF_SIZE, "%p %d Kbs", childs_queue->shmid.mem, (childs_queue->shmid.size/1024));
     sz = snprintf(buf, LOCAL_BUF_SIZE, tmpl->sharedMem_tmpl, "MMAP", buf2);
#else
     sz = snprintf(buf, LOCAL_BUF_SIZE, tmpl->sharedMem_tmpl, "Unknown", "Unknown");
#endif
     ci_membuf_write(info_data->body,buf, sz, 0);


     for (gid = 0; gid < STAT_GROUPS.entries_num; gid++) {
          stat_group = STAT_GROUPS.groups[gid];

          sz = snprintf(buf, LOCAL_BUF_SIZE, tmpl->statsHeader, stat_group);
          if (sz > LOCAL_BUF_SIZE) 
              sz = LOCAL_BUF_SIZE;
          ci_membuf_write(info_data->body, buf, sz, 0);
	  for (k=0; k < info_data->collect_stats->counters64_size && k < STAT_INT64.entries_num; k++) {
	      if (gid == STAT_INT64.entries[k].gid) {
		  sz = snprintf(buf, LOCAL_BUF_SIZE, tmpl->statline_tmpl_int,
				STAT_INT64.entries[k].label, 
				info_data->collect_stats->counters64[k]);
                  if (sz > LOCAL_BUF_SIZE) 
                      sz = LOCAL_BUF_SIZE;
		  ci_membuf_write(info_data->body,buf, sz, 0);
	      }
	  }
	  
	  for (k=0; k < info_data->collect_stats->counterskbs_size && k < STAT_KBS.entries_num; k++) {
	       if (gid == STAT_KBS.entries[k].gid) {
		   sz = snprintf(buf, LOCAL_BUF_SIZE, tmpl->statline_tmpl_kbs,
				 STAT_KBS.entries[k].label, 
				 info_data->collect_stats->counterskbs[k]);
                   if (sz > LOCAL_BUF_SIZE) 
                       sz = LOCAL_BUF_SIZE;
		   ci_membuf_write(info_data->body,buf, sz, 0);
	       }
	  }
	  ci_membuf_write(info_data->body,tmpl->statsEnd, strlen(tmpl->statsEnd), 1);
     }
     
     return 1;
}

