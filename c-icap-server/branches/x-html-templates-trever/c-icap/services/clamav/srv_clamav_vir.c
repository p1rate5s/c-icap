/*
 *  Copyright (C) 2004 Christos Tsantilas
 *  Copyright (C) 2007 Trever L. Adams
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
#include "cfg_param.h"
#include <clamav.h>
#include <time.h>
#include <errno.h>
#include "srv_clamav.h"
#include "htmlTemplate.h"
#include <assert.h>

extern char *VIR_SAVE_DIR;
extern char *VIR_HTTP_SERVER;
extern int VIR_UPDATE_TIME;

char *srvclamav_compute_name(request_t * req);
char *construct_url(char *strformat, char *filename, char *user);

const char *clamav_mod_desc = "Clamav/Antivirus service";

ci_membuf_t *AVtemplateConvert(char token, const request_t * req);

void init_vir_mode_data(request_t * req, av_req_data_t * data)
{
     ci_respmod_reset_headers(req);
     ci_respmod_add_header(req, "HTTP/1.1 200 OK");
     ci_respmod_add_header(req, "Server: C-ICAP/srvclamav");
     ci_respmod_add_header(req, "Connection: close");
     ci_respmod_add_header(req, "Content-Type: text/html");
     ci_respmod_add_header(req, "Content-Language: en");

     data->last_update = time(NULL);
     data->requested_filename = NULL;
     data->page_sent = 0;
     data->html_started = 0;


     if ((data->requested_filename = srvclamav_compute_name(req)) != NULL) {
          if (NULL ==
              (data->body =
               ci_simple_file_named_new(VIR_SAVE_DIR,
                                        data->requested_filename)))
               data->body = ci_simple_file_named_new(VIR_SAVE_DIR, NULL);
     }
     else {
          data->body = ci_simple_file_named_new(VIR_SAVE_DIR, NULL);
     }

     ci_req_unlock_data(req);
}


int send_vir_mode_page(av_req_data_t * data, char *buf, int len,
                       request_t * req)
{
     int bytes;
     ci_membuf_t *buffer;

     if (data->html_started == 0)       // output HTML header
     {
          data->html_started = 1;
          buffer =
              templateBuildContent(req, "AVSCAN", "PROGRESS_BEGIN",
                                AVtemplateConvert);
          bytes = ci_membuf_read(buffer, buf, len);
          ci_membuf_free(buffer);
          return bytes;
     }

     if (ci_simple_file_haseof(((av_req_data_t *) data)->body)
         && data->virus_check_done) {
          if (data->error_page)
               return ci_membuf_read(data->error_page, buf, len);


          if (data->page_sent) {
               ci_debug_printf(10, "viralator:EOF received %d....\n", len);
               return CI_EOF;
          }
          buffer =
              templateBuildContent(req, "AVSCAN", "PROGRESS_SAFE_FINISHED",
                                AVtemplateConvert);
          bytes = ci_membuf_read(buffer, buf, len);
          ci_membuf_free(buffer);
          data->page_sent = 1;
          return bytes;
     }

     if ((((av_req_data_t *) data)->last_update + VIR_UPDATE_TIME) > time(NULL)) {
          return 0;
     }
     time(&(((av_req_data_t *) data)->last_update));
     ci_debug_printf(10,
                     "Downloaded %" PRINTF_OFF_T " bytes from %" PRINTF_OFF_T
                     " of data\n",
                     ci_simple_file_size(data->body), data->expected_size);
     buffer =
         templateBuildContent(req, "AVSCAN", "PROGRESS_INCREMENTAL",
                           AVtemplateConvert);
     bytes = ci_membuf_read(buffer, buf, len);
     ci_membuf_free(buffer);
     return bytes;
}

void endof_data_vir_mode(av_req_data_t * data, request_t * req)
{
     ci_membuf_t *error_page;

     if (data->virus_name && data->body) {
          error_page =
              templateBuildContent(req, "AVSCAN", "PROGRESS_UNSAFE_FINISHED",
                                AVtemplateConvert);
          ((av_req_data_t *) data)->error_page = error_page;
          fchmod(data->body->fd, 0);
     }
     else if (data->body) {
          fchmod(data->body->fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
     }
}


char *srvclamav_compute_name(request_t * req)
{
     char *str, *filename, *last_delim;
     int namelen;
     if ((filename = ci_respmod_get_header(req, "Location")) != NULL) {
          if ((str = strrchr(filename, '/'))) {
               filename = str + 1;
               if ((str = strrchr(filename, '?')))
                    filename = str + 1;
          }
          if (filename != '\0')
               return strdup(filename);
          else
               return NULL;
     }
     /*if we are here we are going to compute name from request headers if exists.... */
     if (!(str = ci_http_request(req)))
          return NULL;

     if (strncmp(str, "GET", 3) != 0)
          return NULL;

     if (!(str = strchr(str, ' ')))
          return NULL;

     str = str + 1;
     filename = str;
     last_delim = NULL;
     while (*str != '\0' && *str != ' ') {
          if (*str == '/' || *str == '?')
               last_delim = str;
          str += 1;
     }
     if (last_delim != NULL)
          filename = last_delim + 1;

     if (filename == str)       /*for example the requested position is http:// */
          return NULL;

     last_delim = str;
     namelen = last_delim - filename;
     if (namelen >= CI_FILENAME_LEN)
          namelen = CI_FILENAME_LEN - 1;

     str = malloc(namelen * sizeof(char) + 1);
     strncpy(str, filename, namelen);
     str[namelen] = '\0';
     return str;
}


char *construct_url(char *strformat, char *filename, char *user)
{
     char *url, *str;
     int i, format_len, filename_len = 0, user_len = 0;
     if (!strformat)
          return NULL;

     format_len = strlen(strformat);
     if (filename)
          filename_len = strlen(filename);
     if (user)
          user_len = strlen(user);

     url = malloc(format_len + filename_len + user_len + 2);
     str = url;

     for (i = 0; i < format_len; i++) {
          if (strformat[i] == '%') {
               switch (strformat[i + 1]) {
               case 'f':
                    if (filename)
                         memcpy(str, filename, filename_len);
                    str += filename_len;
                    i++;
                    break;
               case 'u':
                    if (user)
                         memcpy(str, user, user_len);
                    str += user_len;
                    i++;
                    break;
               default:
                    *str = strformat[i];
                    str += 1;
                    break;
               }
          }
          else {
               *str = strformat[i];
               str += 1;
          }
     }
     *str = '\0';
     return url;
}


ci_membuf_t *AVtemplateConvert(char token, const request_t * req)
{
     ci_membuf_t *mb = ci_membuf_new_sized(200);
     const int buf_size = 100;
     char buf[buf_size];
     av_req_data_t *data = ci_service_data(req);
     char *url = NULL;
     char *filename = NULL, *str = NULL;

     assert(mb != NULL);
     assert(data != NULL);

     ci_debug_printf(9, "AVtemplateConver: Converting a token to value.\n");

     switch (token) {

     case 'r':                 // received data
          snprintf(buf, buf_size, "%" PRINTF_OFF_T "",
                   ci_simple_file_size(data->body));
          ci_membuf_write(mb, buf, strlen(buf), 1);
          break;

     case 'e':                 // expected size
          snprintf(buf, buf_size, "%" PRINTF_OFF_T "", data->expected_size);
          ci_membuf_write(mb, buf, strlen(buf), 1);
          break;

     case 'u':                 // url of download script
          url =
              construct_url(VIR_HTTP_SERVER, data->requested_filename,
                            req->user);
          ci_membuf_write(mb, url, strlen(url), 1);
          break;

     case 'd':                 // download file name
          filename = data->body->filename;
          if ((str = strrchr(filename, '/')) != NULL)
               filename = str + 1;
          ci_membuf_write(mb, filename, strlen(filename), 1);
          break;

     case 'f':                 // display file name
          filename = (data->requested_filename ? data->
                      requested_filename : data->body->filename);
          ci_membuf_write(mb, filename, strlen(filename), 1);
          break;

     case 'p':                 // path and file where the data is saved
          filename = data->body->filename;
          ci_membuf_write(mb, filename, strlen(filename), 1);
          break;

     case 'v':                 // virus name
          ci_membuf_write(mb, data->virus_name, strlen(data->virus_name), 1);
          break;

     case 'm':                 // module name
          ci_membuf_write(mb, clamav_mod_desc, strlen(clamav_mod_desc), 1);
          break;

     default:
          ci_membuf_write(mb, &token, 1, 1);
          break;
     }

     ci_debug_printf(4, "templateConvert: %c --> '%.*s'\n", token,
                     ci_simple_file_size(mb), mb->buf);

     return mb;
}
