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
#include "cfg_param.h"
#include <clamav.h>
#include <time.h>
#include <errno.h>
#include "srv_clamav.h"

extern char *VIR_SAVE_DIR;
extern char *VIR_HTTP_SERVER;
extern int VIR_UPDATE_TIME;


char *srvclamav_compute_name(request_t * req);
char *construct_url(char *strformat, char *filename, char *user);


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
     char *filename, *str;
     char *url;
     if (ci_simple_file_haseof(((av_req_data_t *) data)->body) && data->virus_check_done) {
          if (data->error_page)
               return ci_membuf_read(data->error_page, buf, len);


          if (data->page_sent) {
               ci_debug_printf(10, "viralator:EOF received %d....\n", len);
               return CI_EOF;
          }

          filename = ((av_req_data_t *) data)->body->filename;
          if ((str = strrchr(filename, '/')) != NULL)
               filename = str + 1;

          url =
              construct_url(VIR_HTTP_SERVER, data->requested_filename,
                            req->user);

          bytes =
              snprintf(buf, len,
                       "Download your file(size=%" PRINTF_OFF_T
                       ") from <a href=\"%s%s\">%s</a> <br>",
                       ci_simple_file_size(((av_req_data_t *) data)->body), url,
                       filename,
                       (data->requested_filename ? data->
                        requested_filename : ((av_req_data_t *) data)->body->
                        filename)
              );
          free(url);
          data->page_sent = 1;
          return bytes;
     }



     if ((((av_req_data_t *) data)->last_update + VIR_UPDATE_TIME) > time(NULL)) {
          return 0;
     }
     time(&(((av_req_data_t *) data)->last_update));
     ci_debug_printf(10,
                     "Downloaded %" PRINTF_OFF_T " bytes from %" PRINTF_OFF_T
                     " of data<br>",
                     ci_simple_file_size(((av_req_data_t *) data)->body),
                     ((av_req_data_t *) data)->expected_size);
     return snprintf(buf, len,
                     "Downloaded %" PRINTF_OFF_T " bytes from %" PRINTF_OFF_T
                     " of data<br>",
                     ci_simple_file_size(((av_req_data_t *) data)->body),
                     ((av_req_data_t *) data)->expected_size);
}


static char *e_message = "<H1>A VIRUS FOUND</H1>"
    "You try to upload/download a file that contain the virus<br>";
static char *t_message =
    "<p>This message generated by C-ICAP srvClamAV/antivirus module";

static const char *msg = "<p>Your file was saved as<b>:";
static const char *msg2 =
    "</b><p>Ask your administration for info how to get it";


void endof_data_vir_mode(av_req_data_t * data, request_t * req)
{
     ci_membuf_t *error_page;

     if (data->virus_name && data->body) {
          error_page = ci_membuf_new();
          ((av_req_data_t *) data)->error_page = error_page;
          ci_membuf_write(error_page, e_message, strlen(e_message), 0);
          ci_membuf_write(error_page, (char *) data->virus_name,
                          strlen(data->virus_name), 0);
          ci_membuf_write(error_page, t_message, strlen(t_message), 0); /*And here is the eof.... */
          ci_membuf_write(data->error_page, (char *) msg, strlen(msg), 0);
          ci_membuf_write(data->error_page, data->body->filename,
                          strlen(data->body->filename), 0);
          ci_membuf_write(data->error_page, (char *) msg2, strlen(msg2), 1);
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
