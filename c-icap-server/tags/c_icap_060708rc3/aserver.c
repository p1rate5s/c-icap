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
#include <stdio.h>
#include "net_io.h"
#include "debug.h"
#include "module.h"
#include "log.h"
#include "cfg_param.h"

/*
extern char *PIDFILE;
extern char *RUN_USER;
extern char *RUN_GROUP;
extern int PORT;
*/

extern int DAEMON_MODE;
extern int MAX_SECS_TO_LINGER;
char MY_HOSTNAME[CI_MAXHOSTNAMELEN + 1];

void init_conf_tables();
int config(int, char **);
int init_server(int port, int *family);
int start_server();
int store_pid(char *pidfile);
int is_icap_running(char *pidfile);
int set_running_permissions(char *user, char *group);


void compute_my_hostname()
{
     char hostname[64];
     struct hostent *hent;
     int ret;
     ret = gethostname(hostname, 63);
     if (ret == 0) {
          hostname[63] = '\0';
          if ((hent = gethostbyname(hostname)) != NULL) {
               strncpy(MY_HOSTNAME, hent->h_name, CI_MAXHOSTNAMELEN);
               MY_HOSTNAME[CI_MAXHOSTNAMELEN] = '\0';
          }
          else
               strcpy(MY_HOSTNAME, hostname);
     }
     else
          strcpy(MY_HOSTNAME, "localhost");
}

#if ! defined(_WIN32)
void run_as_daemon()
{
     int pid;
     if ((pid = fork()) < 0) {
          ci_debug_printf(1, "Can not fork. exiting...");
          exit(-1);
     }
     if (pid)
          exit(0);
}
#endif

int main(int argc, char **argv)
{
#if ! defined(_WIN32)
     __log_error = (void (*)(void *, const char *,...)) log_server;     /*set c-icap library log  function */
#else
     __vlog_error = vlog_server;        /*set c-icap library  log function */
#endif

     if (!(CONF.MAGIC_DB = ci_magics_db_build(CONF.magics_file))) {
          ci_debug_printf(1, "Can not load magic file %s!!!\n",
                          CONF.magics_file);
     }
     init_conf_tables();
     init_modules();
     config(argc, argv);
     compute_my_hostname();
     ci_debug_printf(1, "My hostname is:%s\n", MY_HOSTNAME);

#if ! defined(_WIN32)
     if (is_icap_running(CONF.PIDFILE)) {
          ci_debug_printf(1, "c-icap server already running!\n");
          exit(-1);
     }
     if (DAEMON_MODE)
          run_as_daemon();
     store_pid(CONF.PIDFILE);
     if (!set_running_permissions(CONF.RUN_USER, CONF.RUN_GROUP))
          exit(-1);
#endif

     if (!log_open()) {
          ci_debug_printf(1, "Can not init loggers. Exiting.....\n");
          exit(-1);
     }
     if (!init_server(CONF.PORT, &(CONF.PROTOCOL_FAMILY)))
          return -1;
     post_init_modules();
     post_init_services();
     start_server();
     return 0;
}
