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


#ifndef __NET_IO_H
#define __NET_IO_H

#ifndef _WIN32

#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>


#define ci_socket int
#define CI_SOCKET_ERROR -1


#else
#include <WinSock2.h>
#define ci_socket SOCKET
#define CI_SOCKET_ERROR INVALID_SOCKET
#endif


#define CI_MAXHOSTNAMELEN 64
#define CI_IPLEN      18


enum { wait_for_read, wait_for_write}; 


typedef struct ci_connection{
     ci_socket fd;
     struct sockaddr_in claddr;
     struct sockaddr_in srvaddr;
}  ci_connection_t ;



CI_DECLARE_FUNC(void) ci_addrtoip(struct sockaddr_in *addr, char *ip,int ip_strlen);
#define ci_conn_remote_ip(conn,ip) ci_addrtoip(&(conn->claddr),ip,CI_IPLEN)
#define ci_conn_local_ip(conn,ip)  ci_addrtoip(&(conn->srvaddr),ip,CI_IPLEN)


CI_DECLARE_FUNC(char) *ci_addrtohost(struct in_addr *addr, char *hname, int maxhostlen);


CI_DECLARE_FUNC(int) icap_socket_opts(ci_socket fd);
CI_DECLARE_FUNC(ci_socket) icap_init_server();

CI_DECLARE_FUNC(int) check_for_keepalive_data(ci_socket fd);
CI_DECLARE_FUNC(int) wait_for_data(ci_socket fd,int secs,int what_wait);
CI_DECLARE_FUNC(int) wait_for_incomming_data(ci_socket fd);
CI_DECLARE_FUNC(int) wait_for_outgoing_data(ci_socket fd);

CI_DECLARE_FUNC(int) icap_netio_init(ci_socket fd);
CI_DECLARE_FUNC(int) icap_read(ci_socket fd,void *buf,size_t count);
CI_DECLARE_FUNC(int) icap_write(ci_socket fd, const void *buf,size_t count);
CI_DECLARE_FUNC(int) icap_read_nonblock(ci_socket fd, void *buf,size_t count);
CI_DECLARE_FUNC(int) icap_write_nonblock(ci_socket fd, const void *buf,size_t count);

CI_DECLARE_FUNC(int) icap_linger_close(ci_socket fd);
CI_DECLARE_FUNC(int) icap_hard_close(ci_socket fd);

#endif
