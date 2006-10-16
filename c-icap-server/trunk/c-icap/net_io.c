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
#include <errno.h>
#include "net_io.h"
#include "debug.h"
#include "net_io.h"


#ifdef HAVE_IPV6
void ci_fill_sockaddr(ci_sockaddr_t * addr)
{
     addr->ci_sin_family = addr->sockaddr.ss_family;
     if (addr->ci_sin_family == AF_INET6) {
          addr->ci_sin_port =
              ((struct sockaddr_in6 *) &(addr->sockaddr))->sin6_port;
          addr->ci_sin_addr =
              &(((struct sockaddr_in6 *) &(addr->sockaddr))->sin6_addr);
          addr->ci_inaddr_len = sizeof(struct in6_addr);
     }
     else {
          addr->ci_sin_port =
              ((struct sockaddr_in *) &(addr->sockaddr))->sin_port;
          addr->ci_sin_addr =
              &(((struct sockaddr_in *) &(addr->sockaddr))->sin_addr);
          addr->ci_inaddr_len = sizeof(struct in_addr);
     }
}

#else
void ci_fill_sockaddr(ci_sockaddr_t * addr)
{
     addr->ci_sin_family = addr->sockaddr.sin_family;
     addr->ci_sin_port = addr->sockaddr.sin_port;
     addr->ci_sin_addr = &(addr->sockaddr.sin_addr);
     addr->ci_inaddr_len = sizeof(struct in_addr);
}

#endif

#ifdef HAVE_IPV6

void ci_sockaddr_set_port(ci_sockaddr_t * addr, int port)
{
     if (addr->sockaddr.ss_family == AF_INET)
          ((struct sockaddr_in *) &(addr->sockaddr))->sin_port = htons(port);
     else
          ((struct sockaddr_in6 *) &(addr->sockaddr))->sin6_port = htons(port);
}

#else

void ci_sockaddr_set_port(ci_sockaddr_t * addr, int port)
{
     addr->sockaddr.sin_port = htons(port);
     /*(addr).ci_sin_port=htons(port); */ ;
}
#endif



const char *ci_sockaddr_t_to_ip(ci_sockaddr_t * addr, char *ip, int maxlen)
{
     return ci_inet_ntoa(addr->ci_sin_family, addr->ci_sin_addr, ip, maxlen);
}


/*
  Needed check in configure.in for inet_pton and inet_ntop ?
  For Linux and Solaris exists. 
  But I did not found these functions in win32 for example .
*/

int ci_inet_aton(int af, const char *cp, void *addr)
{
#ifdef HAVE_IPV6
     return inet_pton(af, cp, addr);
#else
#ifdef HAVE_INET_ATON
     return inet_aton(cp, (struct in_addr *) addr);
#else
     ((struct in_addr *) addr)->s_addr = inet_addr(cp);
     if (((struct in_addr *) addr)->s_addr == 0xffffffff
         && strcmp(cp, "255.255.255.255") != 0)
          return 0;             /*0xffffffff =255.255.255.255 which is a valid address */
     return 1;
#endif
#endif                          /*HAVE_IPV6 */
}



const char *ci_inet_ntoa(int af, const void *src, char *dst, int cnt)
{
#ifdef HAVE_IPV6
     return inet_ntop(af, src, dst, cnt);
#else
     unsigned char *addr_bytes;
     addr_bytes = (unsigned char *) src;
     snprintf(dst, cnt, "%d.%d.%d.%d", addr_bytes[0], addr_bytes[1],
              addr_bytes[2], addr_bytes[3]);
     dst[cnt - 1] = '\0';
     return (const char *) dst;
#endif
}
