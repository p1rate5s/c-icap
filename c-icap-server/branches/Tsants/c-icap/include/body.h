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


#ifndef __BODY_H
#define __BODY_H

#include "c-icap.h"

typedef struct mem_body{
     int len;
     int endpos;
     int readpos;
     int bufsize;
     int hasalldata;
     char *buf;
} mem_body_t;

CI_DECLARE_FUNC(struct mem_body) * newmembody();
CI_DECLARE_FUNC(void) freemembody(struct mem_body *);
CI_DECLARE_FUNC(int) writememdata(struct mem_body *body, char *buf,int len, int iseof);
CI_DECLARE_FUNC(int) readmemdata(struct mem_body *body,char *buf,int len);
CI_DECLARE_FUNC(void) markendofdata(struct mem_body *body);


/*****************************************************************/
/* Cached file functions and structure                           */

#define FILENAME_LEN 512



typedef struct ci_cached_file{
     int endpos;
     int readpos;
     int bufsize;
/*     int growtosize;*/
     int eof_received;
     int unlocked;
     char *buf;
     int fd;
     char filename[FILENAME_LEN];
} ci_cached_file_t;

CI_DECLARE_FUNC(ci_cached_file_t) * ci_new_cached_file(int size);
CI_DECLARE_FUNC(void) ci_release_cached_file(ci_cached_file_t *);
CI_DECLARE_FUNC(int) ci_write_cached_file(ci_cached_file_t *body,
					  char *buf,int len, int iseof);
CI_DECLARE_FUNC(int) ci_read_cached_file(ci_cached_file_t *body,char *buf,int len);
CI_DECLARE_FUNC(int)  ci_memtofile_cached_file(ci_cached_file_t *body);
CI_DECLARE_FUNC(void) ci_reset_cached_file(ci_cached_file_t *body,int new_size);

#define ci_unlockdata_cached_file(body, len) (body->unlocked=len)
#define ci_unlockalldata_cached_file(body) (body->unlocked=-1)
#define ci_size_cached_file(body, len)       (body->endpos)
#define ci_ismem_cached_file(body)           (body->fd<0)
#define ci_isfile_cached_file(body)          (body->fd>0)
#define ci_readeddata_cached_file(body)      (body->readpos)

#endif
