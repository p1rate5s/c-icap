/*
 *  Copyright (C) 2010 Christos Tsantilas
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

#include "body.h"
#include "request.h"
#include "debug.h"
#include "url_check_body.h"

int body_data_init(struct body_data *bd, enum body_type type,  int size)
{
    if (!bd)
        return 0;
    if (type == CACHED){
        bd->store.cached = ci_cached_file_new(size);
    }
    else if(type == RING ){
        bd->store.ring = ci_ring_buf_new(16384);
    }
    else {
        ci_debug_printf(1, "BUG in url_check, body_data_init: invalid body type:%d", type);
        return 0;
    }
    bd->type = type;
    bd ->eof = 0;
    return 1;
}

void body_data_destroy(struct body_data *body)
{
    if (body->type == CACHED){
        ci_cached_file_destroy(body->store.cached);
        body->store.cached = NULL;
    }
    else if(body->type == RING ){
        ci_ring_buf_destroy(body->store.ring);
        body->store.ring = NULL;
    }
    else {
        ci_debug_printf(1, "BUG in url_check, body_data_destroy: invalid body type:%d\n", body->type);
    }
    body->type = NO_BODY_TYPE;
    body->eof = 0;
}

int body_data_write(struct body_data *body, char *buf, int len, int iseof)
{
    if (body->type == CACHED){
        if (buf && len)
            return ci_cached_file_write(body->store.cached, buf, len, iseof);
        else if (iseof) 
            return  ci_cached_file_write(body->store.cached, NULL, 0, iseof);
        /*else ERROR*/
    }
    else if(body->type == RING ){
        if (iseof)
            body->eof = 1;
        if (len && buf)
            return ci_ring_buf_write(body->store.ring, buf, len);
        else if (iseof)
            return CI_EOF;
        /*else ERROR*/
    }
    else {
        ci_debug_printf(1, "BUG in url_check, body_data_write: invalid body type:%d\n", body->type);
        return CI_ERROR;
    }
    
    return CI_ERROR;
}

int body_data_read(struct body_data *body, char *buf, int len)
{
    if (body->type == CACHED){
        len = ci_cached_file_read(body->store.cached, buf, len);
        return len;
    }
    else if(body->type == RING ){
        len = ci_ring_buf_read(body->store.ring, buf, len);
        if(len == 0 && body->eof == 1)
            return CI_EOF;
        return len;
    }
    else {
        ci_debug_printf(1, "BUG in url_check, body_data_read: invalid body type:%d\n", body->type);
        return CI_ERROR;
    }
}
