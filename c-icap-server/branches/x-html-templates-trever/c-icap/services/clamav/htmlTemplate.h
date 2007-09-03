/*
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

// Additionally, you may use this file under LGPL 2 or (at your option) later

#include <time.h>

#define MAX_TEMPLATES 10

typedef struct {
	char *TEMPLATE_NAME;
	char *SERVICE_NAME;
	char *LANGUAGE;
	ci_membuf_t *data;
	time_t last_used;
} htmlTemplate_t;

#ifndef HTMLTEMPLATE
extern ci_membuf_t *
templateBuildContent(const request_t *req, const char *SERVICE_NAME, const char *TEMPLATE_NAME, ci_membuf_t *(*USRtemplateConvert)(char token, const request_t * req));
extern void templateReload(void);
#endif
