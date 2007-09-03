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

#define HTMLTEMPLATE

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/param.h>
#include <assert.h>

#include "body.h"
#include "c-icap.h"
#include "service.h"
#include "header.h"
#include "request.h"
#include "debug.h"
#include "htmlTemplate.h"
#include "simple_api.h"


extern char *TEMPLATE_DIR;
extern char *TEMPLATE_DEF_LANG;
htmlTemplate_t templates[MAX_TEMPLATES];
int htmlTemplateInited = 0;

void initHtmlTemplate(void)
{
     int i;
     for (i = 0; i < MAX_TEMPLATES; i++) {
          templates[i].data = NULL;
          templates[i].TEMPLATE_NAME = NULL;
          templates[i].SERVICE_NAME = NULL;
          templates[i].LANGUAGE = NULL;
     }
     htmlTemplateInited = 1;
}

void templateFree(htmlTemplate_t * template)
{
     assert(template != NULL);
     if (template->data == NULL)
          return;
     if (template->TEMPLATE_NAME)
          free(template->TEMPLATE_NAME);
     if (template->SERVICE_NAME)
          free(template->SERVICE_NAME);
     if (template->LANGUAGE)
          free(template->LANGUAGE);
     template->TEMPLATE_NAME = template->SERVICE_NAME = template->LANGUAGE = NULL;
     ci_membuf_free(template->data);
     template->data = NULL;
}

void templateReload(void)
{
     int i = 0;
     for (i = 0; i < MAX_TEMPLATES; i++) {
          templateFree(&templates[i]);
     }
}

htmlTemplate_t *templateFind(const char *SERVICE_NAME, const char *TEMPLATE_NAME,
                      const char *LANGUAGE)
{
     int i = 0;

     for (i = 0; i < MAX_TEMPLATES; i++) {
          if (templates[i].data != NULL)
               if (strcmp(templates[i].SERVICE_NAME, SERVICE_NAME) == 0
                   && strcmp(templates[i].TEMPLATE_NAME, TEMPLATE_NAME) == 0
                   && strcmp(templates[i].LANGUAGE, LANGUAGE) == 0) {
                    ci_debug_printf(4,
                                    "templateFind: found: %s, %s, %s in cache at index %d\n",
                                    SERVICE_NAME, LANGUAGE, TEMPLATE_NAME, i);
                    templates[i].last_used = time(NULL);
                    return &templates[i];
               }
     }
     return NULL;
}

htmlTemplate_t *templateFindFree(void)
{
     time_t oldest = 0;
     htmlTemplate_t *useme = NULL;
     int i = 0;

     for (i = 0; i < MAX_TEMPLATES; i++)
          if (templates[i].data == NULL)
               return &templates[i];
     for (i = 0; i < MAX_TEMPLATES; i++) {
          if (templates[i].last_used < oldest) {
               oldest = templates[i].last_used;
               useme = &templates[i];
          }
     }
     if (useme != NULL)
          if (useme->data != NULL)
               templateFree(useme);
     return useme;
}

ci_membuf_t *templateTryLoadText(const request_t * req, const char *service_name,
                              const char *page_name, const char *dir,
                              const char *lang)
{
     int fd;
     char path[MAXPATHLEN];
     char buf[4096];
     struct stat file;
     ssize_t len;
     ci_membuf_t *textbuff = NULL;
     htmlTemplate_t *tempTemplate = NULL;

     if ((tempTemplate = templateFind(service_name, page_name, lang)) != NULL)
          return tempTemplate->data;

     ci_debug_printf(9, "templateTryLoadText: %s/%s/%s/%s\n", dir, service_name, lang,
              page_name);

     snprintf(path, sizeof(path), "%s/%s/%s/%s", dir, service_name, lang,
              page_name);
     fd = open(path, O_RDONLY);

     if (fd < 0) {
          ci_debug_printf(4, "templateTryLoadText: '%s': %s\n", path,
                          strerror(errno));
          return NULL;
     }

     fstat(fd, &file);
     textbuff = ci_membuf_new_sized(file.st_size + 1);

     assert(textbuff != NULL);

     while ((len = read(fd, buf, sizeof(buf))) > 0) {
          ci_membuf_write(textbuff, buf, len, 0);
     }
     ci_membuf_write(textbuff, "\0", 1, 1);     // terminate the string for safety

     if (len < 0) {
          ci_debug_printf(4, "templateTryLoadText: failed to fully read: '%s': %s\n",
                          path, strerror(errno));
     }

     close(fd);

     tempTemplate = templateFindFree();
     if (tempTemplate != NULL) {
          tempTemplate->SERVICE_NAME = strdup(service_name);
          tempTemplate->TEMPLATE_NAME = strdup(page_name);
          tempTemplate->LANGUAGE = strdup(lang);
          tempTemplate->data = textbuff;
          time(&tempTemplate->last_used);
     }
     else
          ci_debug_printf(4,
                          "templateTryLoadText: leaked memory as free template not found.\n");

     return textbuff;
}

ci_membuf_t *templateLoadText(const request_t * req, const char *service_name,
                           const char *page_name)
{
     char *languages = NULL;
     char *str = NULL, *preferred = NULL;
     ci_membuf_t *text = NULL;

     if ((languages = ci_reqmod_get_header(req, "Accept-Language")) != NULL) {
          ci_debug_printf(4, "templateLoadText: Languages are: '%s'\n", languages);
          str = strchr(languages, ';');
          if (str != NULL)
               str[0] = '\0';
          preferred = languages;
          while ((str = strchr(preferred, ',')) != NULL) {
               str[0] = '\0';
               if (preferred != '\0') {
                    ci_debug_printf(4,
                                    "templateLoadText: trying preferred language: '%s'\n",
                                    preferred);
                    text =
                        templateTryLoadText(req, service_name, page_name,
                                         TEMPLATE_DIR, preferred);
                    if (text != NULL) {
                         return text;
                    }
               }
               if (text != NULL)
                    break;
               preferred = str + 1;
          }
          return text;
     }

     return text =
         templateTryLoadText(req, service_name, page_name, TEMPLATE_DIR,
                          TEMPLATE_DEF_LANG);
}

ci_membuf_t *templateBuildContent(const request_t * req, const char *SERVICE_NAME,
                               const char *TEMPLATE_NAME,
                               ci_membuf_t * (*USRtemplateConvert) (char token,
                                                                 const request_t
                                                                 * req))
{
     ci_membuf_t *content = ci_membuf_new();
     const char *m = NULL;
     const char *p = NULL;
     ci_membuf_t *t = NULL;

     ci_debug_printf(9, "templateBuildContent: entered\n");

     if (htmlTemplateInited == 0)
          initHtmlTemplate();

     ci_debug_printf(9, "templateBuildContent: Templates Engine has been initialized\n");

     m = templateLoadText(req, SERVICE_NAME, TEMPLATE_NAME)->buf;
     assert(m);

     while ((p = strchr(m, '%'))) {
          ci_membuf_write(content, m, p - m, 0);        /* copy */
          t = USRtemplateConvert(*++p, req);       /* convert */
          ci_membuf_write(content, t->buf, ci_simple_file_size(t), 0);  /* copy */
          m = p + 1;            /* advance */
          ci_membuf_free(t);
     }

     if (*m)
          ci_membuf_write(content, m, strlen(m), 0);    /* copy tail */
     ci_membuf_write(content, "\0", 1, 1);      // terminate the string for safety
     return content;
}


/* ci_membuf_t *
templateConvert(char token, request_t * req)
{
// see srv_clamav_vir.c for an example
} */
