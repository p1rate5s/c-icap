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


#ifndef __CFG_PARAM_H
#define __CFG_PARAM_H
#include "filetype.h"
#include "body.h"

/**
 \defgroup CONFIG c-icap server configuration API
 \ingroup API
 *
 */

/**
 * This struct holds the basic configurations of c-icap server. It passed as argument to
 * services and modules inititalization functions 
 \ingroup CONFIG
 *
 * Do not use directly this struct but better use the documended macros
 */
struct ci_server_conf{
     int  PORT;
     int  PROTOCOL_FAMILY;
     char *TMPDIR;
     char *PIDFILE;
     char *COMMANDS_SOCKET;
     char *RUN_USER;
     char *RUN_GROUP;
     char *cfg_file;
     char *magics_file;
     struct ci_magics_db *MAGIC_DB;   
     char *SERVICES_DIR;
     char *MODULES_DIR;
};

/**
 * This struct holds a configuration parameter of c-icap server
 \ingroup CONFIG
 * An array of ci_conf_entry structs can be used to define the configuration directives
 * of a service or module which can be set in c-icap configuration file.
 \code
 int AParam;
 struct ci_conf_entry conf_table[]= {
 {"Aparameter", &AParam, ci_cfg_set_int, "This is a simple configuration parameter"},
  {NULL,NULL,NULL,NULL}
 }
 \endcode
 In the above example the  ci_cfg_set_int function is predefined.
 If the table "conf_table" attached to the service "AService" then the AParam integer variable can be set from the
 c-icap configuration file using the directive "AService.Aparameter"
 */
struct ci_conf_entry{
    /**
     * The configuration directive
     */
     char *name;
    /**
     * A pointer to the configuration data
     */
     void *data;
    /**
     * Pointer to the function which will be used to set configuration data
     \param name is the configuration directive.It passed as argument by the c-icap server
     \param argv is a NULL termined string array which holds the list of arguments of configuration parameter
     \param setdata is o pointer to set data which passed as argument by c-icap server
     \return Non zero on success, zero otherwise
     */
     int (*action)(char *name, char **argv,void *setdata);
    /**
     * A description message
     */
     char *msg;
};

/* Command line options implementation structure */
struct ci_options_entry{
     char *name;
     char *parameter;
     void *data;
     int (*action)(char *name, char **argv,void *setdata);
     char *msg;
};

/*Struct for storing default parameter values*/
struct cfg_default_value{
     void *param;
     void *value;
     int size;
     struct cfg_default_value *next;
};

#define MAIN_TABLE 1
#define ALIAS_TABLE 2

#ifndef CI_BUILD_LIB
extern struct ci_server_conf CONF;

struct cfg_default_value * cfg_default_value_store(void *param, void *value,int size);
struct cfg_default_value * cfg_default_value_replace(void *param, void *value);
void *                     cfg_default_value_restore(void *value);
struct cfg_default_value * cfg_default_value_search(void *param);

int register_conf_table(char *name,struct ci_conf_entry *table,int type);
int config(int argc, char **argv);

int intl_cfg_set_str(char *directive,char **argv,void *setdata);
int intl_cfg_set_int(char *directive,char **argv,void *setdata);
int intl_cfg_onoff(char *directive,char **argv,void *setdata);
int intl_cfg_disable(char *directive,char **argv,void *setdata);
int intl_cfg_enable(char *directive,char **argv,void *setdata);
int intl_cfg_size_off(char *directive,char **argv,void *setdata);
int intl_cfg_size_long(char *directive,char **argv,void *setdata);
#endif


CI_DECLARE_FUNC(void)   ci_cfg_lib_init();
CI_DECLARE_FUNC(void)   ci_cfg_lib_reset();
CI_DECLARE_FUNC(void *) ci_cfg_alloc_mem(int size);

/**
 * Sets a string configuration parameter. The setdata are a pointer to a string pointer
 */
CI_DECLARE_FUNC(int) ci_cfg_set_str(char *directive,char **argv,void *setdata);

/**
 * Sets an int configuration parameter. The setdata is a pointer to an integer
 \ingroup CONFIG
 */
CI_DECLARE_FUNC(int) ci_cfg_set_int(char *directive,char **argv,void *setdata);

/**
 * Sets an on/off configuration parameter. The setdata is a pointer to an integer, which
 * when the argument is "on" it is set to 1 and when the argument is "off" it is set to 0.
 \ingroup CONFIG
 */
CI_DECLARE_FUNC(int) ci_cfg_onoff(char *directive,char **argv,void *setdata);

/**
 * Can used with configuration parameters which does not takes arguments but when defined just disable a feature.
 * The setdata is a pointer to an int which is set to zero.
 \ingroup CONFIG
 */
CI_DECLARE_FUNC(int) ci_cfg_disable(char *directive,char **argv,void *setdata);

/**
 * Can used with configuration parameters which does not takes arguments but when defined just enable a feature.
 * The setdata is a pointer to an int which is set to non zero. 
 \ingroup CONFIG
 */
CI_DECLARE_FUNC(int) ci_cfg_enable(char *directive,char **argv,void *setdata);

/**
 * Sets a configuration parameter of type ci_off_t (typedef of off_t type).
 \ingroup CONFIG
 */
CI_DECLARE_FUNC(int) ci_cfg_size_off(char *directive,char **argv,void *setdata);
CI_DECLARE_FUNC(int) ci_cfg_size_long(char *directive,char **argv,void *setdata);

CI_DECLARE_FUNC(void) ci_args_usage(char *progname,struct ci_options_entry *options);
CI_DECLARE_FUNC(int)  ci_args_apply(int argc, char **argv,struct ci_options_entry *options);


#ifdef __CI_COMPAT
#define  icap_server_conf   ci_server_conf
#define  conf_entry         ci_conf_entry
#define  options_entry      ci_options_entry
#endif


#endif
