#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "c-icap.h"
#include "cfg_param.h"
#include "mem.h"
#include "array.h"
#include "debug.h"

void log_errors(void *unused, const char *format, ...)
{                                                     
     va_list ap;                                      
     va_start(ap, format);                            
     vfprintf(stderr, format, ap);                    
     va_end(ap);                                      
}


static struct ci_options_entry options[] = {
    {"-d", "debug_level", &CI_DEBUG_LEVEL, ci_cfg_set_int,
     "The debug level"},
    {NULL,NULL,NULL,NULL,NULL}
};

void print_str(void *data, const char *name, const void *value)
{
    const char *v = (const char *)value;
    ci_debug_printf(2, "\t%s: %s\n", name, v);
}

int mem_init();
int main(int argc,char *argv[])
{
    ci_str_array_t *arr_str;
    ci_ptr_array_t *arr_ptr;
    int i;
    char name[128];
    char value[128];
    void *data;
    ci_cfg_lib_init();
    mem_init();
    __log_error = (void (*)(void *, const char *,...)) log_errors;     /*set c-icap library log  function */

    if (!ci_args_apply(argc, argv, options)) {
        ci_args_usage(argv[0], options);
        exit(-1);
    }
    ci_debug_printf(1, "Creating array of strings ... ");
    arr_str = ci_str_array_new(32768);
    for (i = 1; i< 128; i++) {
        sprintf(name, "name%d", i);
        sprintf(value, "value%d", i);
        ci_str_array_add(arr_str, name, value);
    }
    ci_debug_printf(1, "done  ...  test it ... ");

    ci_debug_printf(2, "\n\nArray of strings:\n");
    ci_str_array_iterate(arr_str, NULL, print_str);

    ci_str_array_destroy(arr_str);
    ci_debug_printf(1, "done \n");

    ci_debug_printf(1, "Creating array of pointers ... ");
    arr_ptr = ci_ptr_array_new(32768);
    for (i = 1; i< 128; i++) {
        sprintf(name, "name%d", i);
        sprintf(value, "dynvalue%d", i);
        data = strdup(value);
        ci_ptr_array_add(arr_ptr, name, data);
    }
    ci_debug_printf(1, "done  ...  test it ... ");
    ci_debug_printf(2, "Array of pointers:\n");
    ci_ptr_array_iterate(arr_ptr, NULL, print_str);
    ci_debug_printf(1, "done\n");
    char buf[1024];
    ci_debug_printf(1, "Test pop on array of pointers...");
    while((data = ci_ptr_array_pop(arr_ptr, buf, sizeof(buf))) != NULL) {
        ci_debug_printf(3, "Deleting : %s: %s\n", buf, (char *)data);
        free(data);
    }
    ci_debug_printf(1, "done\n");
    ci_ptr_array_destroy(arr_ptr);

    
    return 0;
}
