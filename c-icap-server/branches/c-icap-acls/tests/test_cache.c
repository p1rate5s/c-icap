#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "c-icap.h"
#include "mem.h"
#include "lookup_table.h"
#include "cache.h"
#include "debug.h"

void log_errors(void *unused, const char *format, ...)
{                                                     
     va_list ap;                                      
     va_start(ap, format);                            
     vfprintf(stderr, format, ap);                    
     va_end(ap);                                      
}

void *copy_to_str(void *val, int *val_size, ci_mem_allocator_t *allocator)
{
    return (void *)ci_str_ops.dup((char *)val, allocator);
}

void *copy_from_str(void *val, int val_size, ci_mem_allocator_t *allocator)
{
    return (void *)ci_str_ops.dup((char *)val, allocator);
}


int main(int argc,char *argv[]) {
    struct ci_cache *cache;
    ci_mem_allocator_t *allocator;
    char *s;
    printf("Hi re\n");

    CI_DEBUG_LEVEL = 10;
    ci_cfg_lib_init();
    
    __log_error = (void (*)(void *, const char *,...)) log_errors;     /*set c-icap library log  function */                                                    
    
    allocator = ci_create_os_allocator();
    cache = ci_cache_build(65536, /*cache_size*/
                           512, /*max_key_size*/
			   1024, /*max_object_size*/ 
			   0, /*ttl*/
			   &ci_str_ops, /*key_ops*/
			   &copy_to_str, /*copy_to*/
			   &copy_from_str /*copy_from*/
	);

    ci_cache_update(cache, "test1", "A test1 val");

    ci_cache_update(cache, "test2", "A test2 val");

    ci_cache_update(cache, "test3", "A test 3 val");

    ci_cache_update(cache, "test4", "A test 4 val");


    if(ci_cache_search(cache,"test2", (void **)&s, allocator)) {
	printf("Found : %s\n", s);
	allocator->free(allocator,s);
    }

    if(ci_cache_search(cache,"test21", (void **)&s, allocator)) {
	printf("Found : %s\n", s);
	allocator->free(allocator, s);
    }

    if(ci_cache_search(cache,"test1", (void **)&s, allocator)) {
	printf("Found : %s\n", s);
	allocator->free(allocator,s);
    }

    if(ci_cache_search(cache,"test4", (void **)&s, allocator)) {
	printf("Found : %s\n", s);
	allocator->free(allocator,s);
    }

    ci_cache_destroy(cache);
    return 0;
}
